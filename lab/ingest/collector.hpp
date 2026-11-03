// lab/ingest/collector.hpp
//
// Bounded, backpressured ingestion queue for the experimental lab.
//
// What changed relative to the design notes this file came from:
//
// 1. The original used `std::queue` behind a single mutex with two condition
//    variables and no predicate on either wait. That is the classic deadlock:
//    a notify can be lost between the producer's unlock and the consumer's wait,
//    and both sides then sleep forever. The waits here take predicates, and the
//    mutex is unlocked only after the state change is visible.
// 2. `push` blocks when full (real backpressure). `try_push` never blocks and
//    counts the drop, so a fast feed cannot turn into unbounded memory growth.
//    The document's suggested fix was a boost lock-free queue; that helps lock
//    contention and does nothing for the actual failure mode, which is memory
//    exhaustion under sustained overload. Measure before reaching for lock-free.
// 3. Dependencies are gone. The original header pulled in libcurl and
//    nlohmann/json, so nothing compiled without two system packages and a
//    network client. Sources here are a tiny interface; the only implementations
//    are a file reader and a null source. No network code ships in this repo.
// 4. Timestamps are int64 microseconds since the Unix epoch, not strings. String
//    timestamps cannot be ordered correctly across offsets and cannot be a
//    TimescaleDB partition key without a cast.

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace lab {

struct RawEvent {
    std::string source_id;
    std::string client_key;       // salted, truncated hash; never a raw address
    std::string channel;
    std::string ua_family;
    std::string fingerprint_hash;
    std::string payload;          // original record, for the cleaning layer
    std::int64_t observed_at_us = 0;
};

struct Metrics {
    std::atomic<std::uint64_t> pushed{0};
    std::atomic<std::uint64_t> dropped{0};
    std::atomic<std::uint64_t> consumed{0};
    std::atomic<std::uint64_t> deduplicated{0};
    std::atomic<std::uint64_t> high_water{0};
    std::atomic<std::uint64_t> backpressure_signals{0};

    std::uint64_t depth_high_water() const { return high_water.load(std::memory_order_relaxed); }
};

// Bounded MPSC queue. Multiple producers, one consumer.
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

    // Blocks while full. Returns false only if the queue is closed.
    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return closed_ || queue_.size() < capacity_; });
        if (closed_) {
            return false;
        }
        queue_.push_back(std::move(item));
        if (queue_.size() > high_water_) {
            high_water_ = queue_.size();
        }
        lock.unlock();
        not_empty_.notify_one();
        return true;
    }

    // Never blocks. Returns false when the queue is full or closed.
    bool try_push(T item) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (closed_ || queue_.size() >= capacity_) {
                return false;
            }
            queue_.push_back(std::move(item));
            if (queue_.size() > high_water_) {
                high_water_ = queue_.size();
            }
        }
        not_empty_.notify_one();
        return true;
    }

    // Blocks until an item is available or the queue is closed and drained.
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] { return closed_ || !queue_.empty(); });
        if (queue_.empty()) {
            return std::nullopt;
        }
        T item = std::move(queue_.front());
        queue_.pop_front();
        lock.unlock();
        not_full_.notify_one();
        return item;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    double fill_ratio() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<double>(queue_.size()) / static_cast<double>(capacity_);
    }

    std::size_t capacity() const { return capacity_; }

    std::size_t high_water() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return high_water_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    std::deque<T> queue_;
    std::size_t capacity_;
    std::size_t high_water_ = 0;
    bool closed_ = false;
};

// A source of records. Deliberately tiny: this repo does not ship a network client.
class FeedSource {
public:
    virtual ~FeedSource() = default;
    // Returns false when the source is exhausted.
    virtual bool next(RawEvent& out) = 0;
};

class NullSource final : public FeedSource {
public:
    bool next(RawEvent&) override { return false; }
};

class CountingSource final : public FeedSource {
public:
    explicit CountingSource(std::size_t count) : remaining_(count) {}
    bool next(RawEvent& out) override {
        if (remaining_ == 0) {
            return false;
        }
        --remaining_;
        out.source_id = "lab:synthetic";
        out.client_key = "0123456789abcdef";
        out.channel = "feed_item";
        out.ua_family = "curl";
        out.fingerprint_hash = "ja4:000000000001";
        out.observed_at_us = 1767225600000000LL + static_cast<std::int64_t>(remaining_) * 30000000LL;
        out.payload = "{\"note\":\"synthetic\"}";
        return true;
    }

private:
    std::size_t remaining_;
};

struct IngestConfig {
    std::size_t queue_capacity = 1024;
    std::size_t workers = 2;
    double backpressure_threshold = 0.80;  // fill ratio that triggers a signal
};

// Producer threads push, worker threads consume, one consumer callback handles each
// record. `handle` must be thread-safe; the demo writes to a mutex-guarded sink.
class Ingester {
public:
    using Handler = std::function<void(const RawEvent&)>;

    Ingester(IngestConfig config, Metrics& metrics) : config_(config), metrics_(metrics), queue_(config.queue_capacity) {}

    void start(FeedSource& source, Handler handler) {
        for (std::size_t i = 0; i < config_.workers; ++i) {
            workers_.emplace_back([this, handler] { worker_loop(handler); });
        }
        source_ = std::thread([this, &source] { producer_loop(source); });
    }

    void stop() {
        if (source_.joinable()) {
            source_.join();
        }
        // Publications from the queue must reach the shared metrics, otherwise a
        // "high water" of zero reads as health when it may mean the queue saturated.
        metrics_.high_water.store(queue_.high_water(), std::memory_order_relaxed);
        queue_.close();  // also wakes blocked workers
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers_.clear();
    }

    const Metrics& metrics() const { return metrics_; }

private:
    void producer_loop(FeedSource& source) {
        RawEvent event;
        while (!stopping_.load(std::memory_order_relaxed) && source.next(event)) {
            // Backpressure: signal upstream rather than silently buffering forever.
            if (queue_.fill_ratio() >= config_.backpressure_threshold) {
                metrics_.backpressure_signals.fetch_add(1, std::memory_order_relaxed);
            }
            metrics_.high_water.store(queue_.high_water(), std::memory_order_relaxed);
            if (!queue_.try_push(event)) {
                // Sustained overload with an unresponsive upstream: count it instead
                // of blocking the producer thread forever.
                metrics_.dropped.fetch_add(1, std::memory_order_relaxed);
                std::this_thread::sleep_for(std::chrono::microseconds(200));
                continue;
            }
            metrics_.pushed.fetch_add(1, std::memory_order_relaxed);
        }
        queue_.close();
    }

    void worker_loop(const Handler& handler) {
        while (auto item = queue_.pop()) {
            handler(*item);
            metrics_.consumed.fetch_add(1, std::memory_order_relaxed);
        }
    }

    IngestConfig config_;
    Metrics& metrics_;
    BoundedQueue<RawEvent> queue_;
    std::thread source_;
    std::vector<std::thread> workers_;
    std::atomic<bool> stopping_{false};
};

}  // namespace lab
