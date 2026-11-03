// lab/ingest/main.cpp
//
// Self-test for the bounded queue and the ingester. No test framework: the lab
// should build and check itself with a compiler and nothing else.
//
//   make -C lab/ingest && ./lab/ingest/collector_selftest
//
// The tests that matter here are the ones the original design could not pass:
// a full queue must not lose records silently, a blocked producer must wake when a
// consumer drains, and close() must unblock everyone. A watchdog kills the process
// if any of those turn into a hang, so a deadlock fails the build instead of
// stalling it.

#include "collector.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const char* what) {
    if (condition) {
        std::printf("  ok   %s\n", what);
    } else {
        std::printf("  FAIL %s\n", what);
        ++failures;
    }
}

void watchdog(std::atomic<bool>& done, int seconds) {
    std::thread([&done, seconds] {
        for (int i = 0; i < seconds * 20; ++i) {
            if (done.load()) {
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        std::fprintf(stderr, "watchdog: hang detected, aborting\n");
        std::_Exit(3);
    }).detach();
}

void test_queue_basics() {
    std::printf("queue basics\n");
    lab::BoundedQueue<int> queue(2);
    check(queue.try_push(1), "try_push accepts while there is room");
    check(queue.try_push(2), "try_push fills the queue");
    check(!queue.try_push(3), "try_push refuses when full instead of growing");
    check(queue.size() == 2, "size reflects the bound");

    auto first = queue.pop();
    check(first.has_value() && *first == 1, "pop returns FIFO order");
    check(queue.try_push(3), "space reappears after a pop");

    queue.close();
    auto second = queue.pop();
    auto third = queue.pop();
    check(second.has_value() && third.has_value(), "close() still drains everything queued");
    auto drained = queue.pop();
    check(!drained.has_value(), "closed and drained pop returns nullopt");
    check(!queue.try_push(4), "closed queue rejects new items");
}

void test_blocking_push_wakes() {
    std::printf("blocking producer wakes on drain\n");
    lab::BoundedQueue<int> queue(1);
    queue.try_push(1);

    std::atomic<bool> pushed{false};
    std::thread producer([&] {
        queue.push(2);  // must block until the consumer takes the first item
        pushed.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    check(!pushed.load(), "push blocks while the queue is full");

    auto taken = queue.pop();
    producer.join();
    check(taken.has_value() && pushed.load(), "push resumes after a pop");
}

void test_ingester_under_overload() {
    std::printf("ingester under overload\n");
    lab::Metrics metrics;
    lab::IngestConfig config;
    config.queue_capacity = 64;   // deliberately small so the queue saturates
    config.workers = 2;
    config.backpressure_threshold = 0.80;

    const std::size_t total = 20000;

    std::mutex sink_mutex;
    std::vector<lab::RawEvent> sink;
    sink.reserve(total);

    lab::Ingester ingester(config, metrics);
    lab::CountingSource source(total);
    ingester.start(source, [&sink, &sink_mutex](const lab::RawEvent& event) {
        std::lock_guard<std::mutex> lock(sink_mutex);
        sink.push_back(event);
    });

    // Give the pipeline a moment, then shut it down cleanly.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    ingester.stop();

    const std::uint64_t pushed = metrics.pushed.load();
    const std::uint64_t dropped = metrics.dropped.load();
    const std::uint64_t consumed = metrics.consumed.load();

    std::printf("  pushed=%llu dropped=%llu consumed=%llu high_water=%llu signals=%llu\n",
                static_cast<unsigned long long>(pushed),
                static_cast<unsigned long long>(dropped),
                static_cast<unsigned long long>(consumed),
                static_cast<unsigned long long>(metrics.depth_high_water()),
                static_cast<unsigned long long>(metrics.backpressure_signals.load()));

    check(pushed + dropped == total, "every record is either queued or counted as dropped");
    check(consumed == pushed, "everything queued is consumed before exit");
    check(consumed == sink.size(), "handler saw exactly the consumed records");
    check(metrics.depth_high_water() <= config.queue_capacity, "queue never exceeded its bound");
    check(metrics.depth_high_water() > 0, "high-water mark was actually published");
    check(metrics.backpressure_signals.load() > 0, "backpressure signaled while saturated");
}

}  // namespace

int main() {
    std::atomic<bool> done{false};
    watchdog(done, 20);

    test_queue_basics();
    test_blocking_push_wakes();
    test_ingester_under_overload();

    done.store(true);
    if (failures == 0) {
        std::printf("all checks passed\n");
        return 0;
    }
    std::printf("%d check(s) failed\n", failures);
    return 1;
}
