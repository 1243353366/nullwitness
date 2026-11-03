"""Synthetic event stream for the lab.

The lab never ingests a real feed. These generators produce two populations so the
model has something honest to separate:

- `scripted`: clockwork cadence, near-zero jitter, one user agent, one protocol.
- `human`: irregular cadence, diurnal clustering, mixed user agents, mixed protocols.

Neither population is a claim about real adversaries. They are shapes, useful for
testing the pipeline's plumbing and for demonstrating that temporal validation and
drift detection behave, not for estimating real-world performance.
"""

from __future__ import annotations

import math
import random
import uuid
from typing import List

from lab.features.contract import EventRecord, derive_client_key

SALT = b"lab-demo-salt-do-not-reuse"
EPOCH = "2026-11"
SOURCES = ("feed:mitre-attack", "feed:misp", "feed:otx", "site:portfolio", "canary:pdf")

SCRIPTED_UAS = ("curl", "python-requests", "go-http-client")
HUMAN_UAS = ("chrome", "firefox", "safari", "chrome", "chrome")


def _pick(rng: random.Random, seq):
    return seq[rng.randrange(len(seq))]


def make_scripted(rng: random.Random, client: str, start: float, count: int, sloppy: bool = False) -> List[EventRecord]:
    """Clockwork automation: fixed period, minimal jitter, one fingerprint.

    `sloppy=True` models automation written by someone who randomized their cadence
    by hand: heavier jitter, rotating agents. It exists so the demo is not a
    separable toy problem, and so the metrics are honest about a hard case.
    """
    period = rng.choice((30.0, 60.0, 120.0, 300.0))
    fingerprint = f"ja4:{rng.getrandbits(48):012x}"
    ua = _pick(rng, SCRIPTED_UAS)
    jitter_sd = 0.15 if not sloppy else 24.0
    key = derive_client_key(SALT, EPOCH, client)
    events = []
    for i in range(count):
        period_jitter = rng.gauss(0.0, jitter_sd)
        latency = abs(rng.gauss(70.0, 35.0 if not sloppy else 55.0))
        events.append(
            EventRecord(
                event_id=str(uuid.uuid4()),
                observed_at=start + i * period + period_jitter,
                source_id=_pick(rng, SOURCES[:3]),
                client_key=key,
                channel=rng.choice(("feed_item", "site_visit")),
                protocol="http/1.1" if ua != "curl" else "h2",
                ua_family=ua if not sloppy else _pick(rng, SCRIPTED_UAS + HUMAN_UAS[:3]),
                fingerprint_hash=fingerprint,
                network_class=rng.choices(
                    ("datacenter", "unknown", "residential", "mobile"), weights=(0.55, 0.3, 0.1, 0.05)
                )[0],
                bytes_in=int(abs(rng.gauss(4200, 2600)) + 200),
                latency_ms=latency,
                labels={"population": "scripted"},
            )
        )
    return events


def make_human(rng: random.Random, client: str, start: float, count: int, regular: bool = False) -> List[EventRecord]:
    """Irregular human traffic: bursts, gaps, rotating agents.

    `regular=True` is the hard negative: a person who checks the same page at the
    same time every morning. Cadence alone should not call them a bot.
    """
    key = derive_client_key(SALT, EPOCH, client)
    fingerprints = [f"ja4:{rng.getrandbits(48):012x}" for _ in range(rng.randint(2, 4))]
    uas = rng.sample(HUMAN_UAS, k=rng.randint(1, 3))
    events = []
    t = start
    for _ in range(count):
        # Bimodal gaps: quick follow-ups and long absences.
        if regular:
            gap = abs(rng.gauss(86400.0 / max(count, 1), 60.0)) if rng.random() < 0.8 else abs(rng.gauss(900.0, 200.0))
        else:
            gap = abs(rng.gauss(40.0, 25.0)) if rng.random() < 0.65 else abs(rng.gauss(2600.0, 900.0))
        t += gap
        # Diurnal-ish clustering: business hours are busier.
        hour = (t % 86400.0) / 3600.0
        if 8.0 <= hour <= 19.0 and rng.random() < 0.7:
            t += abs(rng.gauss(20.0, 10.0))
        latency = abs(rng.gauss(140.0, 55.0))
        events.append(
            EventRecord(
                event_id=str(uuid.uuid4()),
                observed_at=t,
                source_id=_pick(rng, SOURCES),
                client_key=key,
                channel=rng.choice(("site_visit", "canary_access", "honeytoken_access", "feed_item")),
                protocol=rng.choices(("h2", "http/1.1"), weights=(0.85, 0.15))[0],
                ua_family=_pick(rng, uas),
                fingerprint_hash=_pick(rng, fingerprints),
                network_class=rng.choices(
                    ("residential", "mobile", "unknown", "datacenter"), weights=(0.5, 0.25, 0.15, 0.1)
                )[0],
                bytes_in=int(abs(rng.gauss(9000, 7000)) + 300),
                latency_ms=abs(rng.gauss(95.0, 60.0)),
                labels={"population": "human"},
            )
        )
    return events


def generate(seed: int = 7, scripted_clients: int = 12, human_clients: int = 18, events_each: int = 60, mixed_share: float = 0.3):
    """Return (records, truth) where truth maps client_key -> population.

    `mixed_share` of each population gets the hard variant, so the demo dataset has
    real overlap instead of two well-separated clouds.
    """
    rng = random.Random(seed)
    start = 1767225600.0  # 2026-01-01T00:00:00Z, fixed so runs are reproducible
    records: List[EventRecord] = []
    truth = {}
    for i in range(scripted_clients):
        client = f"198.51.100.{10 + i}"  # TEST-NET-2, reserved for documentation
        sloppy = rng.random() < mixed_share
        batch = make_scripted(rng, client, start + rng.uniform(0, 3600), events_each, sloppy=sloppy)
        records.extend(batch)
        truth[batch[0].client_key] = "scripted"
    for i in range(human_clients):
        client = f"203.0.113.{10 + i}"  # TEST-NET-3, reserved for documentation
        regular = rng.random() < mixed_share
        batch = make_human(rng, client, start + rng.uniform(0, 3600), events_each, regular=regular)
        records.extend(batch)
        truth[batch[0].client_key] = "human"
    records.sort(key=lambda r: r.observed_at)
    return records, truth


def summarize(records: List[EventRecord]) -> dict:
    keys = {r.client_key for r in records}
    span = (records[-1].observed_at - records[0].observed_at) if records else 0.0
    return {
        "events": len(records),
        "clients": len(keys),
        "span_hours": round(span / 3600.0, 2),
        "events_per_client": round(len(records) / max(len(keys), 1), 1),
        "finite": all(math.isfinite(r.observed_at) for r in records),
    }
