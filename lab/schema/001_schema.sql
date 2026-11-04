-- lab/schema/001_schema.sql
--
-- Time-series schema for the experimental lab.
--
-- Fixes relative to the design notes this file came from:
--
-- 1. PRIMARY KEY (observation_id, observed_at). The earlier draft declared
--    `PRIMARY KEY (observation_id, observed_at)` on a table that also had
--    `PARTITION BY RANGE (observed_at)` and then called create_hypertable(). Those
--    are two different partitioning systems: a table declared PARTITION BY is a
--    native PostgreSQL partitioned table and cannot be converted into a hypertable.
--    Here the table is plain, and create_hypertable() does the partitioning.
-- 2. The primary key MUST include the time column. TimescaleDB requires every
--    unique index on a hypertable to contain the partitioning column, so
--    `PRIMARY KEY (observation_id)` alone is rejected at create_hypertable() time.
-- 3. Retention, compression, and RLS are part of the schema rather than a
--    follow-up meeting. A table of behavioral observations with no retention
--    policy is a liability with an index.
-- 4. There is no IP address column, and no raw user agent. `client_key` is a
--    salted, truncated hash that is only meaningful inside one salt epoch.

-- Re-runnable by design: every object is created IF NOT EXISTS, policies are dropped
-- before they are recreated, and the role block below checks first. Applying this file
-- twice against the same database is a no-op, which matters because the file also
-- serves as the document of record and will be pasted into psql more than once.
--
-- Two classes of statement still fail without the extension installed, and they are
-- the only ones that do: CREATE EXTENSION timescaledb, create_hypertable(),
-- the compression/retention policies, and the time_bucket() rollup. Everything else
-- applies cleanly on stock PostgreSQL, which is how the schema is tested here.

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Salt epochs make key rotation a first-class operation: retiring an epoch severs
-- the link between today's observations and last month's.
CREATE TABLE IF NOT EXISTS salt_epochs (
    salt_epoch   TEXT PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sources (
    source_id    TEXT PRIMARY KEY,
    description  TEXT,
    added_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clients (
    client_key   TEXT PRIMARY KEY,
    salt_epoch   TEXT NOT NULL REFERENCES salt_epochs(salt_epoch),
    network_class TEXT NOT NULL CHECK (network_class IN ('residential', 'mobile', 'datacenter', 'unknown')),
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    CONSTRAINT client_key_is_short_hash CHECK (client_key ~ '^[0-9a-f]{8,64}$')
);

CREATE TABLE IF NOT EXISTS events (
    observed_at    TIMESTAMPTZ NOT NULL,
    event_id       UUID NOT NULL,
    source_id      TEXT NOT NULL REFERENCES sources(source_id),
    client_key     TEXT NOT NULL REFERENCES clients(client_key),
    channel        TEXT NOT NULL CHECK (channel IN ('feed_item', 'canary_access', 'honeytoken_access', 'site_visit')),
    protocol       TEXT NOT NULL CHECK (protocol IN ('http/1.1', 'h2', 'h3', 'unknown')),
    ua_family      TEXT NOT NULL CHECK (ua_family IN ('curl', 'python-requests', 'go-http-client', 'headless-chromium', 'chrome', 'firefox', 'safari', 'other', 'unknown')),
    fingerprint_hash TEXT NOT NULL,
    bytes_in       INTEGER NOT NULL CHECK (bytes_in >= 0),
    latency_ms     DOUBLE PRECISION NOT NULL CHECK (latency_ms >= 0),
    labels         JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Time column first: required for the hypertable's unique index.
    PRIMARY KEY (observed_at, event_id)
);

SELECT create_hypertable('events', 'observed_at', chunk_time_interval => INTERVAL '1 day');

CREATE INDEX IF NOT EXISTS events_client_time_idx ON events (client_key, observed_at DESC);
CREATE INDEX IF NOT EXISTS events_channel_time_idx ON events (channel, observed_at DESC);
CREATE INDEX IF NOT EXISTS events_fingerprint_idx ON events (fingerprint_hash, observed_at DESC);

-- ---------------------------------------------------------------------------
-- Enrichment layer
--
-- enrich.R writes to `enrichment` and reads `semantic_anchors`, and neither table
-- existed in the first draft of this schema. The script was therefore written
-- against relations that would not have been there at run time: every insert would
-- have failed on a missing relation, and the failure would have looked like an R
-- problem rather than a schema one.
--
-- Neither table collects anything new. `enrichment` derives a coarse pace bucket
-- from latency that is already stored, one row per event so a re-run cannot
-- double-count, and `semantic_anchors` is reference data for similarity matching.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS enrichment (
    event_id     UUID PRIMARY KEY,
    pace_bucket  TEXT NOT NULL CHECK (pace_bucket IN ('fast', 'normal', 'slow')),
    enriched_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- No foreign key to events, deliberately: a hypertable's unique index has to
-- contain the partitioning column, so `event_id` alone cannot be referenced and a
-- composite key would force the enrichment step to carry timestamps it does not
-- use. Retention can outlive an enrichment row; every read joins to `events`, so
-- an orphan is never surfaced, only never shown.

CREATE INDEX IF NOT EXISTS enrichment_pace_idx ON enrichment (pace_bucket);

CREATE TABLE IF NOT EXISTS semantic_anchors (
    anchor_id    SERIAL PRIMARY KEY,
    anchor_text  TEXT NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The same cap the R sanitiser applies, enforced where it cannot be bypassed.
    CONSTRAINT anchor_text_is_sane CHECK (char_length(anchor_text) BETWEEN 1 AND 512)
);

-- similarity() is only cheap with a trigram index; without one the "ask the
-- database instead of building SQL from candidate strings" approach becomes a
-- sequential scan per candidate and gets replaced by something worse under load.
CREATE INDEX IF NOT EXISTS semantic_anchors_trgm_idx ON semantic_anchors USING gin (anchor_text gin_trgm_ops);

GRANT SELECT, INSERT ON enrichment TO lab_analysis;
GRANT USAGE, SELECT ON SEQUENCE semantic_anchors_anchor_id_seq TO lab_analysis;
GRANT SELECT ON semantic_anchors TO lab_analysis;
REVOKE ALL ON enrichment, semantic_anchors FROM PUBLIC;

-- Compress older chunks; segment by client so per-client queries stay fast.
ALTER TABLE events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'client_key',
    timescaledb.compress_orderby = 'observed_at DESC'
);
SELECT add_compression_policy('events', INTERVAL '7 days');
SELECT add_retention_policy('events', INTERVAL '30 days');

-- ---------------------------------------------------------------------------
-- Least privilege
--
-- The analysis role can read and insert, never update or drop. This is the half of
-- the "second-order injection" mitigation that lives in the database: even a query
-- built from adversarial text cannot escalate to DDL or to rewriting history.
-- ---------------------------------------------------------------------------

-- Roles are cluster-wide, not database-wide, so a plain CREATE breaks the second
-- application of this file with "role already exists". Idempotent instead: this
-- schema is meant to be re-runnable against a database that is already there.
DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lab_analysis') THEN
        CREATE ROLE lab_analysis NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lab_ingest') THEN
        CREATE ROLE lab_ingest NOLOGIN;
    END IF;
END
$roles$;

GRANT USAGE ON SCHEMA public TO lab_analysis, lab_ingest;
GRANT SELECT, INSERT ON events TO lab_ingest;
GRANT SELECT ON events, clients, sources, salt_epochs TO lab_analysis;
GRANT INSERT ON clients, salt_epochs TO lab_ingest;

ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;

-- Analysis sees aggregates and recent rows only. Adjust the window to your policy.
DROP POLICY IF EXISTS events_analysis_recent ON events;
CREATE POLICY events_analysis_recent ON events
    FOR SELECT TO lab_analysis
    USING (observed_at > now() - INTERVAL '30 days');

DROP POLICY IF EXISTS clients_analysis_read ON clients;
CREATE POLICY clients_analysis_read ON clients
    FOR SELECT TO lab_analysis
    USING (true);

REVOKE ALL ON events FROM PUBLIC;
REVOKE ALL ON clients FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- k-anonymous reporting view
--
-- The published view groups by hour and channel with a minimum cell size of 5, so
-- no row describes an individual. Anything smaller stays in the lab database.
-- ---------------------------------------------------------------------------

CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_channel_rollup AS
SELECT
    time_bucket(INTERVAL '1 hour', observed_at) AS hour_bucket,
    channel,
    COUNT(DISTINCT client_key)                  AS distinct_clients,
    COUNT(*)                                    AS events,
    ROUND(AVG(latency_ms)::numeric, 1)          AS mean_latency_ms
FROM events
GROUP BY hour_bucket, channel
HAVING COUNT(DISTINCT client_key) >= 5
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS hourly_channel_rollup_idx ON hourly_channel_rollup (hour_bucket, channel);

-- Refresh from the orchestrator, not on a timer nobody owns:
--   REFRESH MATERIALIZED VIEW CONCURRENTLY hourly_channel_rollup;
