"""Verification for `lab/enrich/enrich.R`.

The R layer was previously marked UNVERIFIED because no R was installed in the sandbox. It has
now been exercised against PostgreSQL 18.6 with R 4.6.2, DBI 1.3.0, and RPostgres 1.4.10, and
that exercise found three real defects, all of which are now regression tests here:

1. `[\\u0000-\\u001f]` in a string literal does not parse. R forbids a nul character in a
   string, so the file failed at parse time and never reached a database.
2. `main()` called `enrich_batch(con)` with no cursor on every pass, so it re-read the same
   first batch forever. The loop could not terminate, and it looked like work.
3. `enrich_batch` returned rows read rather than rows inserted, so a second pass reported
   "enriched 7 rows" while writing nothing.

Two tiers of test: the static ones run anywhere, and the R and database ones skip when the
toolchain is absent rather than pretending to pass. Set `LAB_VERIFY_DSN` to whitespace-separated
`key=value` pairs to run the database cases:

    LAB_VERIFY_DSN="host=/tmp/pgrun port=55432 dbname=lab user=postgres" \\
        python3 -m unittest lab.tests.test_enrich_r
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "lab" / "enrich" / "enrich.R"
RSCRIPT = os.environ.get("RSCRIPT") or shutil.which("Rscript")
DSN = os.environ.get("LAB_VERIFY_DSN", "").strip()

SKIP_R = "R is not installed (set RSCRIPT, or put Rscript on PATH)"
SKIP_DB = "set LAB_VERIFY_DSN to run the database cases"


def dsn_env(value: str) -> dict:
    """`host=... port=... dbname=...` into the PG* variables RPostgres already reads."""
    mapping = {
        "host": "PGHOST",
        "port": "PGPORT",
        "dbname": "PGDATABASE",
        "user": "PGUSER",
        "password": "PGPASSWORD",
    }
    env = dict(os.environ)
    for token in value.split():
        key, _, val = token.partition("=")
        if key in mapping:
            env[mapping[key]] = val
    return env


def run_r(code: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [RSCRIPT, "--vanilla", "-e", textwrap.dedent(code)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=180,
        env=env or dict(os.environ),
    )


class StaticTests(unittest.TestCase):
    """Checks that need neither R nor a database, so a regression cannot slip past a bare sandbox."""

    def setUp(self):
        self.source = SCRIPT.read_text(encoding="utf-8")

    def test_no_nul_escape_in_a_string_literal(self):
        """The comment explaining the old defect mentions it; only code matters."""
        code = "\n".join(
            line for line in self.source.splitlines() if not line.strip().startswith("#")
        )
        self.assertNotIn("\\u0000", code, "R cannot parse a nul character in a string")

    def test_pages_are_ordered_by_their_cursor(self):
        """Paging by event_id while ordering by observed_at revisits and skips rows."""
        self.assertIn("ORDER BY event_id", self.source)
        self.assertNotIn("ORDER BY observed_at", self.source)

    def test_the_loop_advances_its_cursor(self):
        self.assertIn("cursor <- batch$cursor", self.source)
        self.assertIn("enrich_batch(con, since_event_id = cursor)", self.source)

    def test_queries_are_parameterised(self):
        """Second-order injection was the original defect; no value may be pasted into SQL."""
        self.assertIn("params = list(", self.source)
        for line in self.source.splitlines():
            if "SELECT" in line or "INSERT" in line:
                self.assertNotIn("paste0(", line)

    def test_nothing_calls_out_to_a_network_service(self):
        for token in ("httr", "curl::", "url(", "download.file"):
            self.assertNotIn(token, self.source)


@unittest.skipUnless(RSCRIPT, SKIP_R)
class RSyntaxTests(unittest.TestCase):
    def test_the_script_parses(self):
        finished = run_r('invisible(parse("lab/enrich/enrich.R")); cat("parsed\\n")')
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assertIn("parsed", finished.stdout)

    def test_sanitiser_behaviour(self):
        finished = run_r(
            '''
            source("lab/enrich/enrich.R")
            stopifnot(sanitize_text("a\\u0001b") == "a b")          # C0 control
            stopifnot(sanitize_text("a\\u009fb") == "a b")          # C1 control
            stopifnot(sanitize_text("a\\u200bb") == "a b")          # zero width
            stopifnot(sanitize_text("  a   b  ") == "a b")          # whitespace collapse
            stopifnot(sanitize_text(NA_character_) == "")
            stopifnot(nchar(sanitize_text(strrep("x", 5000))) == 512L)
            cat("sanitiser ok\\n")
            '''
        )
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assertIn("sanitiser ok", finished.stdout)


@unittest.skipUnless(RSCRIPT and DSN, SKIP_DB)
class DatabaseTests(unittest.TestCase):
    """The round trip: seed events, page through them, and prove a second pass writes nothing."""

    def test_paging_inserts_once_and_terminates(self):
        finished = run_r(
            '''
            source("lab/enrich/enrich.R")
            con <- connect()
            on.exit(dbDisconnect(con), add = TRUE)

            ids <- sprintf("11111111-1111-1111-1111-%012d", 1:7)
            dbExecute(con, "INSERT INTO salt_epochs (salt_epoch) VALUES (\'verify\') ON CONFLICT DO NOTHING")
            dbExecute(con, "INSERT INTO sources (source_id, description) VALUES (\'verify\', \'test fixture\') ON CONFLICT DO NOTHING")
            dbExecute(con, paste(
              "INSERT INTO clients (client_key, salt_epoch, network_class, first_seen, last_seen)",
              "VALUES (\'deadbeef\', \'verify\', \'residential\', now(), now()) ON CONFLICT DO NOTHING"))
            dbExecute(con, "DELETE FROM enrichment")
            dbExecute(con, "DELETE FROM events WHERE client_key = \'deadbeef\'")
            for (i in seq_along(ids)) {
              dbExecute(con, paste(
                "INSERT INTO events (observed_at, event_id, source_id, client_key, channel, protocol,",
                "ua_family, fingerprint_hash, bytes_in, latency_ms)",
                "VALUES (now() - ($1 || \' minutes\')::interval, $2::uuid, \'verify\', \'deadbeef\', \'site_visit\',",
                "\'h2\', \'curl\', \'abc123\', 100, $3)"),
                params = list(i, ids[i], c(10, 120, 500, 30, 250, 60, 90)[i]))
            }

            first  <- enrich_batch(con, NULL, 3L)
            second <- enrich_batch(con, first$cursor, 3L)
            third  <- enrich_batch(con, second$cursor, 3L)
            empty  <- enrich_batch(con, third$cursor, 3L)
            stopifnot(first$rows == 3L, second$rows == 3L, third$rows == 1L, empty$rows == 0L)
            stopifnot(first$inserted + second$inserted + third$inserted == 7L)
            stopifnot(first$cursor != second$cursor)

            buckets <- dbGetQuery(con, "SELECT pace_bucket, count(*) AS n FROM enrichment GROUP BY 1 ORDER BY 1")
            stopifnot(sum(buckets$n) == 7L)
            stopifnot(setequal(buckets$pace_bucket, c("fast", "normal", "slow")))

            # a full pass over already-enriched rows inserts nothing, and still terminates
            dbExecute(con, "DELETE FROM enrichment")
            stopifnot(main() == 7L)
            stopifnot(main() == 0L)

            dbExecute(con, "DELETE FROM enrichment")
            dbExecute(con, "DELETE FROM events WHERE client_key = \'deadbeef\'")
            cat("database round trip ok\\n")
            ''',
            env=dsn_env(DSN),
        )
        self.assertEqual(finished.returncode, 0, finished.stderr + finished.stdout)
        self.assertIn("database round trip ok", finished.stdout)


if __name__ == "__main__":
    unittest.main()
