"""Pilot tests: the first run has to be able to start.

A pilot fails in the boring places. Someone writes a compose file, nobody starts it because
the sandbox has no daemon, and it ships with a service that authenticates as a role the
schema deliberately made NOLOGIN, a readiness check that passes before the schema exists,
and a published port on every interface. None of that is a security bug in the interesting
sense. All of it is the difference between a stack that comes up and one that does not.

So the static half checks the file against the things it claims, and the live half runs the
role bootstrap against a real server when one is reachable, because the first version of
that script was syntactically fine and did nothing at all.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
LAB = ROOT / "lab"
COMPOSE = LAB / "docker-compose.yml"
SCHEMA = LAB / "schema" / "001_schema.sql"
BOOTSTRAP = LAB / "schema" / "002_pilot_roles.sh"
ENV_TEMPLATE = LAB / ".env.example"

try:  # pyyaml is a test convenience, not a lab dependency
    import yaml
except Exception:  # pragma: no cover - exercised only where pyyaml is absent
    yaml = None


def compose_text() -> str:
    return COMPOSE.read_text(encoding="utf-8")


def compose() -> dict:
    if yaml is None:
        raise unittest.SkipTest("pyyaml is not installed")
    return yaml.safe_load(compose_text())


class ComposeContractTests(unittest.TestCase):
    def test_the_stack_parses_and_names_its_services(self):
        doc = compose()
        self.assertEqual(set(doc["services"]), {"timescaledb", "pipeline"})

    def test_postgres_is_not_published_on_every_interface(self):
        ports = compose()["services"]["timescaledb"]["ports"]
        self.assertTrue(ports)
        for mapping in ports:
            self.assertTrue(
                str(mapping).startswith("127.0.0.1:"),
                f"port mapping {mapping!r} is reachable from the network; a pilot is a laptop or a shared host",
            )

    def test_readiness_means_the_schema_is_present(self):
        """An open socket is not a migrated database, and the difference is a stale volume."""
        check = compose()["services"]["timescaledb"]["healthcheck"]["test"]
        blob = " ".join(check) if isinstance(check, list) else str(check)
        self.assertIn("information_schema.tables", blob)
        self.assertIn("events", blob, "the readiness check must name a table the schema creates")

    def test_init_scripts_are_mounted_before_the_database_sets_its_own_state(self):
        volumes = compose()["services"]["timescaledb"]["volumes"]
        mounts = [v for v in volumes if "docker-entrypoint-initdb.d" in str(v)]
        self.assertEqual(len(mounts), 1)
        self.assertIn(":ro", str(mounts[0]), "the database should not be able to rewrite its own bootstrap")

    def test_the_pipeline_is_not_handed_credentials_it_never_uses(self):
        """The service used to authenticate as a NOLOGIN role for a connection it never made."""
        env = compose()["services"]["pipeline"].get("environment") or {}
        for name in env:
            self.assertNotIn(name, {"PGHOST", "PGUSER", "PGPASSWORD", "PGPORT", "PGDATABASE"})

        pipeline_source = (LAB / "orchestrator" / "run_pipeline.py").read_text(encoding="utf-8")
        for driver in ("psycopg", "psycopg2", "asyncpg", "PGHOST"):
            self.assertNotIn(driver, pipeline_source, f"the pipeline now uses {driver}; then it needs the credentials back")

    def test_the_image_can_be_pinned(self):
        """A mutable tag is fine for a pilot and wrong for anything after one."""
        image = compose()["services"]["timescaledb"]["image"]
        self.assertIn("${TIMESCALE_IMAGE:-", str(image))

    def test_every_variable_the_stack_requires_is_in_the_template(self):
        text = compose_text()
        template = ENV_TEMPLATE.read_text(encoding="utf-8")
        required = set(re.findall(r"\$\{([A-Z_]+):\?", text))
        referenced = set(re.findall(r"\$\{([A-Z_]+)", text))
        self.assertTrue(required, "the compose file should be explicit about what it cannot default")
        for name in sorted(referenced):
            self.assertIn(name, template, f"{name} is used by the stack and undocumented in .env.example")


class RoleBootstrapTests(unittest.TestCase):
    def test_the_schema_keeps_its_roles_unable_to_log_in(self):
        schema = SCHEMA.read_text(encoding="utf-8")
        self.assertIn("CREATE ROLE lab_analysis NOLOGIN", schema)
        self.assertIn("CREATE ROLE lab_ingest NOLOGIN", schema)

    def test_the_bootstrap_grants_login_by_explicit_opt_in(self):
        script = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("ALTER ROLE", script)
        self.assertIn("LOGIN", script)
        self.assertIn("ANALYSIS_PASSWORD", script)
        self.assertIn("NOSUPERUSER", script, "the role must not gain more than the ability to connect")

    def test_the_bootstrap_does_not_use_psql_dash_c(self):
        """`psql -c` does not interpolate -v variables, so the ALTER would fail on a bare colon."""
        script = BOOTSTRAP.read_text(encoding="utf-8")
        body = "\n".join(
            line for line in script.splitlines() if line.strip() and not line.strip().startswith("#")
        )
        self.assertNotIn('"$@" <<', body)  # guard against a future rewrite in the other direction
        for line in body.splitlines():
            if "-c " in line:
                self.assertNotIn("ALTER ROLE", line, "the ALTER is fed on stdin so variables interpolate")

    def test_the_bootstrap_is_executable(self):
        self.assertTrue(os.access(BOOTSTRAP, os.X_OK), "the entrypoint runs .sh files directly")

    def test_bootstrap_against_a_live_server(self):
        """The claim worth testing for real: a hostile password becomes a working LOGIN."""
        psql = shutil.which("psql")
        if not psql or not os.environ.get("PGHOST"):
            raise unittest.SkipTest("no psql or PGHOST; set both to exercise the live path")

        def query(sql: str) -> str:
            out = subprocess.run(
                [psql, "-v", "ON_ERROR_STOP=1", "-tAc", sql],
                capture_output=True,
                text=True,
                check=True,
            )
            return out.stdout.strip()

        def can_login(role: str) -> bool:
            return query(f"SELECT rolcanlogin FROM pg_roles WHERE rolname = '{role}'") == "t"

        hostile = "p'a-ss word; DROP TABLE events"
        subprocess.run([psql, "-v", "ON_ERROR_STOP=1", "-q", "-c", "ALTER ROLE lab_analysis NOLOGIN"], check=True)
        self.assertFalse(can_login("lab_analysis"))

        env = dict(
            os.environ,
            ANALYSIS_PASSWORD=hostile,
            POSTGRES_USER=os.environ.get("PGUSER", "postgres"),
            POSTGRES_DB=os.environ.get("PGDATABASE", "lab"),
        )
        subprocess.run(["sh", str(BOOTSTRAP)], env=env, check=True, capture_output=True)

        self.assertTrue(can_login("lab_analysis"), "the bootstrap did not grant LOGIN")
        self.assertEqual(
            query("SELECT rolsuper FROM pg_roles WHERE rolname = 'lab_analysis'"), "f", "it granted superuser"
        )
        self.assertEqual(
            query("SELECT count(*) FROM information_schema.tables WHERE table_name = 'events'"),
            "1",
            "a quote in a password reached the parser as SQL",
        )
        self.assertFalse(can_login("lab_ingest"), "a blank password must leave the role exactly as the schema made it")

        subprocess.run([psql, "-v", "ON_ERROR_STOP=1", "-q", "-c", "ALTER ROLE lab_analysis NOLOGIN"], check=True)


class DisclosureTests(unittest.TestCase):
    """The readme has to say what the pilot does not cover, in the same place a reader decides."""

    def test_the_readme_has_a_disclosure_section(self):
        text = (LAB / "README.md").read_text(encoding="utf-8")
        self.assertIn("## Disclosure", text)

    def test_the_disclosure_names_the_residual_risks(self):
        text = (LAB / "README.md").read_text(encoding="utf-8")
        section = text.split("## Disclosure", 1)[1]
        for topic in (
            "timing",
            "pilot",
            "enrich",
            "unverified",
        ):
            self.assertIn(topic, section.lower(), f"the disclosure does not mention {topic}")


if __name__ == "__main__":
    unittest.main()
