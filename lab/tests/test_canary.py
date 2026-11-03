"""Tests for the canary modules: tokens, tamper detection, callback listener."""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
import urllib.error
import urllib.request

from lab.canary import listener, manifest, tokens
from lab.features import contract


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.secret = tokens.new_secret()

    def test_issue_is_deterministic(self):
        a = tokens.issue("Vendor Export", self.secret, "2026-11")
        b = tokens.issue("vendor export", self.secret, "2026-11")
        self.assertEqual(a.token_id, b.token_id, "labels are normalised before hashing")

    def test_epoch_rotation_changes_token(self):
        a = tokens.issue("vendor-export", self.secret, "2026-11")
        b = tokens.issue("vendor-export", self.secret, "2026-12")
        self.assertNotEqual(a.token_id, b.token_id)

    def test_verify_rejects_wrong_label_and_secret(self):
        token = tokens.issue("vendor-export", self.secret, "2026-11")
        self.assertTrue(tokens.verify(token.token_id, "vendor-export", self.secret, "2026-11"))
        self.assertFalse(tokens.verify(token.token_id, "other-label", self.secret, "2026-11"))
        self.assertFalse(tokens.verify(token.token_id, "vendor-export", tokens.new_secret(), "2026-11"))

    def test_issue_refuses_empty_inputs(self):
        with self.assertRaises(tokens.TokenError):
            tokens.issue("", self.secret, "2026-11")
        with self.assertRaises(tokens.TokenError):
            tokens.issue("label", "", "2026-11")

    def test_parse_path(self):
        token = tokens.issue("site", self.secret, "2026-11")
        self.assertEqual(tokens.parse_path(f"/c/{token.token_id}?x=1"), token.token_id)
        self.assertIsNone(tokens.parse_path("/c/not-a-token"))
        self.assertIsNone(tokens.parse_path("/"))
        self.assertIsNone(tokens.parse_path(""))

    def test_callback_url(self):
        token = tokens.issue("site", self.secret, "2026-11")
        self.assertEqual(
            token.callback_url("https://canary.example.invalid/"),
            f"https://canary.example.invalid/c/{token.token_id}",
        )


class ManifestTests(unittest.TestCase):
    def test_detects_missing_modified_and_added(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "decoy-a.txt").write_text("canary a\n")
            (root / "decoy-b.txt").write_text("canary b\n")
            baseline = manifest.snapshot(root, ["decoy-a.txt", "decoy-b.txt"])
            self.assertEqual(len(baseline), 2)

            (root / "decoy-a.txt").write_text("canary a, edited\n")
            (root / "decoy-b.txt").unlink()
            (root / "decoy-c.txt").write_text("new file\n")

            report = manifest.verify(root, baseline, watch=["decoy-a.txt", "decoy-b.txt", "decoy-c.txt"])
            self.assertEqual(report.missing, ["decoy-b.txt"])
            self.assertEqual(report.modified, ["decoy-a.txt"])
            self.assertEqual(report.added, ["decoy-c.txt"])
            self.assertFalse(report.clean)
            self.assertIn("missing:decoy-b.txt", report.signals)

    def test_clean_when_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "decoy.txt").write_text("steady\n")
            baseline = manifest.snapshot(root, ["decoy.txt"])
            report = manifest.verify(root, baseline)
            self.assertTrue(report.clean)
            self.assertEqual(report.intact, ["decoy.txt"])

    def test_snapshot_refuses_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "inner"
            root.mkdir()
            with self.assertRaises(ValueError):
                manifest.snapshot(root, ["../outside.txt"])

    def test_events_from_report_uses_the_host_key(self):
        report = manifest.TamperReport(missing=["decoy-b.txt"], modified=["decoy-a.txt"])
        host_key = contract.derive_client_key(b"secret", "2026-11", "127.0.0.1")
        events = manifest.events_from_report(report, host_key, observed_at=1767225600.0)
        self.assertEqual(len(events), 2)
        for event in events:
            event.validate()
            self.assertEqual(event.channel, "canary_access")
            self.assertEqual(event.client_key, host_key)
        self.assertEqual({e.labels["signal"] for e in events}, {"missing", "modified"})


class ListenerTests(unittest.TestCase):
    def test_callback_records_event_without_storing_the_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            jsonl = pathlib.Path(tmp) / "canary_events.jsonl"
            secret = tokens.new_secret()
            epoch = "2026-11"
            token = tokens.issue("site-footer", secret, epoch)

            with listener.serve(jsonl, secret, epoch) as srv:
                url = f"http://127.0.0.1:{srv.bound_port}/c/{token.token_id}"
                request = urllib.request.Request(url, headers={"User-Agent": "curl/8.4.0"})
                with urllib.request.urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 204)

            raw = jsonl.read_text()
            self.assertNotIn("127.0.0.1", raw, "the raw address must never be written")
            lines = [json.loads(line) for line in raw.splitlines() if line.strip()]
            self.assertEqual(len(lines), 1)
            event = lines[0]
            self.assertEqual(event["channel"], "canary_access")
            self.assertEqual(event["ua_family"], "curl")
            self.assertEqual(event["labels"]["token_id"], token.token_id)
            self.assertEqual(
                event["client_key"],
                contract.derive_client_key(secret.encode("utf-8"), epoch, "127.0.0.1"),
            )
            contract.EventRecord(**event).validate()

    def test_unknown_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            jsonl = pathlib.Path(tmp) / "events.jsonl"
            secret = tokens.new_secret()
            with listener.serve(jsonl, secret, "2026-11") as srv:
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(f"http://127.0.0.1:{srv.bound_port}/nope", timeout=5)
                self.assertEqual(ctx.exception.code, 404)
            self.assertFalse(jsonl.exists(), "a rejected path writes no event")

    def test_ua_classification_stays_in_the_closed_vocabulary(self):
        for header in ("curl/8", "python-requests/2.31", "Mozilla/5.0 Chrome/120", "", None, "WeirdThing/1"):
            self.assertIn(listener.classify_ua(header), contract.UA_FAMILIES)


if __name__ == "__main__":
    unittest.main()
