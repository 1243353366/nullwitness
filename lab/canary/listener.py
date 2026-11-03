"""Canary callback listener.

A stdlib HTTP listener whose only job is to notice that a token was used and append a
contract-compliant event. No cookies, no JavaScript, no image squeeze, no redirect
chain, and no attempt to fingerprint beyond what the request already carries. The
connecting address is hashed with the salt epoch and never written to disk.

Run it:

    python3 -m lab.canary.listener --jsonl lab/reports/canary_events.jsonl \\
        --base-url https://canary.example.invalid --port 8080

Then a token issued for label "vendor-export-2026-11" produces a URL you can place in
a document you own. A request to that URL writes one line of JSONL.

Deliberately absent: any mechanism that makes a request happen without the visitor
acting. If a document is opened by software that fetches remote resources, that is the
viewer's behaviour and the operator's notice obligation, not something this file
implements.
"""

from __future__ import annotations

import argparse
import http.server
import json
import pathlib
import socketserver
import threading
import time
import uuid
from typing import Optional

from lab.canary import tokens
from lab.features import contract

UA_RULES = (
    ("curl", "curl"),
    ("python-requests", "python-requests"),
    ("python-urllib", "python-requests"),
    ("go-http-client", "go-http-client"),
    ("headlesschrome", "headless-chromium"),
    ("chrome", "chrome"),
    ("firefox", "firefox"),
    ("safari", "safari"),
)


def classify_ua(user_agent: Optional[str]) -> str:
    """Map a User-Agent to the closed vocabulary in the event contract.

    The raw header is never stored: it is the most identifying string in a request and
    this module's whole purpose is a coarse access signal.
    """
    if not user_agent:
        return "unknown"
    lowered = user_agent.lower()
    for needle, family in UA_RULES:
        if needle in lowered:
            return family
    return "other"


def _protocol(request_version: str) -> str:
    mapping = {"HTTP/1.1": "http/1.1", "HTTP/1.0": "http/1.1", "HTTP/2.0": "h2"}
    return mapping.get(request_version, "unknown")


class CanaryServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def __init__(self, address, jsonl_path: pathlib.Path, secret: str, salt_epoch: str):
        super().__init__(address, CanaryHandler)
        self.jsonl_path = pathlib.Path(jsonl_path)
        self.secret = secret
        self.salt_epoch = salt_epoch
        self._lock = threading.Lock()

    def record(self, event: contract.EventRecord) -> None:
        line = json.dumps(event.to_row(), sort_keys=True)
        with self._lock:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            with self.jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


class CanaryHandler(http.server.BaseHTTPRequestHandler):
    server_version = "lab-canary/0.1"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self._handle(body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib naming
        self._handle(body=False)

    def _handle(self, body: bool) -> None:
        token_id = tokens.parse_path(self.path)
        if token_id is None:
            self.send_error(404, "not a canary callback")
            return

        server: CanaryServer = self.server  # type: ignore[assignment]
        client_key = contract.derive_client_key(
            server.secret.encode("utf-8"),
            server.salt_epoch,
            self.client_address[0],
        )
        event = contract.EventRecord(
            event_id=uuid.uuid4().hex,
            observed_at=time.time(),
            source_id="canary:token",
            client_key=client_key,
            channel="canary_access",
            protocol=_protocol(self.request_version),
            ua_family=classify_ua(self.headers.get("User-Agent")),
            fingerprint_hash="unavailable",  # no TLS termination at this layer
            network_class="unknown",
            bytes_in=len(self.headers.get("User-Agent", "")),
            latency_ms=0.0,
            labels={"token_id": token_id},
        )
        try:
            server.record(event)
        except contract.ContractViolation:
            self.send_error(500, "event rejected by the contract")
            return

        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(b"")

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - stdlib signature
        # Access logs go to the JSONL event stream, not stdout: stdout would put the
        # raw address in a container log, which is the thing this module avoids.
        return


class serve:
    """Context manager: `with serve(...) as srv: srv.port`."""

    def __init__(self, jsonl_path, secret: str, salt_epoch: str, host: str = "127.0.0.1", port: int = 0):
        self.jsonl_path = pathlib.Path(jsonl_path)
        self.secret = secret
        self.salt_epoch = salt_epoch
        self.host = host
        self.port = port
        self.server: Optional[CanaryServer] = None
        self.thread: Optional[threading.Thread] = None

    def __enter__(self) -> "serve":
        self.server = CanaryServer((self.host, self.port), self.jsonl_path, self.secret, self.salt_epoch)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    @property
    def bound_port(self) -> int:
        assert self.server is not None
        return self.server.server_address[1]

    def __exit__(self, *exc_info) -> None:
        assert self.server is not None
        self.server.shutdown()
        self.server.server_close()
        if self.thread:
            self.thread.join(timeout=5)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Log canary token callbacks as contract events.")
    parser.add_argument("--jsonl", type=pathlib.Path, required=True)
    parser.add_argument("--label", default="demo", help="label to issue a demo token for")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--epoch", default="2026-11")
    parser.add_argument("--secret", default=None, help="HMAC key; generated if omitted")
    args = parser.parse_args(argv)

    secret = args.secret or tokens.new_secret()
    token = tokens.issue(args.label, secret, args.epoch)
    print(f"token_id   {token.token_id}")
    print(f"callback   {token.callback_url(args.base_url)}")
    print(f"secret     {secret}   (store this; callbacks cannot be re-derived without it)")
    print(f"events     {args.jsonl}")
    with serve(args.jsonl, secret, args.epoch, host=args.host, port=args.port) as srv:
        print(f"listening on http://{args.host}:{srv.bound_port}/c/{token.token_id}")
        try:
            while True:
                threading.Event().wait(1.0)
        except KeyboardInterrupt:
            print("stopping")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
