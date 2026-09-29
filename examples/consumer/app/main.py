"""Billing webhook verifier — HMAC-SHA256, secret from the environment."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


def verify_signature(secret: bytes, body: bytes, header: str) -> bool:
    if not header.startswith("sha256="):
        return False
    try:
        given = bytes.fromhex(header.removeprefix("sha256="))
    except ValueError:
        return False
    expected = hmac.new(secret, body, hashlib.sha256).digest()
    return hmac.compare_digest(expected, given)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/webhook":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length < 0 or length > 1_000_000:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        secret = os.environ.get("WEBHOOK_SECRET", "")
        sig = self.headers.get("X-Signature", "")
        if not secret or not verify_signature(secret.encode(), body, sig):
            self.send_error(401)
            return
        try:
            json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400)
            return
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
