"""Minimal Lumeus webhook receiver. Python 3.9+, standard library only.

    WEBHOOK_SECRET=whsec_... python3 webhook_receiver.py
    WEBHOOK_SECRET_FILE=webhook-secret.txt python3 webhook_receiver.py

The secret comes from WEBHOOK_SECRET, or from the file named by
WEBHOOK_SECRET_FILE, which is read on every request: you can start the receiver
before you create the subscription, and it answers 503 until the file exists.
During a signing-key rotation also set WEBHOOK_NEXT_SECRET. In your own
framework, import verify_webhook and WebhookError from this file and pass the
raw request bytes and the request headers.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET_FILE = os.environ.get("WEBHOOK_SECRET_FILE")
PORT = int(os.environ.get("PORT", "3000"))
MAX_BODY = 256 * 1024  # deliveries are at most 64 KiB
TOLERANCE_SECONDS = 300
SIGNATURE = re.compile(r"^t=([0-9]{1,12}),v1=([a-fA-F0-9]{64})$")


class WebhookError(Exception):
    """Raised with a short code that is safe to log."""


def _check(header, payload, secrets, now):
    """Return the signed timestamp if one secret signed payload, else None."""
    match = SIGNATURE.match(header or "")
    if not match or abs(now - int(match.group(1))) > TOLERANCE_SECONDS:
        return None
    timestamp, received = match.group(1), match.group(2).lower()
    for secret in secrets:
        expected = hmac.new(secret.encode(), timestamp.encode() + b"." + payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, received):
            return timestamp
    return None


def verify_webhook(raw_body, headers, secrets, now=None, require_context=True):
    """Verify a delivery. headers must be case-insensitive (http.server headers are)."""
    now = time.time() if now is None else now
    timestamp = _check(headers.get("X-Webhook-Signature"), raw_body, secrets, now) or _check(
        headers.get("X-Webhook-Next-Signature"), raw_body, secrets, now)
    if not timestamp:
        raise WebhookError("invalid_webhook_signature")
    encoded = headers.get("X-Webhook-Delivery-Context") or ""
    if not encoded:
        if require_context:
            raise WebhookError("missing_delivery_context")
        return {"timestamp": timestamp, "context": None}
    if len(encoded) > 16384 or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise WebhookError("invalid_delivery_context")
    context_bytes = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    context_timestamp = _check(headers.get("X-Webhook-Context-Signature"), context_bytes, secrets, now) or _check(
        headers.get("X-Webhook-Next-Context-Signature"), context_bytes, secrets, now)
    if context_timestamp != timestamp:
        raise WebhookError("invalid_context_signature")
    try:
        context = json.loads(context_bytes)
        event = json.loads(raw_body)
    except ValueError:
        raise WebhookError("context_body_mismatch")
    network = lambda value: "mainnet" if value == "pubnet" else value
    lane = context.get("lane")
    if (context.get("domain") != "lumeus-delivery-context-v1" or not context.get("generation")
            or not context.get("subscription_id") or context.get("event_id") != event.get("id")
            or network(context.get("network")) != network(event.get("network"))
            or context.get("body_sha256") != hashlib.sha256(raw_body).hexdigest()
            or lane not in ("live", "replay", "test")
            or (lane == "replay" and not context.get("replay_job_id"))
            or (lane == "test" and (event.get("kind") != "test" or headers.get("X-Webhook-Test") != "true"))):
        raise WebhookError("context_body_mismatch")
    return {"timestamp": timestamp, "context": context}


def current_secrets():
    secrets = [os.environ.get("WEBHOOK_SECRET"), os.environ.get("WEBHOOK_NEXT_SECRET")]
    if SECRET_FILE:
        try:
            with open(SECRET_FILE, encoding="utf-8") as f:
                secrets.append(f.read().strip())
        except OSError:
            pass  # not created yet
    return [s for s in secrets if s]


seen = set()  # demo only: in production use a database UNIQUE key on (network, event id)


class Handler(BaseHTTPRequestHandler):
    def _answer(self, status):
        self.send_response(status)
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0:
            return self._answer(400)
        if length > MAX_BODY:
            return self._answer(413)
        raw_body = self.rfile.read(length)
        secrets = current_secrets()
        if not secrets:
            print("no secret yet: waiting for", SECRET_FILE, flush=True)
            return self._answer(503)
        try:
            context = verify_webhook(raw_body, self.headers, secrets)["context"]
        except WebhookError as error:
            print("rejected:", error, flush=True)
            return self._answer(400)
        event = json.loads(raw_body)
        key = (context["network"], event["id"])
        if context["lane"] == "test":
            print("verified test delivery", event["id"], flush=True)
        elif key in seen:
            print("duplicate, already processed", event["id"], flush=True)
        else:
            seen.add(key)  # store the event and enqueue your work here, before you answer
            print(f"verified {context['lane']} {event.get('kind')} {event.get('type')} {event['id']} ledger {event.get('ledger')}", flush=True)
        self._answer(204)  # answer fast with an empty body

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    if not os.environ.get("WEBHOOK_SECRET") and not SECRET_FILE:
        raise SystemExit("set WEBHOOK_SECRET or WEBHOOK_SECRET_FILE")
    print(f"listening on http://localhost:{PORT}", flush=True)
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()
