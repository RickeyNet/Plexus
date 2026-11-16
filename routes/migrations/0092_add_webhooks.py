"""
Migration 0092: outbound event webhooks.

Adds:

  - webhooks - one row per subscription: the target (``url``,
    ``http_method``, ``content_type``), which object-change events it takes
    (``object_types_json`` and ``actions_json``, JSON lists; ``filters_json``,
    a JSON object of field -> allowed values matched against the object),
    custom headers (``headers_enc``: the JSON header map, encrypted, since a
    header often carries a token), an optional Jinja2 ``body_template``, the
    HMAC-SHA256 signing secret (``secret_enc``, encrypted), TLS options
    (``verify_tls``, ``ca_bundle`` PEM), and the delivery limits
    (``timeout_seconds``, ``max_retries``, ``concurrency``).
  - webhook_deliveries - one row per delivery attempt: the delivery id
    (shared by every attempt and redelivery of one event), the event, the
    attempt number, the outcome (``status``: success, retrying, failed,
    blocked), the HTTP status code, latency, the request body sent (for
    redelivery), a truncated response body and the error. Purged after the
    webhook delivery retention (see DATA_RETENTION.md).

Timestamps are written by Plexus as UTC ``YYYY-MM-DD HH:MM:SS`` text.
Every step is idempotent.
"""

from __future__ import annotations

VERSION = 92
DESCRIPTION = "Add outbound event webhooks and their delivery log"


async def up(db) -> None:
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS webhooks (
            id                SERIAL PRIMARY KEY,
            name              TEXT    NOT NULL UNIQUE,
            enabled           INTEGER NOT NULL DEFAULT 1,
            url               TEXT    NOT NULL,
            http_method       TEXT    NOT NULL DEFAULT 'POST',
            content_type      TEXT    NOT NULL DEFAULT 'application/json',
            object_types_json TEXT    NOT NULL DEFAULT '[]',
            actions_json      TEXT    NOT NULL DEFAULT '["create","update","delete"]',
            filters_json      TEXT    NOT NULL DEFAULT '{}',
            headers_enc       TEXT    NOT NULL DEFAULT '',
            body_template     TEXT    NOT NULL DEFAULT '',
            secret_enc        TEXT    NOT NULL DEFAULT '',
            verify_tls        INTEGER NOT NULL DEFAULT 1,
            ca_bundle         TEXT    NOT NULL DEFAULT '',
            timeout_seconds   REAL    NOT NULL DEFAULT 10,
            max_retries       INTEGER NOT NULL DEFAULT 3,
            concurrency       INTEGER NOT NULL DEFAULT 2,
            created_by        TEXT    NOT NULL DEFAULT '',
            created_at        TEXT    NOT NULL DEFAULT '',
            updated_at        TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id            SERIAL PRIMARY KEY,
            webhook_id    INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
            delivery_id   TEXT    NOT NULL,
            event         TEXT    NOT NULL DEFAULT '',
            object_type   TEXT    NOT NULL DEFAULT '',
            object_id     TEXT    NOT NULL DEFAULT '',
            action        TEXT    NOT NULL DEFAULT '',
            attempt       INTEGER NOT NULL DEFAULT 1,
            status        TEXT    NOT NULL DEFAULT '',
            status_code   INTEGER,
            latency_ms    REAL,
            request_body  TEXT    NOT NULL DEFAULT '',
            response_body TEXT    NOT NULL DEFAULT '',
            error         TEXT    NOT NULL DEFAULT '',
            created_at    TEXT    NOT NULL DEFAULT ''
        )
        """
    )
    await db.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries (webhook_id, id)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created ON webhook_deliveries (created_at)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_delivery ON webhook_deliveries (delivery_id)")
