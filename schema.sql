-- PostgreSQL schema for the catchall mail stack
CREATE TABLE IF NOT EXISTS emails (
    id              SERIAL PRIMARY KEY,
    message_id      TEXT,
    direction       TEXT NOT NULL DEFAULT 'inbound',  -- inbound | outbound
    envelope_from   TEXT DEFAULT '',
    envelope_to     TEXT DEFAULT '',
    from_header     TEXT NOT NULL DEFAULT '',
    to_header       TEXT NOT NULL DEFAULT '',
    cc_header       TEXT DEFAULT '',
    reply_to_header TEXT DEFAULT '',
    subject         TEXT NOT NULL DEFAULT '(no subject)',
    body_text       TEXT DEFAULT '',
    body_html       TEXT DEFAULT '',
    raw_source      TEXT NOT NULL DEFAULT '',
    has_attachments BOOLEAN DEFAULT FALSE,
    is_read         BOOLEAN DEFAULT FALSE,
    is_starred      BOOLEAN DEFAULT FALSE,
    forwarded       BOOLEAN DEFAULT FALSE,
    forward_error   TEXT,
    in_reply_to     TEXT DEFAULT '',
    references_hdr  TEXT DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_emails_created    ON emails(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_emails_direction  ON emails(direction);
CREATE INDEX IF NOT EXISTS idx_emails_is_read    ON emails(is_read) WHERE NOT is_read;
CREATE INDEX IF NOT EXISTS idx_emails_message_id ON emails(message_id);

CREATE TABLE IF NOT EXISTS attachments (
    id           SERIAL PRIMARY KEY,
    email_id     INT REFERENCES emails(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes   INT  NOT NULL,
    content      BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attachments_email ON attachments(email_id);
