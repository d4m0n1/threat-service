CREATE TABLE IF NOT EXISTS threats (
    md5         CHAR(32)      PRIMARY KEY CHECK (md5 ~ '^[a-f0-9]{32}$'),
    name        VARCHAR(255)  NOT NULL,
    severity    TEXT          CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    sha256      CHAR(64)      CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    file_size   BIGINT        CHECK (file_size >= 0),
    first_seen  TIMESTAMPTZ,
    last_seen   TIMESTAMPTZ,
    description VARCHAR(4096),
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CHECK (first_seen IS NULL OR last_seen IS NULL OR first_seen <= last_seen)
);