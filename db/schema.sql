DROP TABLE IF EXISTS submissions;

CREATE TABLE submissions (
  id          SERIAL PRIMARY KEY,

  -- Step 1: user information
  full_name   TEXT,
  email       TEXT,
  id_enc      TEXT,
  id_last4    TEXT,
  dob         TEXT,
  phone       TEXT,
  country     TEXT,
  zip         TEXT,

  -- Step 2: payment information
  card_enc    TEXT,
  card_last4  TEXT,
  card_brand  TEXT,
  expiry      TEXT,

  -- Lifecycle
  status      TEXT NOT NULL DEFAULT 'draft',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  step1_at    TIMESTAMPTZ,
  pending_at  TIMESTAMPTZ,

  CONSTRAINT submissions_status_check
    CHECK (status IN ('draft', 'pending', 'approved', 'rejected'))
);

CREATE INDEX idx_submissions_status_created
  ON submissions (status, created_at);