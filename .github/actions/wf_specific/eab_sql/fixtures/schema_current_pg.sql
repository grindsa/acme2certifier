CREATE TABLE IF NOT EXISTS acme_account (
    id SERIAL PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    email VARCHAR(320)
);

CREATE TABLE IF NOT EXISTS acme_credential (
    id SERIAL PRIMARY KEY,
    account_id INT REFERENCES acme_account (id),
    key_id VARCHAR(63) NOT NULL,
    description VARCHAR(127),
    profile JSONB,
    enabled SMALLINT NOT NULL
);
