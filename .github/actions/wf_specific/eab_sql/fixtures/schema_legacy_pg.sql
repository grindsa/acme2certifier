CREATE TABLE IF NOT EXISTS account (
    id SERIAL PRIMARY KEY,
    name VARCHAR(127) NOT NULL,
    contact VARCHAR(127)
);

CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    account_id INT REFERENCES account (id),
    key_id VARCHAR(63) NOT NULL,
    profile JSONB,
    description VARCHAR(255),
    status SMALLINT NOT NULL
);
