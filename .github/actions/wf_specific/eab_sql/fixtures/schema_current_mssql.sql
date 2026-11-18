IF OBJECT_ID('dbo.acme_account', 'U') IS NULL
CREATE TABLE acme_account (
    id INT IDENTITY(1,1) PRIMARY KEY,
    name NVARCHAR(256) NOT NULL,
    email NVARCHAR(320)
);

IF OBJECT_ID('dbo.acme_credential', 'U') IS NULL
CREATE TABLE acme_credential (
    id INT IDENTITY(1,1) PRIMARY KEY,
    account_id INT NULL,
    key_id NVARCHAR(63) NOT NULL,
    description NVARCHAR(127),
    profile NVARCHAR(MAX),
    enabled TINYINT NOT NULL
);
