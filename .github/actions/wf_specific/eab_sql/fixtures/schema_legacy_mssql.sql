IF OBJECT_ID('dbo.account', 'U') IS NULL
CREATE TABLE account (
    id INT IDENTITY(1,1) PRIMARY KEY,
    name NVARCHAR(127) NOT NULL,
    contact NVARCHAR(127)
);

IF OBJECT_ID('dbo.credentials', 'U') IS NULL
CREATE TABLE credentials (
    id INT IDENTITY(1,1) PRIMARY KEY,
    account_id INT NULL,
    key_id NVARCHAR(63) NOT NULL,
    profile NVARCHAR(MAX),
    description NVARCHAR(255),
    status TINYINT NOT NULL
);
