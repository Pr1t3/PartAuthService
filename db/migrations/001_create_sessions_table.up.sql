CREATE TABLE sessions (
    id VARCHAR(120) PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    refresh_token VARCHAR(500) NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);