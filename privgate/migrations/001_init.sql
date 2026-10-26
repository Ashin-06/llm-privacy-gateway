-- Conversations own their placeholders; entries expire with the conversation.
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    owner TEXT,
    created_at BIGINT NOT NULL
);
CREATE INDEX conversations_created ON conversations (created_at);

-- lookup = HMAC of (conversation, type, normalised value): finds a repeated value
-- without storing it. sealed = base64(nonce + AES-256-GCM ciphertext).
CREATE TABLE vault_entries (
    conversation_id TEXT NOT NULL,
    placeholder TEXT NOT NULL,
    kind TEXT NOT NULL,
    lookup TEXT NOT NULL,
    sealed TEXT NOT NULL,
    PRIMARY KEY (conversation_id, placeholder),
    UNIQUE (conversation_id, lookup)
);

-- Hash-chained audit entries (JSON). seq is the chain position; the key stops two
-- writers from both appending after the same entry.
CREATE TABLE audit_log (
    seq BIGINT PRIMARY KEY,
    entry TEXT NOT NULL
);
