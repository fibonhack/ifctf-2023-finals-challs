CREATE TABLE IF NOT EXISTS user (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS property (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    FOREIGN KEY (user_id) REFERENCES user (id)
);

CREATE TABLE IF NOT EXISTS post (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    content TEXT,
    FOREIGN KEY (user_id) REFERENCES user (id)
);

INSERT INTO user(id, username, password) VALUES
    ('a7fe35e5-b4c4-49eb-8796-1fb9cd0da828', 'admin', '$2b$10$l9Z54mfEbFwoy/VRDWcrduqz05x0lumR6XWwh48lIEJkRiwHXRRmO');
