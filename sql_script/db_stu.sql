CREATE TABLE IF NOT EXISTS "doc_name" (
	"id"	INTEGER,
	"name"	TEXT,
	"history_seq"	INTEGER,
	"discuss_seq"	TEXT,
	PRIMARY KEY("ID" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "history" (
	"doc_id"	INTEGER,
	"rev"	INTEGER,
	"type"	INTEGER,
	"content"	TEXT,
	"author"	INTEGER,
	"edit_comment"	TEXT,
	"datetime"	TEXT,
	"length"	INTEGER
);
CREATE TABLE IF NOT EXISTS "config" (
	"name"	TEXT,
	"value"	TEXT,
	PRIMARY KEY("name")
);
CREATE TABLE IF NOT EXISTS "user" (
	"id"	INTEGER,
	"name"	TEXT,
	"password"	TEXT,
	"isip"	INTEGER,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "discuss" (
	"doc_id"	INTEGER,
	"disc_id"	INTEGER,
	"name"	TEXT,
	"user"	INTEGER,
	"status"	INTEGER
);
CREATE TABLE IF NOT EXISTS "api_key_requests" (
	"id"	INTEGER,
	"user_id"	INTEGER,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "api_keys" (
	"user_id"	INTEGER,
	"key"	TEXT,
	PRIMARY KEY("user_id")
);