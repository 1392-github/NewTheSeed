CREATE TABLE IF NOT EXISTS "doc_name" (
	"id"	INTEGER,
	"name"	TEXT,
	"history_seq"	INTEGER,
	"discuss_seq"	INTEGER,
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
	"ban"	INTEGER,
	"reason"	TEXT,
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
CREATE TABLE IF NOT EXISTS "acl" (
	"doc_id"	INTEGER,
	"type"	TEXT,
	"index"	INTEGER,
	"value"	TEXT,
	"yes"	TEXT,
	"no"	TEXT,
	PRIMARY KEY("doc_id","type","index")
);
CREATE TABLE IF NOT EXISTS "api_policy" (
	"name"	TEXT,
	"value"	INTEGER,
	PRIMARY KEY("name")
);
CREATE TABLE IF NOT EXISTS "api_key_perm" (
	"key"	TEXT,
	"name"	TEXT,
	"value"	INTEGER,
	PRIMARY KEY("key","name")
);
CREATE TABLE IF NOT EXISTS "file" (
	"id"	INTEGER,
	"type"	TEXT,
	"data"	BLOB,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "namespace" (
	"id"	INTEGER,
	"name"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "nsacl" (
	"doc_id"	INTEGER,
	"type"	TEXT,
	"index"	INTEGER,
	"value"	TEXT,
	"yes"	TEXT,
	"no"	TEXT,
	PRIMARY KEY("doc_id","type","index")
);
CREATE TABLE IF NOT EXISTS "permacl" (
	"doc_id"	INTEGER,
	"type"	TEXT,
	"index"	INTEGER,
	"value"	TEXT,
	"yes"	TEXT,
	"no"	TEXT,
	PRIMARY KEY("doc_id","type","index")
);