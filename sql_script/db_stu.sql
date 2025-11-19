CREATE TABLE IF NOT EXISTS "doc_name" (
	"id"	INTEGER,
	"namespace"	INTEGER,
	"name"	TEXT,
	"history_seq"	INTEGER,
	PRIMARY KEY("ID" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "history" (
	"doc_id"	INTEGER,
	"rev"	INTEGER,
	"type"	INTEGER,
	"content"	TEXT,
	"content2"	TEXT,
	"content3"	TEXT,
	"author"	INTEGER,
	"edit_comment"	TEXT,
	"datetime"	INTEGER,
	"length"	INTEGER,
	"hide"	INTEGER NOT NULL DEFAULT 0,
	"hidecomm"	INTEGER NOT NULL DEFAULT -1,
	"troll"	INTEGER NOT NULL DEFAULT -1
);
CREATE TABLE IF NOT EXISTS "config" (
	"name"	TEXT,
	"value"	TEXT,
	PRIMARY KEY("name")
);
CREATE TABLE IF NOT EXISTS "user" (
	"id"	INTEGER,
	"name"	TEXT UNIQUE,
	"password"	TEXT,
	"isip"	INTEGER NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "discuss" (
	"slug"	INTEGER,
	"doc_id"	INTEGER NOT NULL,
	"topic"	TEXT NOT NULL DEFAULT '',
	"last"	INTEGER NOT NULL DEFAULT 0,
	"status"	TEXT NOT NULL DEFAULT 'normal',
	"fix_comment"	INTEGER,
	"seq"	INTEGER NOT NULL DEFAULT 1,
	PRIMARY KEY("slug" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "api_policy" (
	"name"	TEXT,
	"value"	INTEGER,
	PRIMARY KEY("name")
);
CREATE TABLE IF NOT EXISTS "api_key_perm" (
	"user"	INTEGER,
	"name"	TEXT,
	"value"	INTEGER,
	PRIMARY KEY("user","name")
);
CREATE TABLE IF NOT EXISTS "namespace" (
	"id"	INTEGER,
	"name"	TEXT,
	PRIMARY KEY("id")
);
CREATE TABLE IF NOT EXISTS "acl" (
	"doc_id"	INTEGER,
	"acltype"	TEXT,
	"idx"	INTEGER,
	"condtype"	TEXT NOT NULL,
	"value"	TEXT,
	"value2"	INTEGER,
	"no"	INTEGER NOT NULL,
	"action"	TEXT NOT NULL,
	"otherns"	INTEGER,
	"expire"	INTEGER
);
CREATE TABLE IF NOT EXISTS "nsacl" (
	"ns_id"	INTEGER,
	"acltype"	TEXT,
	"idx"	INTEGER,
	"condtype"	TEXT NOT NULL,
	"value"	TEXT,
	"value2"	INTEGER,
	"no"	INTEGER NOT NULL,
	"action"	TEXT NOT NULL,
    "otherns"	INTEGER,
	"expire"	INTEGER
);
CREATE TABLE IF NOT EXISTS "extension" (
	"name"	TEXT
);
CREATE TABLE IF NOT EXISTS "api_keys" (
	"user_id"	INTEGER,
	"key"	TEXT,
	"enable"	INTEGER,
	PRIMARY KEY("user_id")
);
CREATE TABLE IF NOT EXISTS "aclgroup_log" (
	"id"	INTEGER,
	"gid"	INTEGER NOT NULL,
	"ip"	TEXT,
	"user"	INTEGER,
	"note"	TEXT,
	"start"	INTEGER NOT NULL,
	"end"	INTEGER,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "aclgroup" (
	"id"	INTEGER,
	"name"	TEXT,
	"deleted"	INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "block_log" (
	"type"	INTEGER NOT NULL,
	"operator"	INTEGER NOT NULL,
	"target_ip"	TEXT,
	"target"	INTEGER,
	"id"	INTEGER,
	"gid"	INTEGER,
	"date"	INTEGER NOT NULL,
	"duration"	INTEGER,
	"grant_perm"	TEXT,
	"note"	TEXT
);
CREATE TABLE IF NOT EXISTS "perm" (
	"user"	INTEGER NOT NULL,
	"perm"	TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS "data" (
	"id"	INTEGER,
	"value"	TEXT,
	PRIMARY KEY("id")
);
CREATE TABLE IF NOT EXISTS "thread_comment" (
	"slug"	INTEGER NOT NULL,
	"no"	INTEGER NOT NULL,
	"type"	INTEGER NOT NULL DEFAULT 0,
	"text"	TEXT,
	"text2"	TEXT,
	"author"	INTEGER NOT NULL,
	"time"	INTEGER NOT NULL,
	"blind"	INTEGER NOT NULL DEFAULT 0,
	"blind_operator"	INTEGER,
	"admin"	INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS "login_history" (
	"user"	INTEGER NOT NULL,
	"date"	INTEGER NOT NULL,
	"ip"	TEXT NOT NULL,
	"ua"	TEXT NOT NULL,
	"uach"	TEXT
);
CREATE TABLE IF NOT EXISTS "aclgroup_config" (
	"gid"	INTEGER,
	"name"	TEXT,
	"value"	TEXT NOT NULL,
	PRIMARY KEY("gid","name")
);