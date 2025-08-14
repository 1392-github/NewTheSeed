CREATE TABLE IF NOT EXISTS "doc_name" (
	"id"	INTEGER,
	"name"	TEXT,
	"history_seq"	INTEGER,
	"discuss_seq"	INTEGER,
	PRIMARY KEY("id" AUTOINCREMENT)
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
	"api_key"	TEXT,
	"api_key_enable"	INTEGER,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "discuss" (
	"doc_id"	INTEGER,
	"disc_id"	INTEGER,
	"name"	TEXT,
	"user"	INTEGER,
	"status"	INTEGER
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
CREATE TABLE IF NOT EXISTS "acl" (
	"doc_id"	INTEGER,
	"acltype"	TEXT,
	"index"	INTEGER,
	"condtype"	INTEGER,
	"value"	TEXT,
	"action"	TEXT,
	PRIMARY KEY("doc_id","acltype","index")
);
CREATE TABLE IF NOT EXISTS "nsacl" (
	"ns_id"	INTEGER,
	"acltype"	TEXT,
	"index"	INTEGER,
	"condtype"	INTEGER,
	"value"	TEXT,
	"action"	TEXT,
	PRIMARY KEY("ns_id","acltype","index")
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
	"readperm"	TEXT NOT NULL,
	"addperm"	TEXT NOT NULL,
	"deleteperm"	TEXT NOT NULL,
	"warn_msg"	TEXT,
	"style"	TEXT,
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
)