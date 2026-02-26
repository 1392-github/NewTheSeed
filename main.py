import secrets
import mimetypes
import hashlib
import sys
import datetime
import types
import os
import shutil
import subprocess
import cssutils
import json
import traceback
import stat
import base64
import importlib
from typing import cast

from flask import Flask, request, redirect, session, send_file, send_from_directory, abort, Response, url_for
from flask import g as _g
from jinja2 import ChoiceLoader, FileSystemLoader
from git import Repo, InvalidGitRepositoryError
from markupsafe import escape, Markup
import dotenv
import requests
import werkzeug.exceptions

import data
import exceptions
import hooks
import tool
from render import render_set

if sys.version_info < (3, 10):
    if input("경고! NewTheSeed는 Python 3.10 미만의 Python 버전은 지원하지 않으며, 이로 인해 발생하는 버그(보안취약점 포함)는 수정되지 않습니다. 계속하려면 y를 입력해주세요. -> ") != "y":
        sys.exit()

os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.environ["GIT_TERMINAL_PROMPT"]="0"

for i in os.scandir("extensions"):
    if i.is_dir():
        try:
            with open(os.path.join(i.path, "info.json"), "r", encoding="utf-8") as f:
                j = json.load(f)
        except FileNotFoundError:
            print(f'"{i.name}" extension does not have info.json')
            continue
        except json.JSONDecodeError as e:
            print(f'"{i.name}" extension\'s info.json is invalid JSON: {e}')
            continue
        id = j["id"]
        if id in data.extension_info:
            print(f"The following extension ID is duplicated: {id}")
            sys.exit()
        if id != i.name:
            shutil.move(i.path, os.path.join("extensions", id))
        data.extension_info[id] = j
        data.all_extensions.append(id)
if not os.path.exists("extensions/list.txt"):
    shutil.copy("extensions/list.example.txt", "extensions/list.txt")
with open("extensions/list.txt", encoding="utf-8") as f:
    for i in f:
        i = i.strip()
        if not i or i[0] == "#":
            continue
        if i not in data.all_extensions:
            print(f"{i} extension doesn't exists")
            continue
        try:
            ext = importlib.import_module(f"extensions.{i}.main")
        except ModuleNotFoundError:
            print(f"{i} extension hasn't main.py")
            continue
        data.extension_module[i] = ext
        data.extensions.append(i)
for i in os.scandir("skins"):
    if i.is_dir():
        try:
            with open(os.path.join(i.path, "info.json"), "r", encoding="utf-8") as f:
                j = json.load(f)
        except FileNotFoundError:
            print(f'"{i.name}" skin does not have info.json')
            continue
        except json.JSONDecodeError as e:
            print(f'"{i.name}" Skin\'s info.json is invalid JSON: {e}')
            continue
        id = j["id"]
        if id in data.skin_info:
            print(f"The following skin ID is duplicated: {id}")
            sys.exit()
        if id != i.name:
            shutil.move(i.path, os.path.join("skins", id))
        if "version" not in j and "version_name" in j:
            print(f"[WARNING] skin {id}: The version_name in the skin info.json has been replaced with version, and version_name will be discontinued on March 1, 2026.")
            j["version"] = j["version_name"]
        data.skin_info[id] = j
        data.skins.append(id)
hooks.Start1()
try:
    repo = Repo(".", search_parent_directories=False)
except InvalidGitRepositoryError:
    repo = None
if repo is None:
    commit_id = "0000000"
else:
    commit_id = repo.commit().hexsha[:7]
    repo.close()
for i in data.skins:
    try:
        srepo = Repo(os.path.join("skins", i), search_parent_directories=False)
        data.skin_git.add(i)
        data.skin_commit[i] = srepo.commit().hexsha[:7]
        srepo.close()
    except InvalidGitRepositoryError:
        data.skin_commit[i] = "0000000"
for i in data.all_extensions:
    try:
        erepo = Repo(os.path.join("extensions", i), search_parent_directories=False)
        data.extension_git.add(i)
        data.extension_commit[i] = erepo.commit().hexsha[:7]
        erepo.close()
    except InvalidGitRepositoryError:
        data.extension_commit[i] = "0000000"
if not os.path.exists(".env"):
    shutil.copy(".env.example", ".env")
dotenv.load_dotenv()
app = Flask(__name__)
g = cast(tool.MyGlobals, _g)
with app.app_context():
    g.db = tool.getdb()
    tool.run_sqlscript("db_stu.sql") # DB 구조 만들기
    hooks.Start2(app)
    with g.db.cursor() as c:
        for k in data.default_config:
            if c.execute("select exists (select 1 from config where name = ?)", (k,)).fetchone()[0] == 0:
                c.execute('insert into config values(?, ?)', (k, data.default_config[k]() if isinstance(data.default_config[k], types.FunctionType) else data.default_config[k]))
        for k in data.default_string_config:
            if c.execute("select exists (select 1 from string_config where name = ?)", (k,)).fetchone()[0] == 0:
                c.execute('insert into string_config values(?, ?)', (k, data.default_string_config[k]() if isinstance(data.default_string_config[k], types.FunctionType) else data.default_string_config[k]))
        print(f"NewTheSeed [Version {tool.version_str(data.version)}]")
        print("(c) 1392-github, 2023-2025, MIT License")
        db_version = (int(tool.get_config("version")), int(tool.get_config("version2", "0")))
        print(f"DB Version : {tool.version_str(db_version)}")
        if db_version > data.version:
            print("경고 : 상위 버전 NewTheSeed의 DB입니다")
            print("DB 손상 위험이 있을 수도 있습니다")
            if input("그래도 계속 진행하려면 Y를 입력해주세요 -> ") != "Y":
                sys.exit(0)

        # DB 변환 코드
        if db_version < (6, 0):
            # discuss_seq 컬럼 추가
            c.execute("alter table doc_name add discuss_seq INTEGER")
        if db_version < (8, 0):
            # discuss_seq 컬럼의 데이터 타입 오류 수정
            c.executescript('''alter table doc_name drop column discuss_seq;
                            alter table doc_name add column discuss_seq INTEGER;''')
            # config에 get_api_key 추가
            c.execute("insert into config values('get_api_key', 'disabled')")
        if db_version < (10, 0):
            # ban, reason 컬럼 추가
            c.executescript('''alter table user add ban INTEGER;
        alter table user add reason TEXT;
        update user set ban=0;''')
        if db_version < (16, 0):
            # ACL 테이블 다 갈아엎음
            c.execute('drop table acl')
            c.execute('drop table nsacl')
            c.execute('drop table aclgroupuser')
            c.execute("INSERT OR IGNORE INTO api_keys SELECT id, NULL, 0 FROM user WHERE isip = 0") # API 키 시스템 바뀜
            # API Key 테이블 재생성
            c.execute("DROP TABLE api_key_perm")
            c.execute("DROP TABLE api_keys")
            tool.run_sqlscript('db_stu.sql')
            c.executemany('''insert into api_key_perm
        select ?, name, case value
            when 0 then 1
            when 1 then 1
            when 2 then 0
            end
        from api_policy''', c.execute("SELECT id FROM user WHERE isip = 0").fetchall())
            c.execute("INSERT INTO api_keys SELECT id, NULL, 0 FROM user WHERE isip = 0")
        if db_version < (16, 0) or tool.init:
            c.execute("INSERT INTO aclgroup (name) VALUES('차단된 사용자')")
            l = c.lastrowid
            c.executemany("INSERT INTO aclgroup_config (gid, name, value) VALUES(?,?,?)",
                          ((l, x[0], x[1]) for x in data.default_aclgroup_config))

        if db_version < (17, 0):
            # owner 설정 삭제 및 권한 시스템으로 대체
            c.execute("DELETE FROM config WHERE name = 'owner'")
        if db_version < (19, 0):
            # acl, nsacl 테이블 재생성
            c.execute("DROP TABLE acl")
            c.execute("DROP TABLE nsacl")
            c.execute('''CREATE TABLE "acl" (
            "doc_id"	INTEGER,
            "acltype"	TEXT,
            "idx"	INTEGER,
            "condtype"	TEXT NOT NULL,
            "value"	TEXT,
            "value2"	INTEGER,
            "no"	INTEGER NOT NULL,
            "action"	TEXT NOT NULL,
            "expire"	INTEGER
        )''')
            c.execute('''CREATE TABLE "nsacl" (
            "ns_id"	INTEGER,
            "acltype"	TEXT,
            "idx"	INTEGER,
            "condtype"	TEXT NOT NULL,
            "value"	TEXT,
            "value2"	INTEGER,
            "no"	INTEGER NOT NULL,
            "action"	TEXT NOT NULL,
            "expire"	INTEGER
        )''')
            # doc_name에 namespace 추가 및 discuss_seq 제거
            c.execute("ALTER TABLE doc_name RENAME TO doc_name2")
            c.execute('''CREATE TABLE "doc_name" (
            "id"	INTEGER,
            "namespace"	INTEGER NOT NULL,
            "name"	TEXT NOT NULL,
            "history_seq"	INTEGER,
            PRIMARY KEY("ID" AUTOINCREMENT)
        )''')
            c.execute("INSERT INTO doc_name SELECT id, 1, name, history_seq FROM doc_name2")
            c.execute("DROP TABLE doc_name2")
            # history 테이블에 content2, content3 hide, hidecomm, troll 컬럼 추가 및 datetime을 UNIX 시간으로 변경
            history = c.execute("SELECT * FROM history").fetchall()
            c.execute("DROP TABLE history")
            c.execute('''CREATE TABLE "history" (
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
        );''')
            c.executemany("INSERT INTO history VALUES(?,?,?,?,NULL,NULL,?,?,?,?,0,-1,-1)",
                        ((i[0], i[1], i[2], i[3], i[4], i[5], int(datetime.datetime.strptime(i[6][:-7], "%Y-%m-%d %H:%M:%S").timestamp()), i[7]) for i in history))
            # data 테이블 추가
            c.execute("""INSERT INTO data (id, value)
        SELECT A.doc_id, A.content FROM history A
        JOIN (SELECT doc_id, max(rev) mr FROM history GROUP BY doc_id) B
        ON (A.doc_id = B.doc_id AND A.rev = B.mr)
        ORDER BY A.doc_id""")
            c.execute("ALTER TABLE aclgroup RENAME TO aclgroup2")
            c.execute("""CREATE TABLE "aclgroup" (
            "id"	INTEGER,
            "name"	TEXT,
            "deleted"	INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY("id" AUTOINCREMENT)
        )""")
            c.execute("INSERT INTO aclgroup (id, name, deleted) SELECT id, name, 0 FROM aclgroup2")
            c.execute("DROP TABLE aclgroup2")
            c.execute("ALTER TABLE user RENAME TO user2")
            c.execute("""CREATE TABLE "user" (
            "id"	INTEGER,
            "name"	TEXT UNIQUE,
            "password"	TEXT,
            "isip"	INTEGER NOT NULL,
            PRIMARY KEY("id" AUTOINCREMENT)
        );""")
            c.execute("INSERT INTO user (id, name, password, isip) SELECT id, name, password, isip FROM user2")
            c.execute("DROP TABLE user2")
            c.execute("DELETE FROM config WHERE name IN ('debug', 'host', 'port')")
        if db_version < (19, 0) or tool.init:
            # 기본 이름공간 및 ACL 생성
            tool.run_sqlscript("default_namespace2.sql")
        if db_version < (22, 0):
            c.execute("DROP TABLE discuss")
            c.execute("""CREATE TABLE "discuss" (
            "slug"	INTEGER,
            "doc_id"	INTEGER NOT NULL,
            "topic"	TEXT NOT NULL DEFAULT '',
            "last"	INTEGER NOT NULL DEFAULT 0,
            "status"	TEXT NOT NULL DEFAULT 'normal',
            "fix_comment"	INTEGER,
	        "seq"	INTEGER NOT NULL DEFAULT 2,
            PRIMARY KEY("slug" AUTOINCREMENT)
        )""")
            c.execute("DELETE FROM config WHERE name = 'wiki_title'")
        if db_version < (27, 0):
            # secret key 저장위치 변경
            dotenv.set_key(".env", "SECRET_KEY", tool.get_config("secret_key"))
            c.execute("DELETE FROM config WHERE name = 'secret_key'")
            # admin 컬럼 추가
            c.execute("ALTER TABLE thread_comment ADD COLUMN admin INTEGER NOT NULL DEFAULT 0")
            c.execute("UPDATE thread_comment SET admin = (SELECT EXISTS (SELECT 1 FROM perm WHERE user = author AND perm IN ('admin', 'developer')))")
        if db_version < (31, 0):
            # gotootherns 추가
            c.execute("""CREATE TABLE "acl_new" (
            "doc_id"	INTEGER,
            "acltype"	TEXT,
            "idx"	INTEGER,
            "condtype"	TEXT NOT NULL,
            "value"	TEXT,
            "value2"	INTEGER,
            "no"	INTEGER,
            "action"	TEXT NOT NULL,
            "otherns"	INTEGER,
            "expire"	INTEGER
        )""")
            c.execute("INSERT INTO acl_new (doc_id, acltype, idx, condtype, value, value2, no, action, expire) SELECT doc_id, acltype, idx, condtype, value, value2, no, action, expire FROM acl")
            c.execute("DROP TABLE acl")
            c.execute("ALTER TABLE acl_new RENAME TO acl")
            c.execute("""CREATE TABLE "nsacl_new" (
            "ns_id"	INTEGER,
            "acltype"	TEXT,
            "idx"	INTEGER,
            "condtype"	TEXT NOT NULL,
            "value"	TEXT,
            "value2"	INTEGER,
            "no"	INTEGER,
            "action"	TEXT NOT NULL,
            "otherns"	INTEGER,
            "expire"	INTEGER
        )""")
            c.execute("INSERT INTO nsacl_new (ns_id, acltype, idx, condtype, value, value2, no, action, expire) SELECT ns_id, acltype, idx, condtype, value, value2, no, action, expire FROM nsacl")
            c.execute("DROP TABLE nsacl")
            c.execute("ALTER TABLE nsacl_new RENAME TO nsacl")
            # seq 기본값 2에서 1로 변경
            c.execute("""CREATE TABLE "discuss_new" (
            "slug"	INTEGER,
            "doc_id"	INTEGER NOT NULL,
            "topic"	TEXT NOT NULL DEFAULT '',
            "last"	INTEGER NOT NULL DEFAULT 0,
            "status"	TEXT NOT NULL DEFAULT 'normal',
            "fix_comment"	INTEGER,
            "seq"	INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY("slug" AUTOINCREMENT)
        );""")
            c.execute("INSERT INTO discuss_new SELECT * FROM discuss")
            c.execute("DROP TABLE discuss")
            c.execute("ALTER TABLE discuss_new RENAME TO discuss")
        if db_version < (34, 0):
            # file 테이블 삭제
            c.execute("DROP TABLE file")
        if db_version < (35, 0):
            c.execute("UPDATE config SET name = 'ignore_developer_perm' WHERE name = 'ignore_developer_perm'")
        if db_version < (39, 0):
            c.execute("DELETE FROM perm WHERE perm in ('database', 'sysman')")
        if db_version < (41, 0):
            c.execute("""CREATE TABLE "thread_comment_new" (
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
""")
            c.execute("INSERT INTO thread_comment_new (slug, no, type, text, text2, author, time, admin) SELECT slug, no, type, text, text2, author, time, admin FROM thread_comment")
            c.execute("DROP TABLE thread_comment")
            c.execute("ALTER TABLE thread_comment_new RENAME TO thread_comment")
        if db_version < (45, 0):
            for i in c.execute("SELECT id FROM aclgroup WHERE deleted = 0").fetchall():
                i = i[0]
                if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_config WHERE gid = ?)", (i,)).fetchone()[0] == 0:
                    c.executemany("INSERT INTO aclgroup_config (gid, name, value) VALUES(?,?,?)", ((i, x[0], x[1]) for x in data.default_aclgroup_config))
        if db_version < (48, 2):
            c.execute("UPDATE aclgroup_config SET name = 'withdraw_period' WHERE name = 'withdraw_period_hours'")
            c.execute("UPDATE aclgroup_config SET value = CAST(CAST(value AS INTEGER) * 3600 AS TEXT) WHERE name = 'withdraw_period' AND value != '-1'")
        if db_version < (49, 0):
            userns = int(tool.get_config("user_namespace"))
            time = tool.get_utime()
            for id, name in c.execute("SELECT id, name FROM user WHERE isip = 0").fetchall():
                docid = tool.get_docid(userns, name)
                if docid == -1:
                    tool.set_user_config(id, "signup", time)
                else:
                    f = c.execute("SELECT datetime FROM history WHERE doc_id = ? AND rev = 1", (docid,)).fetchone()
                    if f is None: tool.set_user_config(id, "signup", time)
                    else: tool.set_user_config(id, "signup", f[0])
        if db_version < (50, 0):
            for id in c.execute("SELECT id FROM user WHERE isip = 0").fetchall():
                id = id[0]
                tool.set_user_config(id, "change_name", tool.get_user_config(id, "signup"))
        if db_version < (54, 3):
            c.execute("UPDATE string_config SET value = (SELECT value FROM config WHERE name = 'document_license') WHERE name = 'document_license'")
            c.execute("UPDATE string_config SET value = (SELECT value FROM config WHERE name = 'document_license_checkbox') WHERE name = 'document_license_checkbox'")
            c.execute("UPDATE string_config SET value = (SELECT value FROM config WHERE name = 'withdraw_pledgeinput') WHERE name = 'withdraw_pledgeinput'")
            c.execute("DELETE FROM config WHERE name IN ('document_license', 'document_license_checkbox', 'withdraw_pledgeinput')")
        if db_version < (54, 4):
            # 폐지된 테이블 삭제
            c.execute("DROP TABLE api_policy")
            c.execute("DROP TABLE api_key_perm")
            c.execute("DROP TABLE api_keys")
        if db_version < (59, 0):
            # 차단내역 버그 수정
            c.execute("DELETE FROM block_log WHERE type = 4 AND target = -1")
        if db_version < (68, 7):
            c.execute("UPDATE acl SET expire = 32503647600 WHERE expire > 32503647600")
            c.execute("UPDATE aclgroup_log SET end = 32503647600 WHERE end > 32503647600")
        if db_version < (76, 0):
            c.execute("DELETE FROM config WHERE name IN ('get_api_key', 'api_key_length', 'base_url', 'grantable_permission')")
        if db_version < (81, 1):
            c.execute("UPDATE user SET password = '$4$$' || password")
        c.execute("""update config
        set value = ?
        where name = 'version'""", (str(data.version[0]),)) # 변환 후 버전 재설정
        c.execute("""update config
        set value = ?
        where name = 'version2'""", (str(data.version[1]),)) # 변환 후 버전 재설정
        for skin in data.skin_info:
            info = data.skin_info[skin]
            for cf in info["skin_config"]:
                key = cf["key"]
                k = f"skin.{skin}.{key}"
                if not tool.has_config(k):
                    c.execute("INSERT INTO config (name, value) VALUES(?,?)", (k, cf["default"]))
    tool.reload_config(app)
    g.db.close()
    hooks.Start3()
if not os.getenv("SECRET_KEY"):
    key = secrets.token_hex(32)
    dotenv.set_key(".env", "SECRET_KEY", secrets.token_hex(32))
    app.secret_key = key
else:
    app.secret_key = os.getenv("SECRET_KEY")
app.json.ensure_ascii = False

@app.errorhandler(403)
def errorhandler_403(e):
    return tool.error("권한이 부족합니다.", 403)
@app.errorhandler(404)
def errorhandler_404(e):
    return tool.rt(f"{tool.get_skin()}/404.html"), 404
@app.errorhandler(500)
def errorhandler_500(e):
    if os.getenv("DISABLE_FULL_ERROR", "0") == "0" and tool.has_perm("developer"):
        return traceback.format_exc(), 500, {"Content-Type": "text/plain"}
    else:
        return werkzeug.exceptions.InternalServerError.get_response()
@app.errorhandler(exceptions.ACLDeniedError)
def errorhandler_acl(e):
    return tool.error(str(e), 403)
@app.errorhandler(exceptions.DocumentContentEqualError)
def errorhandler_equal(e):
    return tool.error("문서 내용이 같습니다.", 409)
@app.before_request
def before_request():
    g.db = tool.getdb()
    g.username_cache = {}
@app.after_request
def after_request(res):
    if tool.get_config("keep_login_history") != "0":
        res.headers["Accept-CH"] = tool.get_config("accept_ch")
        res.headers["Accept-CH-Lifetime"] = tool.get_config("accept_ch_lifetime")
        res.headers["Permissions-Policy"] = "ch-ua=(self)"
    return res
@app.teardown_request
def teardown_request(exc):
    g.db.close()
def render_username(user, bold = 0):
    name = tool.id_to_user_name(user)
    if bold == 0:
        b = False if name is None else not tool.isip(user)
    elif bold == 1:
        b = True
    elif bold == 2:
        b = False
    if user in g.username_cache:
        if b:
            return Markup(f"<b>{g.username_cache[user]}</b>")
        else:
            return Markup(g.username_cache[user])
    else:
        if name is None:
            if tool.has_perm("admin"):
                r = f'<a href="{url_for("document_contribution", user = user)}" class="deleted-user">(삭제된 사용자)</a>'
            else:
                r = '<span class="deleted-user">(삭제된 사용자)</span>'
        else:
            css = cssutils.css.CSSStyleDeclaration()
            with g.db.cursor() as c:
                for gr in c.execute("SELECT gid, value FROM aclgroup_config WHERE name = 'style' AND value != ''").fetchall():
                    if tool.user_in_aclgroup(gr[0], user):
                        for p in cssutils.parseStyle(gr[1]):
                            css.setProperty(p.name, p.value, p.priority)
            r = f'<a href="{url_for("doc_read", doc_title = tool.id_to_ns_name(int(tool.get_config("user_namespace"))) + ":" + escape(name))}" style="{css.cssText}">{escape(name)}</a>'
        g.username_cache[user] = r
        if b:
            return Markup(f"<b>{r}</b>")
        else:
            return Markup(r)
def history_msg(type, text2, text3):
    if type == 0:
        return ""
    elif type == 1:
        return "(새 문서)"
    elif type == 2:
        return "(삭제)"
    elif type == 3:
        return f"({text2}에서 {text3}으로 문서 이동)"
    elif type == 4:
        return f"({text2}으로 ACL 변경)"
    elif type == 5:
        return f"(r{text2}으로 되돌림)"
    return f"(type {type}, {text2}, {text3})"
app.jinja_loader = ChoiceLoader([
    FileSystemLoader("skins"),
    FileSystemLoader("templates"),
    FileSystemLoader("extensions")
])
app.jinja_env.globals["has_perm"] = tool.has_perm
app.jinja_env.globals["history_msg"] = history_msg
app.jinja_env.globals["range"] = range
app.jinja_env.globals["get_skin_config"] = tool.get_skin_config
app.jinja_env.globals["get_config"] = tool.get_config
app.jinja_env.filters["user"] = render_username
app.jinja_env.filters["time"] = tool.utime_to_str
app.jinja_env.policies['json.dumps_kwargs']['ensure_ascii'] = False
@app.route("/api/preview", methods=["POST"])
def api_preview():
    json = request.get_json()
    r = render_set(g.db, json["name"], json["data"], "api_view")
    return {"html": r[0], "js": r[1]}
@app.route("/api/preview/thread", methods=["POST"])
def api_thread():
    json = request.get_json()
    r = render_set(g.db, json["data"], "api_thread")
    return {"html": r[0], "js": r[1]}
@app.route("/")
def redirect_frontpage():
    return redirect(url_for("doc_read", doc_title = tool.get_config("frontpage")))
@app.route("/w/<path:doc_title>")
def doc_read(doc_title):
    with g.db.cursor() as c:
        ns, name = tool.split_ns(doc_title)
        docid = tool.get_docid(ns, name)
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return tool.rt("document_no_read_perm.html", title=tool.render_docname(ns, name), msg = acl[1]), 403
        rev = request.args.get('rev')
        menu = [
            tool.Menu("역링크", f"/backlink/{doc_title}"),
            tool.Menu("토론", f"/discuss/{doc_title}"),
            tool.Menu("편집", f"/edit/{doc_title}"),
            tool.Menu("역사", f"/history/{doc_title}"),
            tool.Menu("ACL", f"/acl/{doc_title}"),
            ]
        if rev is None:
            d = c.execute("SELECT value FROM data WHERE id = ?", (docid,)).fetchone()
        else:
            d = c.execute("SELECT content FROM history WHERE doc_id = ? AND rev = ?", (docid, rev)).fetchone()
        if d is None or d[0] is None:
            return tool.rt("no_document.html", title=tool.render_docname(ns, name), raw_title=doc_title, menu=menu), 404
        d = d[0]
        if "noredirect" not in request.args:
            re = data.redirect_regex.fullmatch(d)
            if re:
                return redirect(url_for("doc_read", doc_title = re.group(1), **{"from": doc_title}))
        d = render_set(g.db, doc_title, d)
        if "/" not in name and ns == int(tool.get_config("user_namespace")):
            user = tool.user_name_to_id(name)
            admin_userdoc = tool.has_perm("admin", user)
            tool.delete_expired_aclgroup()
            aclgroup = c.execute("SELECT A.name, L.id, L.start, L.end, L.note FROM aclgroup_log L JOIN aclgroup_config C ON (L.gid = C.gid) JOIN aclgroup A ON (L.gid = A.id) WHERE L.user = ? AND C.name = 'show_user_document' AND C.value = '1'", (user,)).fetchall()
            menu.append(tool.Menu("기여 목록", url_for("document_contribution", user = user)))
            menu.append(tool.Menu("UID 복사", f'javascript:navigator.clipboard.writeText("{user}")'))
        else:
            admin_userdoc = False
            aclgroup = []
        return tool.rt("document_read.html", admin_userdoc = admin_userdoc, title=tool.render_docname(ns, name), raw_title=doc_title, aclgroup=aclgroup,
                       doc_data=d, menu=menu, fr=request.args.get("from", None), image = ns in data.file_namespace, docid = docid
                       ), 200, {} if rev is None else {"X-Robots-Tag": "noindex"}
@app.route("/raw/<path:doc_title>")
def doc_raw(doc_title):
    with g.db.cursor() as c:
        ns, name = tool.split_ns(doc_title)
        docid = tool.get_docid(ns, name)
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return tool.error(acl[1], 403)
        rev = request.args.get('rev')
        if rev is None:
            d = c.execute("SELECT value FROM data WHERE id = ?", (docid,)).fetchone()
        else:
            d = c.execute("SELECT content FROM history WHERE doc_id = ? AND rev = ?", (docid, rev)).fetchone()
        if d is None or d[0] is None:
            return tool.error("문서를 찾을 수 없습니다.", 404)
        return tool.rt("document_raw.html", doc_title=tool.render_docname(ns, name), raw_title=doc_title, doc_data=d[0]), 200, {} if rev is None else {"X-Robots-Tag": "noindex"}
@app.route("/edit/<path:doc_title>")
def doc_edit(doc_title):
    with g.db.cursor() as c:
        ns, name = tool.split_ns(doc_title)
        docid = tool.get_docid(ns, name)
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return tool.error(acl[1], 403)
        acl = tool.check_document_acl(docid, ns, "edit", name)
        d = c.execute("select value from data where id = ?", (docid,)).fetchone()
        d = "" if d is None else d[0]
        if d is None: d = ""
        r = c.execute("select history_seq - 1 from doc_name where id = ?", (docid,)).fetchone()
        r = 0 if r is None else r[0]
        return tool.rt("document_edit.html", title=tool.render_docname(ns, name), subtitle="새 문서 생성" if r == 0 else f"r{r} 편집", raw_title=doc_title, doc_data=d, doc_rev=r, req_captcha = tool.is_required_captcha("edit"), aclmsg = acl[1], menu = [
            tool.Menu("역링크", f"/backlink/{doc_title}"),
            tool.Menu("삭제", f"/delete/{doc_title}"),
            tool.Menu("이동", f"/move/{doc_title}")
        ])
@app.route("/edit_form", methods = ['POST'])
def doc_edit_form():
    with g.db.cursor() as c:
        if not tool.captcha("edit"):
            return tool.captcha_failed()
        doc_name = request.form["doc_name"]
        value = request.form["value"]
        ns, name = tool.split_ns(doc_name)
        """docid = tool.get_docid(ns, name)
        if tool.check_document_acl(docid, ns, "edit", name, showmsg=False) == 0:
            abort(403)
        if docid == -1:
            if ns in data.file_namespace or ("/" not in name and ns == int(tool.get_config("user_namespace"))):
                return tool.error("invalid_namespace")
            docid = tool.get_docid(ns, name, True)
        prev_content = c.execute("SELECT value FROM data WHERE id = ?", (docid,)).fetchone()
        new_document = prev_content is None
        prev_content = "" if new_document else prev_content[0]
        if prev_content is None:
            new_document = True
            prev_content = ""
        tool.record_history(docid, int(new_document), value, None, None, tool.get_user(), request.form["edit_comment"], len(value) - len(prev_content))
        c.execute("UPDATE data SET value = ? WHERE id = ?", (value, docid))"""
        tool.edit_or_new(ns, name, value, request.form["edit_comment"])
        return redirect(f"/w/{doc_name}")
@app.route("/license")
def license():
    update = int(os.path.getmtime("data.py"))
    return tool.rt("license.html", title = "라이선스", engine_commit = commit_id, skin_commit = data.skin_commit[tool.get_skin()], update = update, before = tool.time_to_str(tool.get_utime() - update))
@app.route("/user")
def user():
    with g.db.cursor() as c:
        if tool.is_login():
            try:
                return tool.rt("user.html", user_name = tool.id_to_user_name(tool.get_user()), login=True)
            except:
                session.pop("id", None)
                return tool.rt("user.html", user_name = tool.getip(), login=False)
        else:
            return tool.rt("user.html", user_name = tool.getip(), login=False)
@app.route("/member/login", methods = ["GET", "POST"])
def login():
    if request.method == "POST":
        if not tool.captcha("login"):
            return tool.captcha_failed()
        id = tool.user_name_to_id(request.form["id"], True)
        if id == -1:
            return tool.error("계정이 존재하지 않습니다.")
        password = request.form["pw"]
        if not tool.check_password(id, password):
            return tool.error("비밀번호가 일치하지 않습니다.")
        if tool.check_needs_rehash(id):
            with g.db.cursor() as c:
                c.execute("UPDATE user SET password = ? WHERE id = ?", (tool.hash_password(password), id))
        if "keep" in request.form:
            session.permanent = True
        session["id"] = id
        tool.add_login_history()
        return redirect("/")
    return tool.rt("login.html", title = "로그인", req_captcha = tool.is_required_captcha("login"))
@app.route("/member/signup", methods = ["GET", "POST"])
def signup():
    if request.method == "POST":
        if not tool.captcha("signup"):
            return tool.captcha_failed()
        if tool.get_config("email_verification_level") == "3" or tool.has_perm("bypass_email_verify"):
            with g.db.cursor() as c:
                token = secrets.token_hex(32)
                email = tool.sanitize_email(request.form["email"])
                if email is None:
                    return tool.error("이메일의 값을 형식에 맞게 입력해주세요.")
                if not tool.check_email_wblist(email):
                    return tool.error("이메일 허용 목록에 있는 이메일이 아닙니다." if data.email_wblist_type else "이메일 차단 목록에 있는 이메일입니다.")
                if "agree" not in request.form:
                    return tool.error("동의의 값은 필수입니다.")
                wiki_name = tool.get_config("wiki_name")
                ip = tool.getip()
                title = tool.get_string_config("email_verification_signup_title").format(wiki_name = wiki_name)
                limit = int(tool.get_config("email_limit"))
                if limit != 0 and c.execute("SELECT count(*) FROM user_config WHERE name = 'email' and value = ?", (email,)).fetchone()[0] >= limit:
                    tool.email(email, title, tool.get_string_config("email_verification_signup_max").format(wiki_name = wiki_name, max = limit, ip = ip))
                else:
                    c.execute("INSERT INTO signup_link (token, email, ip, expire) VALUES(?,?,?,?)", (token, email, ip, tool.get_utime() + 86400))
                    tool.email(email, title, tool.get_string_config("email_verification_signup").format(wiki_name = wiki_name, link = url_for("signup2", token = token, _external = True), ip = ip))
                return tool.rt("signup_email.html", title = "계정 만들기", email = email)
        else:
            return redirect(url_for("signup2", token = "0"))
    return tool.rt("signup.html", title = "계정 만들기", policy = tool.get_string_config("policy"), email_must = tool.get_config("email_verification_level") == "3", req_captcha = tool.is_required_captcha("signup"), wblist = tool.show_email_wblist())
@app.route("/member/signup/<token>", methods = ["GET", "POST"])
def signup2(token):
    tool.delete_expired_signup_link()
    if tool.get_config("email_verification_level") != "3" or tool.has_perm("bypass_email_verify"):
        email = None
    else:
        with g.db.cursor() as c:
            f = c.execute("SELECT email, ip FROM signup_link WHERE token = ?", (token,)).fetchone()
        if f is None:
            return tool.error("인증 요청이 만료되었거나 올바르지 않습니다.")
        email, ip = f
        if ip != tool.getip():
            return tool.error("보안 상의 이유로 요청한 아이피 주소와 현재 아이피 주소가 같아야 합니다.")
    if request.method == "POST":
        if request.form['pw'] != request.form['pw2']:
            return tool.error("비밀번호가 일치하지 않습니다.")
        check = tool.check_username(request.form["name"])
        if check is not None:
            return tool.rt("error.html", error=check)
        with g.db.cursor() as c:
            first = c.execute("SELECT NOT EXISTS (SELECT 1 FROM user WHERE isip = 0)").fetchone()[0]
            u = tool.signup(request.form["name"], request.form["pw"])
            if first:
                c.execute("INSERT INTO perm VALUES(?, 'developer')", (u,))
            if email is not None:
                tool.set_user_config(u, "email", email)
                c.execute("DELETE FROM signup_link WHERE email = ?", (email,))
        session["id"] = u
        tool.add_login_history()
        return tool.rt("signup_completed.html", title = "계정 만들기", user = request.form["name"])
    return tool.rt("signup2.html", title = "계정 만들기", email = email)
@app.route("/member/logout")
def logout():
    session.clear()
    return redirect('/')
@app.route("/history/<path:doc_name>")
def history(doc_name):
    with g.db.cursor() as c:
        ns, name = tool.split_ns(doc_name)
        docid = tool.get_docid(ns, name)
        if docid == -1:
            return tool.error("문서를 찾을 수 없습니다.", 404)
        return tool.rt("history.html", history=c.execute("""SELECT rev, type, content, content2, content3, author, edit_comment, datetime, length, troll FROM history WHERE doc_id = ? ORDER BY rev DESC""", (docid,)).fetchall(),
                       title=tool.render_docname(ns, name), subtitle="역사", raw_doc_name=doc_name)
@app.route("/sql")
def sqldump():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SQLSHELL") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    with open("dump.sql", "w", encoding='utf-8') as f:
        for l in g.db.iterdump():
            f.write("%s\n" % l)
    return send_file("dump.sql", as_attachment=True)
@app.route("/sql_shell", methods=['GET', 'POST'])
def sqlshell():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SQLSHELL") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    if request.method == "GET":
        return tool.rt("sql_shell.html", title = "SQL Shell", prev_sql = "", result = "")
    else:
        try:
            with g.db.cursor() as c:
                result = str(c.execute(request.form["sql"]).fetchall())
        except Exception as e:
            result = str(e)
        return tool.rt("sql_shell.html", title = "SQL Shell", prev_sql = request.form["prev"] + "\n" + request.form["sql"], result = result)
@app.route("/delete/<path:doc_name>", methods = ["GET", "POST"])
def delete(doc_name):
    ns, name = tool.split_ns(doc_name)
    docid = tool.get_docid(ns, name)
    if request.method == "POST":
        try:
            tool.delete(docid, request.form["note"])
        except exceptions.DocumentNotExistError:
            return tool.error("문서를 찾을 수 없습니다.", 404)
        return redirect(url_for("doc_read", doc_title = doc_name))
    else:
        acl = tool.check_document_acl(docid, ns, "delete", name)
        if acl[0] == 0:
            return tool.error(acl[1], 403)
        return tool.rt("document_delete.html", title = tool.render_docname(ns, name), subtitle = "삭제")
@app.route("/move/<path:doc_name>", methods = ["GET", "POST"])
def move(doc_name):
    tool.clean_docid()
    ns, name = tool.split_ns(doc_name)
    docid = tool.get_docid(ns, name)
    acl = tool.check_document_acl(docid, ns, "move", name)
    if acl[0] == 0:
        return tool.error(acl[1], 403)
    if docid == -1:
        return tool.error("문서를 찾을 수 없습니다.", 404)
    if request.method == "POST":
        to = request.form["to"]
        tons, toname = tool.split_ns(to)
        if (ns in data.file_namespace) ^ (tons in data.file_namespace):
            return tool.error("이 문서를 해당 이름 공간으로 이동할 수 없습니다.", 409)
        if ns in data.file_namespace and os.path.splitext(name)[1] != os.path.splitext(toname)[1]:
            return tool.error("확장자가 다릅니다.", 409)
        if "swap" in request.form:
            # 문서를 서로 맞바꾸기
            todocid = tool.get_docid(tons, toname)
            if todocid == -1 or todocid == docid:
                return tool.error("문서를 찾을 수 없습니다.", 404)
            with g.db.cursor() as c:
                c.execute("UPDATE doc_name SET namespace = ?, name = ? WHERE id = ?", (tons, toname, docid))
                c.execute("UPDATE doc_name SET namespace = ?, name = ? WHERE id = ?", (ns, name, todocid))
            tool.record_history(docid, 3, tool.get_doc_data(docid), doc_name, to, tool.get_user(), request.form["note"], 0)
            tool.record_history(todocid, 3, tool.get_doc_data(todocid), to, doc_name, tool.get_user(), request.form["note"], 0)
        else:
            # 일반 문서 이동
            if tool.get_docid(tons, toname) != -1:
                return tool.error("문서가 이미 존재합니다.", 409)
            acl = tool.check_document_acl(-1, tons, "move", toname)
            if acl[0] == 0:
                return tool.error(acl[1], 403)
            with g.db.cursor() as c:
                c.execute("UPDATE doc_name SET namespace = ?, name = ? WHERE id = ?", (tons, toname, docid))
            tool.record_history(docid, 3, tool.get_doc_data(docid), doc_name, to, tool.get_user(), request.form["note"], 0)
        return redirect(url_for("doc_read", doc_title = to))
    return tool.rt("document_move.html", title = tool.render_docname(ns, name), subtitle = "이동")
@app.route("/acl/<path:doc_name>", methods = ["GET", "POST"])
def acl(doc_name):
    type1 = request.args.get("type1", "document")
    type2 = request.args.get("type2", None)
    with g.db.cursor() as c:
        tool.delete_expired_acl()
        nsacl = type1 == "namespace"
        if type2 not in data.acl_type_key:
            type2 = "read" if nsacl else "edit"
        ns, name = tool.split_ns(doc_name)
        docid = tool.get_docid(ns, name, request.method == "POST" and not nsacl)
        acl_t = "nsacl" if nsacl else "acl"
        id_col = "ns_id" if nsacl else "doc_id"
        id = ns if nsacl else docid
        if request.method == "POST":
            if not (tool.has_perm("nsacl") if nsacl else tool.has_perm("nsacl") or tool.check_document_acl(docid, ns, "acl", name, showmsg = False) == 1):
                abort(403)
            limit_acl = int(tool.get_config("limit_acl"))
            limit = False
            if type2 == "read" and limit_acl >= 2:
                limit = True
            if type2 == "acl" and limit_acl % 2 == 1:
                limit = True
            if limit and not tool.has_perm("nsacl"): abort(403)
            json = request.get_json()
            opcode = json["opcode"]
            if type2 == "read" and not nsacl and tool.get_config("document_read_acl") == "0":
                return tool.error_400("invalid_acl_condition")
            if opcode == "add":
                condtype = json["condtype"]
                cond = json["cond"]
                action = json["action"]
                no = json["not"]
                duration = json["duration"]
                ty2 = False
                if not isinstance(condtype, str) or \
                not isinstance(cond, str) or \
                not isinstance(action, str) or \
                not isinstance(no, bool) or \
                not isinstance(duration, int):
                    return tool.error_400("invalid_acl_condition")
                end = None if duration == 0 else tool.get_utime() + duration
                if end is not None and end > data.max_utime:
                    return tool.error_400("maximum_time_exceed")
                if condtype == "perm":
                    if no and cond == "member":
                        no = False
                        cond = "ip"
                    if no and cond == "ip":
                        no = False
                        cond = "member"
                    m = data.member_signup_days_ago_regex.match(cond)
                    if m is not None:
                        cond = f"member_signup_{int(m.group(1))}days_ago"
                    m = data.member_signup_ago_regex.match(cond)
                    if m is not None:
                        cond = f"member_signup_{int(m.group(1))}_ago"
                if type2 not in data.acl_type_key:
                    return tool.error_400("invalid_acl_condition")
                if action != "allow" and action != "deny" and (nsacl or action != "gotons") and action != "gotootherns":
                    return tool.error_400("invalid_acl_condition")
                if condtype == "user":
                    if not tool.has_user(cond):
                        return tool.error_400("invalid_acl_condition")
                    cond2 = cond
                    cond = tool.user_name_to_id(cond)
                    ty2 = True
                elif condtype == "ip":
                    if not tool.is_valid_ip(cond) and not tool.is_valid_cidr(cond):
                        return tool.error_400("invalid_acl_condition")
                    if "/" in cond: cond = tool.convert_cidr(cond)
                    else: cond = tool.convert_ip(cond)
                elif condtype == "geoip":
                    return tool.error_400("GeoIP는 아직 안 만들었으니 쓰지 마세요")
                    if len(cond) != 2 or not cond.isupper():
                        return tool.error_400("invalid_acl_condition")
                elif condtype == "aclgroup":
                    fetch = c.execute("SELECT id FROM aclgroup WHERE name = ? AND deleted = 0", (cond,)).fetchone()
                    if fetch == None:
                        return tool.error_400("invalid_acl_condition")
                    cond2 = cond
                    cond = fetch[0]
                    ty2 = True
                elif condtype != "perm":
                    return tool.error_400("invalid_acl_condition")
                if action == "gotootherns":
                    ons = c.execute("SELECT id FROM namespace WHERE name = ?", (json["ns"],)).fetchone()
                    if ons is None: return tool.error_400(f"{json['ns']} 이름공간은 존재하지 않습니다!")
                c.execute(f"""INSERT INTO {acl_t} ({id_col}, acltype, idx, condtype, value{"2" if ty2 else ""}, no, action, expire, otherns)
                                SELECT ?1,?2,(SELECT COALESCE(MAX(idx), 0) + 1 FROM {acl_t} WHERE {id_col} = ?1 AND acltype = ?2),?3,?4,?5,?6,?7,?8""",
                            (id, type2, condtype, cond, no, action, end, ons[0] if action == "gotootherns" else None))
                if not nsacl: tool.record_history(docid, 4, tool.get_doc_data(docid), f'insert,{type2},{action},{"not:" if no else ""}{condtype}:{cond2 if condtype == "aclgroup" or condtype == "user" else cond}', None, tool.get_user(), "", 0)
            elif opcode == "delete":
                idx = json["index"]
                if not isinstance(idx, int):
                    return tool.error_400("invalid_acl_condition")
                f = c.execute(f"SELECT condtype, value, value2, no, action FROM {acl_t} WHERE {id_col} = ? AND acltype = ? AND idx = ?", (id, type2, idx)).fetchone()
                if f is None:
                    return tool.error_400("invalid_acl_condition")
                if f[0] == "user":
                    v = tool.id_to_user_name(f[2])
                elif f[0] == "aclgroup":
                    v = c.execute("SELECT name FROM aclgroup WHERE id = ?", (f[2],)).fetchone()[0]
                else:
                    v = f[1]
                if not nsacl: tool.record_history(docid, 4, tool.get_doc_data(docid), f'delete,{type2},{f[4]},{"not:" if f[3] else ""}{f[0]}:{v}', None, tool.get_user(), "", 0)
                c.execute(f"DELETE FROM {acl_t} WHERE {id_col} = ? AND acltype = ? AND idx = ?", (id, type2, idx))
                c.execute(f"UPDATE {acl_t} SET idx = idx - 1 WHERE {id_col} = ? AND acltype = ? AND idx > ?", (id, type2, idx))
            elif opcode == "move":
                fro = json["from"]
                to = json["to"]
                if not isinstance(fro, int) or not isinstance(to, int) or fro < 1 or to < 1:
                    return tool.error_400("invalid_acl_condition")
                max = c.execute(f"SELECT COALESCE(MAX(idx), 0) FROM {acl_t} WHERE {id_col} = ? AND acltype = ?", (id, type2)).fetchone()[0]
                if fro > max or to > max:
                    return tool.error_400("invalid_acl_condition")
                if to > fro:
                    c.execute(f"UPDATE {acl_t} SET idx = 0 WHERE {id_col} = ? AND acltype = ? AND idx = ?", (id, type2, fro))
                    c.execute(f"UPDATE {acl_t} SET idx = idx - 1 WHERE {id_col} = ? AND acltype = ? AND idx > ? AND idx <= ?", (id, type2, fro, to))
                    c.execute(f"UPDATE {acl_t} SET idx = ? WHERE idx = 0", (to,))
                elif to < fro:
                    c.execute(f"UPDATE {acl_t} SET idx = 0 WHERE {id_col} = ? AND acltype = ? AND idx = ?", (id, type2, fro))
                    c.execute(f"UPDATE {acl_t} SET idx = idx + 1 WHERE {id_col} = ? AND acltype = ? AND idx < ? AND idx >= ?", (id, type2, fro, to))
                    c.execute(f"UPDATE {acl_t} SET idx = ? WHERE idx = 0", (to,))
            return {}
        acls = []
        for i in data.acl_type_key if nsacl or tool.get_config("document_read_acl") == "1" else data.acl_type_key2:
            acls.append(tool.Menu(data.acl_type[i], url_for("acl", doc_name = doc_name, type1 = type1, type2 = i), "menu2-selected" if i == type2 else ""))
        return tool.rt("acl.html", title=tool.render_docname(ns, name), raw_doc_name = doc_name, subtitle="ACL", type=data.acl_type[type2], type2 = type2, dns = tool.get_namespace_name(int(tool.get_config("default_namespace"))),
                hasperm = tool.has_perm("nsacl") if nsacl else tool.has_perm("nsacl") or tool.check_document_acl(docid, ns, "acl", name, showmsg = False) == 1, perms = data.perm_type,
                acl = tool.render_acl(c.execute(f"""SELECT idx, condtype, value, value2, no, action, expire, otherns FROM {acl_t} WHERE {id_col} = ? AND acltype = ? ORDER BY idx""", (id, type2)).fetchall(), type2),
                nsacl = nsacl, menu2 = (
            [
                tool.Menu("문서 ACL", url_for("acl", doc_name = doc_name, type1 = "document"), "menu2-selected" if not nsacl else ""),
                tool.Menu("이름공간 ACL", url_for("acl", doc_name = doc_name, type1 = "namespace"), "menu2-selected" if nsacl else "")
            ], acls
        ))
@app.route("/random")
def random_document():
    with g.db.cursor() as c:
        c.execute('SELECT name FROM doc_name LIMIT 1 OFFSET abs(random()) % (SELECT COUNT(*) FROM doc_name);')
        r = c.fetchone()[0]
        return redirect('/w/{0}'.format(r))
@app.route("/file/<int:id>")
def file(id):
    name = tool.get_doc_name(id)
    if name is None: abort(404)
    ns, name = name
    if ns not in data.file_namespace: abort(404)
    if tool.check_document_acl(id, ns, "read", name, showmsg=False) == 0: return "", 403
    try:
        return send_file(os.path.join("file", str(id)), mimetypes.guess_type(name)[0])
    except FileNotFoundError:
        abort(404)
@app.route("/admin/config", methods = ["GET", "POST"])
def config():
    with g.db.cursor() as c:
        if not tool.has_perm("config"):
            abort(403)
        if request.method == "POST":
            c.execute("DELETE FROM config")
            c.executemany("INSERT INTO config VALUES(?,?)", request.form.items())
        tool.reload_config(app)
        return tool.rt("config.html", title="Config", settings = c.execute("SELECT name, value FROM config").fetchall(), save = request.method == "POST")
@app.route("/admin/config/string", methods = ["GET", "POST"])
def string_config():
    with g.db.cursor() as c:
        if not tool.has_perm("config"):
            abort(403)
        if request.method == "POST":
            c.execute("DELETE FROM string_config")
            c.executemany("INSERT INTO string_config VALUES(?,?)", request.form.items())
        tool.reload_config(app)
        return tool.rt("string_config.html", title="String config", settings = c.execute("SELECT name, value FROM string_config").fetchall(), save = request.method == "POST")
@app.route("/aclgroup", methods = ["GET", "POST"])
def aclgroup():
    with g.db.cursor() as c:
        tool.delete_expired_aclgroup()
        groups = []
        for id, name in c.execute("SELECT id, name FROM aclgroup WHERE deleted = 0"):
            if tool.check_aclgroup_flag(id, "access_flags"):
                groups.append(name)
        if len(groups) == 0:
            abort(403)
        grp = request.args.get("group", "")
        current = grp if grp in groups else groups[0]
        gid = c.execute("SELECT id FROM aclgroup WHERE name = ? AND deleted = 0", (current,)).fetchone()[0]
        if request.method == "POST":
            dur = 0 if request.form["dur"] == "" else int(request.form["dur"])
            """if not tool.check_aclgroup_flag(gid, "add_flags"):
                abort(403)
            t = tool.get_utime()
            if tool.get_config("aclgroup_note_required") == "1" and request.form["note"] == "":
                return tool.error_400("note의 값은 필수입니다.")
            if request.form["mode"] == "ip":
                ip = request.form["value"]
                try:
                    ipn = ipaddress.ip_network(ip)
                    ip = str(ipn)
                except:
                    return tool.error_400("invalid_cidr")
                max_cidr = "max_ipv4_cidr" if ipn.version == 4 else "max_ipv6_cidr"
                max_cidr_value = int(tool.get_aclgroup_config(gid, max_cidr))
                if ipn.prefixlen < max_cidr_value: return tool.error_400(f"{max_cidr}은 {max_cidr_value}입니다.")
                max_duration = int(tool.get_aclgroup_config(gid, "max_duration_ip"))
                if max_duration != 0 and dur > max_duration: return tool.error_400(f"max_duration_ip는 {max_duration}입니다.")
                if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_log WHERE ip = ? AND gid = ?)", (ip, gid)).fetchone()[0]:
                    return tool.error_400("aclgroup_already_exists")
                c.execute("INSERT INTO aclgroup_log (gid, ip, note, start, end) VALUES(?, ?, ?, ?, ?)",
                        (gid, ip, request.form["note"], t, None if dur == 0 else t + dur))
                c.execute("INSERT INTO block_log (type, operator, target_ip, id, gid, date, duration, note) VALUES(1, ?, ?, ?, ?, ?, ?, ?)",
                        (tool.get_user(), ip, c.lastrowid, gid, t, dur, request.form["note"]))
            else:
                if not tool.has_user(request.form["value"]):
                    return tool.error_400("사용자 이름이 올바르지 않습니다.")
                max_duration = int(tool.get_aclgroup_config(gid, "max_duration_account"))
                if max_duration != 0 and dur > max_duration: return tool.error_400(f"max_duration_account는 {max_duration}입니다.")
                if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_log WHERE user = (SELECT id FROM user WHERE name = ?) AND gid = ?)", (request.form["value"], gid)).fetchone()[0]:
                    return tool.error_400("aclgroup_already_exists")
                c.execute("INSERT INTO aclgroup_log (gid, user, note, start, end) VALUES(?, (SELECT id FROM user WHERE name = ?), ?, ?, ?)",
                        (gid, request.form["value"], request.form["note"], t, None if dur == 0 else t + dur))
                c.execute("INSERT INTO block_log (type, operator, target, id, gid, date, duration, note) VALUES(1, ?, (SELECT id FROM user WHERE name = ?), ?, ?, ?, ?, ?)",
                        (tool.get_user(), request.form["value"], c.lastrowid, gid, t, dur, request.form["note"]))"""
            mode = request.form["mode"]
            if mode == "user":
                user = tool.user_name_to_id(request.form["value"])
                if user == -1:
                    return tool.error_400("사용자 이름이 올바르지 않습니다.")
            else:
                user = request.form["value"]
            try:
                tool.aclgroup_insert(gid, mode, user, request.form["note"], dur)
            except exceptions.ACLGroupPermissionDeniedError:
                return '', 403
            except exceptions.ACLGroupConfigError as e:
                return tool.error_400(f"{e.name}은 {e.value}입니다.")
            except exceptions.ACLGroupNoteRequiredError:
                return tool.error_400("note의 값은 필수입니다.")
            except exceptions.ACLGroupAlreadyExistsError:
                return tool.error_400("aclgroup_already_exists")
            except exceptions.InvalidCIDRError:
                return tool.error_400("invalid_cidr")
            except exceptions.MaximumTimeExceedError:
                return tool.error_400("maximum_time_exceed")
            except ValueError:
                return "", 400
        return tool.rt("aclgroup.html", title = "ACLGroup", groups = groups, gid = gid, current = current, newgroup_perm = tool.has_perm("aclgroup"), add_perm = tool.check_aclgroup_flag(gid, "add_flags"), delete_perm = tool.check_aclgroup_flag(gid, "remove_flags"), record = (
            (x[0], x[1], x[2], tool.utime_to_str(x[3]), "영구" if x[4] is None else tool.utime_to_str(x[4]))
            for x in c.execute("SELECT id, (CASE WHEN ip IS NULL THEN (SELECT name FROM user WHERE id = user) ELSE ip END), note, start, end FROM aclgroup_log WHERE gid = (SELECT id FROM aclgroup WHERE name = ? AND deleted = 0)", (current,)).fetchall()
        ))
@app.route("/aclgroup/delete", methods = ["POST"])
def aclgroup_delete():
    with g.db.cursor() as c:
        id = int(request.form["id"])
        try:
            tool.aclgroup_delete(id, request.form["note"])
        except exceptions.ACLGroupElementNotExistsError:
            return tool.error_400("aclgroup_not_found")
        except exceptions.NoteRequiredError:
            return tool.error_400("note의 값은 필수입니다.")
        except exceptions.ACLGroupPermissionDeniedError:
            return '', 403
        return '', 204
@app.route("/aclgroup/new_group", methods = ["POST"])
def aclgroup_new_group():
    if not tool.has_perm("aclgroup"):
        abort(403)
    with g.db.cursor() as c:
        if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup WHERE name = ? AND deleted = 0)", (request.form["group"],)).fetchone()[0]: return tool.error("이미 존재하는 ACLGroup입니다.")
        c.execute("INSERT INTO aclgroup (name) VALUES(?)",
                (request.form["group"],))
        id = c.lastrowid
        c.executemany("INSERT INTO aclgroup_config (gid, name, value) VALUES(?,?,?)",
                      ((id, x[0], x[1]) for x in data.default_aclgroup_config))
        return redirect("/aclgroup?group={0}".format(request.form["group"]))
@app.route("/aclgroup/delete_group", methods = ["POST"])
def aclgroup_delete_group():
    if not tool.has_perm("aclgroup"):
        abort(403)
    with g.db.cursor() as c:
        gid = c.execute("SELECT id FROM aclgroup WHERE name = ? AND deleted = 0", (request.form["group"],)).fetchone()
        if gid is None:
            abort(400)
        gid = gid[0]
        c.execute("UPDATE aclgroup SET deleted = 1 WHERE id = ?", (gid,))
        c.execute("DELETE FROM aclgroup_log WHERE gid = ?", (gid,))
        c.execute("DELETE FROM aclgroup_config WHERE gid = ?", (gid,))
        return redirect("/aclgroup")
@app.route("/aclgroup/manage", methods = ["GET", "POST"])
def aclgroup_manage():
    if not tool.has_perm("aclgroup"):
        abort(403)
    with g.db.cursor() as c:
        gid = c.execute("SELECT id FROM aclgroup WHERE name = ? AND deleted = 0", (request.args["group"],)).fetchone()
        if gid == None:
            abort(404)
        gid = gid[0]
        if request.method == "POST":
            c.execute("BEGIN")
            def fail():
                g.db.rollback()
                abort(400)
            def remove_zero(n):
                r = n.lstrip("0")
                if r == "": return "0"
                else: return r
            tmp = request.form["withdraw_period"]
            if not tmp.isdecimal() and tmp != "-1": fail()
            c.execute("UPDATE aclgroup_config SET value = ? WHERE gid = ? AND name = 'withdraw_period'", (remove_zero(tmp), gid))
            tmp = request.form["signup_policy"]
            if tmp not in ["none", "require_verification", "block"]: fail()
            c.execute("UPDATE aclgroup_config SET value = ? WHERE gid = ? AND name = 'signup_policy'", (tmp, gid))
            tmp = request.form["max_duration_ip"]
            if not tmp.isdecimal(): fail()
            c.execute("UPDATE aclgroup_config SET value = ? WHERE gid = ? AND name = 'max_duration_ip'", (remove_zero(tmp), gid))
            tmp = request.form["max_duration_account"]
            if not tmp.isdecimal(): fail()
            c.execute("UPDATE aclgroup_config SET value = ? WHERE gid = ? AND name = 'max_duration_account'", (remove_zero(tmp), gid))
            tmp = request.form["max_ipv4_cidr"]
            try: tmp2 = int(tmp)
            except: fail()
            if tmp2 < 0 or tmp2 > 32: fail()
            c.execute("UPDATE aclgroup_config SET value = ? WHERE gid = ? AND name = 'max_ipv4_cidr'", (remove_zero(tmp), gid))
            tmp = request.form["max_ipv6_cidr"]
            try: tmp2 = int(tmp)
            except: fail()
            if tmp2 < 0 or tmp2 > 128: fail()
            c.execute("UPDATE aclgroup_config SET value = ? WHERE gid = ? AND name = 'max_ipv6_cidr'", (remove_zero(tmp), gid))
            for i in ["access_flags", "add_flags", "remove_flags", "style", "message", "self_remove_note"]:
                c.execute("UPDATE aclgroup_config SET value = ? WHERE gid = ? AND name = ?", (request.form[i], gid, i))
            c.execute("UPDATE aclgroup_config SET value = ? WHERE gid = ? AND name = 'show_user_document'", ("1" if "show_user_document" in request.form else "0", gid))
            c.execute("UPDATE aclgroup_config SET value = ? WHERE gid = ? AND name = 'self_removable'", ("1" if "self_removable" in request.form else "0", gid))
            return redirect(url_for("aclgroup", group = request.args["group"]))
        return tool.rt("aclgroup_manage.html", title="ACLGroup 설정", group = request.args["group"],
                       config = dict(c.execute("SELECT name, value FROM aclgroup_config WHERE gid = ?", (gid,)).fetchall()))
@app.route("/api/hasuser/<name>")
def api_hasuser(name):
    return Response("1" if tool.has_user(name) else "0", mimetype="text/plain")
@app.route("/api/hasuser1/<name>")
def api_hasuser1(name):
    return Response("1" if tool.has_user(name, True) else "0", mimetype="text/plain")
@app.route("/BlockHistory")
def block_history():
    with g.db.cursor() as c:
        return tool.rt("block_history.html", title = "차단 내역", log = [
            (x[0], x[1], x[2], x[3], x[4], x[5], x[6], None if x[7] is None else tool.time_to_str(x[7]), x[8], x[9]) for x in
            c.execute("""SELECT type, operator, target, target_ip, block_log.id, aclgroup.name, date, duration, grant_perm, note FROM block_log
    LEFT JOIN aclgroup ON block_log.gid = aclgroup.id
    ORDER BY date DESC""").fetchall()], note_ext = tool.get_config("ext_note") == "1")
@app.route("/admin/grant", methods = ["GET", "POST"])
def grant():
    if not tool.has_perm("grant"):
        abort(403)
    with g.db.cursor() as c:
        if request.method == "POST":
            if not tool.has_user(request.args.get("username", "")):
                return tool.error_400("사용자 이름이 올바르지 않습니다.")
            user = tool.user_name_to_id(request.args.get("username", ""))
            logstr = []
            for p in data.permissions:
                if tool.can_grant(p):
                    if p in request.form:
                        if c.execute("SELECT NOT EXISTS (SELECT 1 FROM perm WHERE user = ? AND perm = ?)", (user, p)).fetchone()[0]:
                            c.execute("INSERT INTO perm VALUES(?,?)", (user, p))
                            logstr.append("+" + p)
                    else:
                        if c.execute("SELECT EXISTS (SELECT 1 FROM perm WHERE user = ? AND perm = ?)", (user, p)).fetchone()[0]:
                            c.execute("DELETE FROM perm WHERE user =  ? AND perm = ?", (user, p))
                            logstr.append("-" + p)
            if len(logstr) != 0: c.execute("INSERT INTO block_log (type, operator, target, date, grant_perm, note) VALUES(3,?,?,?,?,?)",
                    (tool.get_user(), user, tool.get_utime(), " ".join(logstr), request.form["note"] if tool.get_config("ext_note") == "1" else ""))
            return '', 204
        else:
            user = request.args.get("username", "")
            if user == "":
                return tool.rt("grant.html", title="권한 부여", user2 = "")
            else:
                if not tool.has_user(user):
                    return tool.rt("grant.html", title="권한 부여", user2 = user, error = 1)
                else:
                    return tool.rt("grant.html", title="권한 부여", user2 = user, grantable = ((x, tool.can_grant(x)) for x in data.permissions), validuser = True, ext_note = tool.get_config("ext_note") == "1",
                            perm = set(x[0] for x in c.execute(f"SELECT perm FROM perm WHERE user = ? AND perm IN ({','.join('?' * len(data.permissions))})", [tool.user_name_to_id(user)] + data.permissions).fetchall()))
@app.route("/admin/captcha_test", methods = ["GET", "POST"])
def captcha_test():
    if not tool.has_perm("config"):
        abort(403)
    if request.method == "POST":
        return tool.rt("captcha_test.html", title = "CAPTCHA 테스트", result = int(tool.captcha("test")))
    return tool.rt("captcha_test.html", title = "CAPTCHA 테스트", req_captcha = tool.is_required_captcha("test"), result = -1)
@app.route("/Go")
def go():
    return redirect(url_for("doc_read", doc_title = request.args["q"]))
@app.route("/discuss/<path:doc>", methods = ["GET", "POST"])
def discuss(doc):
    with g.db.cursor() as c:
        ns, name = tool.split_ns(doc)
        docid = tool.get_docid(ns, name)
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return tool.error(acl[1], 403)
        if request.method == "POST":
            acl = tool.check_document_acl(docid, ns, "create_thread", name)
            if acl[0] == 0:
                return tool.error(acl[1], 403)
            if docid == -1: docid = tool.get_docid(ns, name, True)
            time = tool.get_utime()
            c.execute("INSERT INTO discuss (doc_id, topic, last) VALUES(?,?,?)", (docid, request.form["topic"], time))
            slug = c.lastrowid
            #c.execute("INSERT INTO thread_comment (slug, no, text, type, author, time) VALUES(?,1,?,0,?,?)", (slug, request.form["content"], tool.get_user(), time))
            tool.write_thread_comment(slug, 0, request.form["content"])
            return redirect(url_for("thread", slug = slug))
        else:
            state = request.args.get("state", "")
            if state == "close":
                return tool.rt("closed_discuss.html", title = tool.render_docname(ns, name), raw_title = doc, subtitle = "닫힌 토론", discuss = c.execute("SELECT slug, topic FROM discuss WHERE doc_id = ? AND status == 'close' ORDER BY last DESC", (docid,)).fetchall())
            else:
                return tool.rt("discuss.html", title = tool.render_docname(ns, name), raw_title = doc, subtitle = "토론 목록", discuss = c.execute("SELECT slug, topic FROM discuss WHERE doc_id = ? AND status != 'close' ORDER BY last DESC", (docid,)).fetchall(), menu = [
                    tool.Menu("편집", url_for("doc_edit", doc_title = doc)),
                    tool.Menu("ACL", url_for("acl", doc_name = doc))
                ])
@app.route("/thread/<int:slug>", methods = ["GET", "POST"])
def thread(slug):
    with g.db.cursor() as c:
        f = c.execute("SELECT namespace, name, doc_id, topic, status FROM discuss JOIN doc_name ON (doc_id = id) WHERE slug = ?", (slug,)).fetchone()
        if f is None:
            abort(404)
        ns, name, docid, topic, status = f
        fullname = tool.cat_namespace(ns, name)
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return tool.error(acl[1], 403)
        if request.method == "POST":
            opcode = request.form.get("opcode")
            if opcode == "status":
                if not tool.has_perm("update_thread_status"):
                    abort(403)
                st = request.form["status"]
                if st == status or (st != "normal" and st != "close" and st != "pause"):
                    abort(400)
                c.execute("UPDATE discuss SET status = ? WHERE slug = ?", (st, slug))
                tool.write_thread_comment(slug, 1, st)
            elif opcode == "document":
                if not tool.has_perm("update_thread_document"):
                    abort(403)
                ns, name = tool.split_ns(request.form["value"])
                docid = tool.get_docid(ns, name)
                acl = tool.check_document_acl(docid, ns, "create_thread", name)
                if acl[0] == 0:
                    return acl[1], 403, {"Content-Type": "text/plain"}
                acl = tool.check_document_acl(docid, ns, "write_thread_comment", name)
                if acl[0] == 0:
                    return acl[1], 403, {"Content-Type": "text/plain"}
                c.execute("UPDATE discuss SET doc_id = ? WHERE slug = ?", (tool.get_docid(ns, name, True), slug))
                tool.write_thread_comment(slug, 2, fullname, request.form["value"])
            elif opcode == "topic":
                if not tool.has_perm("update_thread_topic"):
                    abort(403)
                c.execute("UPDATE discuss SET topic = ? WHERE slug = ?", (request.form["value"], slug))
                tool.write_thread_comment(slug, 3, topic, request.form["value"])
            else:
                if status != "normal":
                    return tool.error_400("invalid_status")
                acl = tool.check_document_acl(docid, ns, "write_thread_comment", name)
                if acl[0] == 0:
                    return acl[1], 403, {"Content-Type": "text/plain"}
                tool.write_thread_comment(slug, 0, request.form["value"])
            #c.execute("""INSERT INTO thread_comment (slug, no, type, text, author, time)
#SELECT ?1, (SELECT seq FROM discuss WHERE slug = ?1), 0, ?2, ?3, ?4""", (slug, request.form["value"], tool.get_user(), tool.get_utime()))
            #c.execute("UPDATE discuss SET seq = seq + 1 WHERE slug = ?", (slug,))
            return "", 204
        #html, js = tool.render_thread(slug)
        return tool.rt("thread.html", topic = topic, title = tool.render_docname(ns, name), raw_title = fullname, subtitle = "토론", count = c.execute("SELECT seq - 1 FROM discuss WHERE slug = ?", (slug,)).fetchone()[0], comment = c.execute("SELECT no, blind FROM thread_comment WHERE slug = ?", (slug,)).fetchall(),
                       status = status, slug = slug, whtc = tool.has_perm("weak_hide_thread_comment"), htc = tool.has_perm("hide_thread_comment"), menu = [
            tool.Menu("토론 목록", url_for("discuss", doc = fullname)),
            tool.Menu("ACL", url_for("acl", doc_name = fullname))
        ])
"""@app.route("/api/render_thread/<int:slug>")
def render_thread(slug):
    with g.db.cursor() as c:
        ns, name, docid = c.execute("SELECT namespace, name, doc_id FROM discuss JOIN doc_name ON (doc_id = id) WHERE slug = ?", (slug,)).fetchone()
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return "", 403
        html, js = tool.render_thread(slug)
        return {"html": html, "js": js}"""
@app.route("/api/thread_comment_internal/<int:slug>/<int:no>/<int:type1>")
def api_thread_comment_internal(slug, no, type1):
    with g.db.cursor() as c:
        ns, name, docid = c.execute("SELECT namespace, name, doc_id FROM discuss JOIN doc_name ON (doc_id = id) WHERE slug = ?", (slug,)).fetchone()
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return "", 403
        ignore_blind = type1 >= 2
        if ignore_blind and not tool.has_perm("hide_thread_comment"): return "", 403
        author, type, text, text2, time, admin, blind, blind_operator = c.execute("SELECT author, type, text, text2, time, admin, blind, blind_operator FROM thread_comment WHERE slug = ? AND no = ?", (slug, no)).fetchone()
        clas = ["comment"]
        if author == tool.get_thread_presenter(slug): clas.append("comment-presenter")
        if blind == 2 and not ignore_blind:
            html = f"[{render_username(blind_operator, 1)}에 의해 숨겨진 글입니다.]"
            if tool.has_perm("hide_thread_comment"): html += ' <button class="danger show-blind">[ADMIN] SHOW</button>'
            js = ""
            clas.append("comment-blind")
        else:
            if type == 0:
                if type1 % 2 == 0: html, js = render_set(g.db, "", text, "api_thread")
                else:
                    html = text
                    js = ""
            elif type == 1:
                html = f"스레드 상태를 <b>{text}</b>로 변경"
            elif type == 2:
                html = f"스레드를 <b>{text}</b>에서 <b>{text2}</b>로 이동"
            elif type == 3:
                html = f"스레드 주제를 <b>{text}</b>에서 <b>{text2}</b>로 변경"
            elif type == 4:
                html = f"토론 ACL을 <b>{text}</b>로 변경"
            elif type == 5:
                html = f"<a href="#{text}">#{text}</a> 댓글을 고정"
            elif type == 6:
                html = "댓글 고정 해제"
            if type != 0:
                js = ""
                clas.append("comment-special")
            if blind == 1:
                html = f"[{render_username(blind_operator, 1)}에 의해 숨겨진 글입니다.]<hr>{html}"
                clas.append("comment-weakblind")
        return {
            "html": html,
            "js": js,
            "class": " ".join(clas),
            "author": render_username(author, 1 if admin else 2),
            "time": tool.utime_to_str(time),
            "blind": blind,
            "special": type > 0
        }
@app.route("/api/thread_comment_count/<int:slug>")
def thread_comment_count(slug):
    with g.db.cursor() as c:
        ns, name, docid = c.execute("SELECT namespace, name, doc_id FROM discuss JOIN doc_name ON (doc_id = id) WHERE slug = ?", (slug,)).fetchone()
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return "", 403
        return str(c.execute("SELECT COUNT(*) FROM thread_comment WHERE slug = ?", (slug,)).fetchone()[0]), 200, {"Content-Type": "text/plain"}
@app.route("/api/hide_thread_comment/<int:slug>/<int:no>/<int:type>", methods = ["POST"])
def hide_thread_comment(slug, no, type):
    if type < 0 or type > 2:
        return "", 400
    with g.db.cursor() as c:
        status = c.execute("SELECT blind FROM thread_comment WHERE slug = ? AND no = ?", (slug, no)).fetchone()[0]
        if type == status: return "", 400
        if not tool.has_perm("weak_hide_thread_comment"): return "", 403
        if (type == 2 or status == 2) and not tool.has_perm("hide_thread_comment"): return "", 403
        if type == 0: c.execute("UPDATE thread_comment SET blind = 0, blind_operator = NULL WHERE slug = ? AND no = ?", (slug, no))
        else: c.execute("UPDATE thread_comment SET blind = ?, blind_operator = ? WHERE slug = ? AND no = ?", (type, tool.get_user(), slug, no))
        return "", 204
@app.route("/topic/<int:slug>")
def topic_redirect(slug):
    return redirect(url_for("thread", slug = slug))
@app.route("/robots.txt")
def robots():
    return send_file("robots.txt")
@app.route("/admin/sysman")
def sysman():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    return tool.rt("sysman.html", title="시스템 관리", nokey = tool.get_config("pythonanywhere") == "1" and not os.getenv("API_TOKEN"))
@app.route("/admin/sysman/update", methods = ["GET", "POST"])
def update():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    if request.method == "POST":
        p = subprocess.Popen(["git", "pull", "origin", "main"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        r1 = p.communicate()[0]
        try:
            p = subprocess.Popen([f"python{sys.version_info.major}.{sys.version_info.minor}", "-m", "pip", "install", "-r", "requirements.txt"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except FileNotFoundError:
            p = subprocess.Popen(["python", "-m", "pip", "install", "-r", "requirements.txt"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return tool.rt("update_result.html", title = "업데이트 결과", result = r1.decode("utf-8") + "\n" + p.communicate()[0].decode("utf-8"))
    if repo is None:
        return tool.error("엔진이 git 저장소로 다운로드 되지 않았기 때문에 업데이트 기능을 사용할 수 없습니다.")
    else:
        return tool.rt("update.html", title = "업데이트", branch = (r.name[7:] for r in repo.remotes.origin.refs), current = data.version)
@app.route("/admin/sysman/restart", methods = ["GET", "POST"])
def restart():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    if request.method == "POST":
        if tool.get_config("pythonanywhere") == "1":
            requests.post(f"https://{'eu' if tool.get_config('pythonanywhere_eu') == '1' else 'www'}.pythonanywhere.com/api/v0/user/{tool.get_config('pythonanywhere_user')}/webapps/{tool.get_config('pythonanywhere_domain')}/reload/",
                          headers={"Authorization": "Token " + os.getenv("API_TOKEN")})
            return redirect("/")
        else:
            return tool.error("재시작 기능은 pythonanywhere에서만 사용 가능합니다.", 501)
    return tool.rt("restart.html", title = "재시작", paw = tool.get_config("pythonanywhere") == "1")
@app.route("/admin/sysman/shutdown", methods = ["GET", "POST"])
def shutdown():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    if request.method == "POST":
        if tool.get_config("pythonanywhere") == "1":
            requests.post(f"https://{'eu' if tool.get_config('pythonanywhere_eu') == '1' else 'www'}.pythonanywhere.com/api/v0/user/{tool.get_config('pythonanywhere_user')}/webapps/{tool.get_config('pythonanywhere_domain')}/disable/",
                          headers={"Authorization": "Token " + os.getenv("API_TOKEN")})
            return redirect("/")
        else:
            os._exit(0)
    return tool.rt("shutdown.html", title = "종료")
@app.route("/admin/sysman/skin")
def manage_skin():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    return tool.rt("manage_skin.html", title = "스킨 관리",
                   skins = ((x, f"{data.skin_info[x]['version']} ({data.skin_commit[x]})", x not in data.skin_git) for x in data.skins))
@app.route("/admin/sysman/skin/update", methods = ["POST"])
def update_skin():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    skin = request.form["skin"]
    if skin not in data.skin_git:
        return tool.error("존재하지 않거나 git로 다운로드 되지 않은 스킨입니다.")
    return tool.rt("update_result.html", title = "업데이트 결과", result = subprocess.Popen(["git", "-C", os.path.join("skins", skin), "pull"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].decode("utf-8"))
@app.route("/admin/sysman/skin/delete", methods = ["POST"])
def delete_skin():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    skin = request.form["skin"]
    if skin not in data.skins:
        return tool.error("존재하지 않는 스킨입니다.")
    data.skins.remove(skin)
    path = os.path.join("skins", skin)
    for root, dirs, files in os.walk(path):
        for i in dirs:
            os.chmod(os.path.join(root, i), stat.S_IWRITE)
        for i in files:
            os.chmod(os.path.join(root, i), stat.S_IWRITE)
    shutil.rmtree(path)
    return redirect(url_for("restart"))
@app.route("/admin/sysman/skin/install", methods = ["POST"])
def install_skin():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    return tool.rt("update_result.html", title = "설치 결과", result = subprocess.Popen(["git", "clone", request.form["git"], os.path.join("skins", str(tool.get_utime()))], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].decode("utf-8"))
@app.route("/admin/sysman/extension")
def manage_extension():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    with open("extensions/list.txt", "r", encoding = "utf-8") as f:
        list = f.read()
    return tool.rt("manage_extension.html", title = "확장 프로그램 관리",
                   extensions = ((x, f"{data.extension_info[x]['version_name']} ({data.extension_commit[x]})", x not in data.extension_git, x not in data.extensions) for x in data.all_extensions),
                   list = list)
@app.route("/admin/sysman/extension/update", methods = ["POST"])
def update_extension():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    extension = request.form["extension"]
    if extension not in data.extension_git:
        return tool.error("존재하지 않거나 git로 다운로드 되지 않은 확장 프로그램입니다.")
    return tool.rt("update_result.html", title = "업데이트 결과", result = subprocess.Popen(["git", "-C", os.path.join("extensions", extension), "pull"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].decode("utf-8"))
@app.route("/admin/sysman/extension/delete", methods = ["POST"])
def delete_extension():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    extension = request.form["extension"]
    if extension not in data.extensions:
        return tool.error("존재하지 않는 확장 프로그램입니다.")
    data.extensions.remove(extension)
    path = os.path.join("extensions", extension)
    for root, dirs, files in os.walk(path):
        for i in dirs:
            os.chmod(os.path.join(root, i), stat.S_IWRITE)
        for i in files:
            os.chmod(os.path.join(root, i), stat.S_IWRITE)
    shutil.rmtree(path)
    return redirect(url_for("restart"))
@app.route("/admin/sysman/extension/install", methods = ["POST"])
def install_extension():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    return tool.rt("update_result.html", title = "설치 결과", result = subprocess.Popen(["git", "clone", request.form["git"], os.path.join("extensions", str(tool.get_utime()))], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].decode("utf-8"))
@app.route("/admin/sysman/extension/list", methods = ["POST"])
def extension_list():
    if not tool.has_perm("developer"):
        abort(403)
    if os.getenv("DISABLE_SYSMAN") == "1":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    with open("extensions/list.txt", "w", encoding="utf-8") as f:
        f.write(request.form["list"].replace("\r\n", "\n").replace("\r", "\n"))
    return redirect(url_for("manage_extension"))
@app.route("/RecentChanges")
def recent_changes():
    type = request.args.get("type", -1, type=int)
    with g.db.cursor() as c:
        return tool.rt("recent_changes.html", title = "최근 변경", recent = 
            ((tool.get_doc_full_name(x[0]), x[1], None if x[2] == 0 and x[7] == "" else f"{escape(x[7])} <i>{escape(history_msg(x[2], x[3], x[4]))}</i>", x[5], tool.time_to_str(x[6])) for x in
            c.execute(f"SELECT doc_id, length, type, content2, content3, author, ? - datetime, edit_comment FROM history{'' if type == -1 else ' WHERE type = ?'} ORDER BY datetime DESC, rev DESC LIMIT 100", (tool.get_utime(),) if type == -1 else (tool.get_utime(),type)).fetchall()), menu2 = [[
            tool.Menu("전체", url_for("recent_changes"), "menu2-selected" if type == -1 else ""),
            tool.Menu("일반", url_for("recent_changes"), "menu2-selected" if type == 0 else ""),
            tool.Menu("새 문서", url_for("recent_changes", type = 1), "menu2-selected" if type == 1 else ""),
            tool.Menu("삭제", url_for("recent_changes", type = 2), "menu2-selected" if type == 2 else ""),
            tool.Menu("이동", url_for("recent_changes", type = 3), "menu2-selected" if type == 3 else ""),
            tool.Menu("되돌림", url_for("recent_changes", type = 5), "menu2-selected" if type == 5 else ""),
            tool.Menu("ACL", url_for("recent_changes", type = 4), "menu2-selected" if type == 4 else ""),
            ]])
@app.route("/RecentDiscuss")
def recent_discuss():
    logtype = request.args.get("logtype", "normal_thread")
    if logtype not in data.allow_recentthread_type:
        return redirect(url_for("recent_discuss"))
    old = logtype == "old_thread"
    if logtype == "normal_thread" or logtype == "old_thread": status = "normal"
    if logtype == "pause_thread": status = "pause"
    if logtype == "closed_thread": status = "close"
    with g.db.cursor() as c:
        return tool.rt("recent_discuss.html", title = "최근 토론", recent =
            ((x[0], tool.get_doc_full_name(x[1]), x[2], x[3], tool.time_to_str(x[4])) for x in
            c.execute("SELECT D.slug, D.doc_id, D.topic, C.author, ? - D.last FROM discuss D JOIN thread_comment C ON (D.slug = C.slug AND D.seq - 1 = C.no) WHERE D.status = ? ORDER BY D.last {0}, C.no {0} LIMIT 100".format("ASC" if old else "DESC"), (tool.get_utime(), status)).fetchall()), menu2 = [[
            tool.Menu("열린 토론", url_for("recent_discuss", logtype = "normal_thread"), "menu2-selected" if logtype == "normal_thread" else ""),
            tool.Menu("오래된 토론", url_for("recent_discuss", logtype = "old_thread"), "menu2-selected" if logtype == "old_thread" else ""),
            tool.Menu("중지된 토론", url_for("recent_discuss", logtype = "pause_thread"), "menu2-selected" if logtype == "pause_thread" else ""),
            tool.Menu("닫힌 토론", url_for("recent_discuss", logtype = "closed_thread"), "menu2-selected" if logtype == "closed_thread" else ""),
        ]])
@app.route("/admin/login_history")
def login_history():
    if not tool.has_perm("login_history"): abort(403)
    with g.db.cursor() as c:
        exp = int(tool.get_config("keep_login_history"))
        if exp == 0:
            return tool.error("이 기능이 비활성화되어 있습니다.")
        if exp != -1:
            c.execute("DELETE FROM login_history WHERE date < ?", (tool.get_utime() - exp,))
        if "user" in request.args:
            user = request.args["user"]
            id = tool.user_name_to_id(user)
            if id == -1:
                return tool.error("invalid_username")
            c.execute("INSERT INTO block_log (type, operator, target, date, note) VALUES(4,?,?,?,?)", (tool.get_user(), id, tool.get_utime(), request.args["note"] if tool.get_config("ext_note") == "1" else ""))
            return tool.rt("login_history_1.html", title = f"{user} 로그인 내역", email = tool.get_user_config(id, "email", "(미설정)"), lh = c.execute("SELECT date, ip, ua, uach FROM login_history WHERE user = ? ORDER BY date DESC", (id,)).fetchall())
        else:
            return tool.rt("login_history.html", title = "로그인 내역", ext_note = tool.get_config("ext_note") == "1")
@app.route("/Upload", methods=['GET','POST'])
def upload():
    if request.method == "POST":
        tool.clean_docid()
        with g.db.cursor() as c:
            if "file" not in request.files: abort(400)
            file = request.files["file"]
            if file.filename == "": abort(400)
            if not tool.has_perm("bypass_image_size_limit"):
                file.seek(0, 2)
                max_size = int(tool.get_config("max_file_size"))
                if file.tell() > max_size:
                    return tool.error(f"파일 최대 용량({max_size} 바이트)을 초과합니다.", 413)
                file.seek(0)
            ns, name = tool.split_ns(request.form["name"])
            if ns not in data.file_namespace:
                return tool.error("invalid_namespace")
            if tool.get_docid(ns, name) != -1:
                return tool.error("이미 해당 이름의 문서가 존재합니다.")
            acl = tool.check_document_acl(-1, ns, "edit", name)
            if acl[0] == 0:
                return tool.error(acl[1], 403)
            ext = os.path.splitext(request.form["name"])[1][1:]
            if ext not in data.allow_file_extension:
                return tool.error(f"{ext} 확장자는 허용되지 않습니다.")
            docid = tool.get_docid(ns, name, True)
            content = f'[include({tool.get_config("image_license")}{request.form["license"]})]\n[[{tool.get_namespace_name(int(tool.get_config("category_namespace")))}:{tool.get_config("file_category")}{request.form["category"]}]]\n{request.form["content"]}'
            c.execute("UPDATE data SET value = ? WHERE id = ?", (content, docid))
            tool.record_history(docid, 1, content, None, None, tool.get_user(), request.form["note"], len(content))
            file.save(os.path.join("file", str(docid)))
            return redirect(url_for("doc_read", doc_title = request.form["name"]))
    temp_docid = tool.get_docid(*tool.split_ns(tool.get_config("image_upload_templete")))
    if temp_docid == -1: templete = ""
    else: templete = tool.get_doc_data(temp_docid)
    if templete is None: templete = ""
    image_license_ns, image_license = tool.split_ns(tool.get_config("image_license"))
    file_category = tool.get_config("file_category")
    with g.db.cursor() as c:
        return tool.rt("upload.html", title = "파일 올리기", dns = tool.get_namespace_name(data.file_namespace[0]), templete = templete,
                       def_license = tool.get_config("default_image_license"), def_category = tool.get_config("default_file_category"),
                   license = (x[0] for x in c.execute("SELECT substr(name, ?) FROM doc_name N JOIN data D ON (N.id = D.id) WHERE namespace = ? AND name LIKE ? AND D.value IS NOT NULL ORDER BY name", (len(image_license) + 1, image_license_ns, image_license + "%")).fetchall()),
                   category = (x[0] for x in c.execute("SELECT substr(name, ?) FROM doc_name N JOIN data D ON (N.id = D.id) WHERE namespace = ? AND name LIKE ? AND D.value IS NOT NULL ORDER BY name", (len(file_category) + 1, int(tool.get_config("category_namespace")), file_category + "%")).fetchall()))
@app.route("/admin/config/namespace", methods = ["GET", "POST"])
def manage_namespace():
    if not tool.has_perm("config"): abort(403)
    with g.db.cursor() as c:
        if request.method == "POST":
            id = int(request.form["id"])
            c.execute("INSERT INTO namespace (id, name) VALUES(?,?)", (id, request.form["name"]))
            tool.init_nsacl(id)
        return tool.rt("manage_namespace.html", title = "이름공간 관리", namespace = c.execute("SELECT id, name FROM namespace").fetchall(), auto_number = c.execute("SELECT max(id) + 1 FROM namespace").fetchone()[0])
@app.route("/admin/config/namespace/reset", methods = ["POST"])
def nsacl_reset():
    if not tool.has_perm("config"): abort(403)
    tool.init_nsacl(int(request.form["ns"]))
    return "", 204
@app.route("/admin/config/namespace/delete", methods = ["POST"])
def delete_namespace():
    if not tool.has_perm("config"): abort(403)
    ns = int(request.form["ns"])
    with g.db.cursor() as c:
        c.execute("DELETE FROM namespace WHERE id = ?", (ns,))
        c.execute("DELETE FROM nsacl WHERE ns_id = ?", (ns,))
    return "", 204
"""@app.route("/admin/config/delete_file")
def delete_file():
    if not tool.has_perm("config"): abort(403)"""
"""@app.route("/admin/grant2", methods = ["GET", "POST"])
def grant2():
    if not tool.has_perm("developer"): abort(403)
    if request.method == "POST":
        if tool.has_user(request.form["user"])
    return tool.rt("grant2.html")"""
@app.route("/contribution/<int:user>/document")
def document_contribution(user):
    type = request.args.get("logtype", -1, int)
    with g.db.cursor() as c:
        if c.execute("SELECT EXISTS (SELECT 1 FROM user WHERE id = ?)", (user,)).fetchone()[0] == 0:
            abort(404)
        name = tool.id_to_user_name(user)
        return tool.rt("document_contribution.html", title = f'"{"<삭제된 사용자>" if name is None else name}" 기여 목록', contribution = [(tool.get_doc_full_name(x[0]), x[1], None if x[2] == 0 and x[6] == "" else f"{x[6]} <i>{escape(history_msg(x[2], x[4], x[5]))}</i>", tool.time_to_str(x[7]), x[8]) for x in
                c.execute(f"SELECT doc_id, rev, type, content, content2, content3, edit_comment, ? - datetime, length FROM history WHERE author = ?{'' if type == -1 else ' AND type = ?'} ORDER BY datetime DESC, rev DESC", (tool.get_utime(), user) if type == -1 else (tool.get_utime(), user, type)).fetchall()], menu2 = [[
                    tool.Menu("문서", url_for("document_contribution", user = user), "menu2-selected"),
                    #tool.Menu("토론", url_for("discuss_contribution", user = user))
                ],
                [
                    tool.Menu("전체", url_for("document_contribution", user = user), "menu2-selected" if type == -1 else ""),
                    tool.Menu("일반", url_for("document_contribution", user = user, logtype = 0), "menu2-selected" if type == 0 else ""),
                    tool.Menu("새 문서", url_for("document_contribution", user = user, logtype = 1), "menu2-selected" if type == 1 else ""),
                    tool.Menu("삭제", url_for("document_contribution", user = user, logtype = 2), "menu2-selected" if type == 2 else ""),
                    tool.Menu("이동", url_for("document_contribution", user = user, logtype = 3), "menu2-selected" if type == 3 else ""),
                    tool.Menu("되돌림", url_for("document_contribution", user = user, logtype = 5), "menu2-selected" if type == 5 else ""),
                    tool.Menu("ACL", url_for("document_contribution", user = user, logtype = 4), "menu2-selected" if type == 4 else ""),
                ]])
@app.route("/contribution/<int:user>/discuss")
def discuss_contribution(user): return "아 아직 안 만듬", 404
@app.route("/contribution/ip/<ip>")
def ip_contribution(ip):
    with g.db.cursor() as c:
        user = c.execute("SELECT id FROM user WHERE name = ? AND isip = 1", (ip,)).fetchone()
        if user is None: abort(404)
        return redirect(url_for("document_contribution", user = user[0]))
@app.route("/google<code>.html")
def google_site_verification(code):
    valid = tool.get_config("google_site_verification")
    if valid == "": abort(404)
    if code != valid: abort(404)
    return f"google-site-verification: google{code}.html"
@app.route("/admin/batch_blind", methods = ["POST"])
def batch_blind():
    if not tool.has_perm("weak_hide_thread_comment"): abort(403)
    type = int(request.form["type"])
    htc = tool.has_perm("hide_thread_comment")
    if type < 0 or type > 2: abort(400)
    if type == 2 and not htc: abort(403)
    slug = int(request.form["slug"])
    comments = request.form["comments"].strip().splitlines()
    user = tool.get_user()
    with g.db.cursor() as c:
        c.execute("BEGIN")
        for i in comments:
            if i.isdecimal():
                if type == 0: c.execute(f"UPDATE thread_comment SET blind = 0, blind_operator = NULL WHERE slug = ? AND no = ?{'' if htc else ' AND blind != 2'}", (slug, int(i)))
                else: c.execute(f"UPDATE thread_comment SET blind = ?, blind_operator = ? WHERE slug = ? AND no = ?{'' if htc else ' AND blind != 2'}", (type, user, slug, int(i)))
            else:
                ma = data.batch_blind_regex.match(i)
                if ma is None:
                    g.db.rollback()
                    return tool.error_400(f"유효하지 않은 값 또는 범위: {i}")
                st = int(ma.group(1))
                en = int(ma.group(2))
                if st > en: st, en = en, st
                if type == 0: c.execute(f"UPDATE thread_comment SET blind = 0, blind_operator = NULL WHERE slug = ? AND no BETWEEN ? AND ?{'' if htc else ' AND blind != 2'}", (slug, st, en))
                else: c.execute(f"UPDATE thread_comment SET blind = ?, blind_operator = ? WHERE slug = ? AND no BETWEEN ? AND ?{'' if htc else ' AND blind != 2'}", (type, user, slug, st, en))
        g.db.commit()
        return "", 204
@app.route("/aclgroup/self_remove")
def self_remove():
    id = request.args.get("id", None)
    if id is None: return tool.error("aclgroup_not_found")
    with g.db.cursor() as c:
        f = c.execute("SELECT gid, ip, user FROM aclgroup_log WHERE id = ?", (id,)).fetchone()
        if f is None: return tool.error("aclgroup_not_found")
        gid, ip, user = f
        if ip is None:
            if not tool.is_login(): return tool.error("aclgroup_not_found")
            user2 = tool.get_user(False)
            if user != user2: return tool.error("aclgroup_not_found")
        else:
            if not tool.ip_in_cidr(tool.getip(), ip): return tool.error("aclgroup_not_found")
        if tool.get_aclgroup_config(gid, "self_removable") == "0": return tool.error("not_self_removable")
        tool.aclgroup_delete(id, tool.get_aclgroup_config(gid, "self_remove_note"), flags_check = False)
        return redirect("/")
@app.route("/member/mypage")
def mypage():
    if not tool.is_login(): return redirect("/")
    with g.db.cursor() as c:
        user = tool.get_user()
        l = len(data.permissions)
        return tool.rt("mypage.html", title="내 정보", user = tool.id_to_user_name(user), use_email = tool.get_config("email_verification_level") != "0",
                       email = tool.get_user_config(user, "email", "(미설정)"), change_name = tool.get_config("change_name_enable") == "1",
                       skins = data.skins, current_skin = tool.get_user_config(user, "skin"),
                       perm = ", ".join(sorted((x[0] for x in c.execute("SELECT perm FROM perm WHERE user = ?", (user,)).fetchall()),
                                               key = lambda x: data.permissions_order.get(x, l))))
@app.route("/member/change_password", methods = ["GET", "POST"])
def change_password():
    if not tool.is_login(): return redirect("/")
    if request.method == "POST":
        user = tool.get_user()
        with g.db.cursor() as c:
            if not tool.check_password(user, request.form["cpw"]):
                return tool.error("패스워드가 올바르지 않습니다.")
            if request.form["pw"] != request.form["pw2"]:
                return tool.error("패스워드 확인이 올바르지 않습니다.")
            c.execute("UPDATE user SET password = ? WHERE id = ?", (tool.hash_password(request.form["pw"]), user))
            return redirect("/")
    return tool.rt("change_password.html", title="비밀번호 변경")
@app.route("/member/change_name", methods = ["GET", "POST"])
def change_name():
    if tool.get_config("change_name_enable") == "0": return tool.error("이름 변경이 비활성화되어 있습니다.", 501)
    if not tool.is_login(): return redirect("/")
    user = tool.get_user()
    cooltime = int(tool.get_user_config(user, "change_name", 0)) + int(tool.get_config("change_name_cooltime"))
    if cooltime <= tool.get_utime():
        cooltime = None
    if request.method == "POST":
        if cooltime is not None:
            return tool.error("최근에 계정을 생성했거나 최근에 이름 변경을 이미 했습니다.", 403)
        for i in data.change_name_block:
            st = tool.user_in_aclgroup(i, user)
            if st:
                return tool.rt("error.html", error=tool.get_aclgroup_deny_message(st, i).format(type="이름 변경", tab=""))
        with g.db.cursor() as c:
            if not tool.check_password(user, request.form["pw"]):
                return tool.error("패스워드가 올바르지 않습니다.")
        name = request.form["name"]
        if tool.has_user(name):
            return tool.error("이미 존재하는 사용자 이름입니다.")
        if tool.is_valid_ip(name) or tool.is_valid_cidr(name):
            return tool.error("IP나 CIDR 형식의 사용자 이름은 사용이 불가능합니다.")
        if data.username_format.fullmatch(name) is None:
            return tool.rt("error.html", error=f'계정명은 정규식 {escape(tool.get_config("username_format"))}을 충족해야 합니다.')  
        tool.change_name(user, name)
        return redirect("/")
    return tool.rt("change_name.html", title = "이름 변경", user = tool.id_to_user_name(user), cooltime = cooltime, cool = tool.time_to_str(int(tool.get_config("change_name_cooltime"))))
@app.route("/member/change_skin", methods = ["POST"])
def change_skin():
    if not tool.is_login(): return redirect("/")
    skin = request.form["skin"]
    if skin == "":
        tool.del_user_config(tool.get_user(), "skin")
        return redirect(url_for("mypage"))
    if skin not in data.skins:
        return tool.error("invalid_skin")
    tool.set_user_config(tool.get_user(), "skin", skin)
    return redirect(url_for("mypage"))
@app.route("/member/withdraw", methods = ["GET", "POST"])
def withdraw():
    if tool.get_config("withdraw_enable") == "0": return tool.error("계정 삭제가 비활성화되어 있습니다.", 501)
    if not tool.is_login(): return redirect("/")
    user = tool.get_user()
    with g.db.cursor() as c:
        withdraw_block = None
        wait = int(tool.get_config("withdraw_cooltime"))
        for gid, value in c.execute("SELECT gid, CAST(value AS INTEGER) FROM aclgroup_config WHERE name = 'withdraw_period' AND value != '0' ORDER BY CASE WHEN value = '-1' THEN 0 ELSE 1 END, CAST(value AS INTEGER) DESC").fetchall():
            st = tool.user_in_aclgroup(gid, user)
            if st:
                if value == -1:
                    withdraw_block = tool.get_aclgroup_deny_message(st, gid).format(type = "계정 삭제", tab = "")
                else:
                    wait = value
                break
        if withdraw_block is None:            
            cooltime = c.execute("SELECT max(r) FROM (SELECT max(datetime) r FROM history WHERE author = ?1 UNION ALL SELECT max(time) r FROM thread_comment WHERE author = ?1)", (user,)).fetchone()[0] + wait
            if cooltime <= tool.get_utime():
                cooltime = None
        else:
            cooltime = None
        if request.method == "POST":
            if cooltime is not None or withdraw_block is not None:
                return tool.error("계정 삭제가 불가능한 상태입니다.", 403)
            if not tool.check_password(user, request.form["pw"]):
                return tool.error("패스워드가 올바르지 않습니다.")
            if request.form["pledgeinput"] != tool.get_string_config("withdraw_pledgeinput"):
                return tool.error("동일하게 입력해주세요.")
            tool.delete_user(user)
            session.clear()
            return redirect("/")
        return tool.rt("withdraw.html", title = "계정 삭제", pledgeinput = tool.get_string_config("withdraw_pledgeinput"), cool = tool.time_to_str(wait), cooltime = cooltime, withdraw_block = withdraw_block)
@app.route("/admin/config/smtp_test", methods = ["GET", "POST"])
def smtp_test():
    if not tool.has_perm("config"): abort(403)
    if request.method == "POST":
        tool.email(request.form["to"], "NewTheSeed SMTP Test", "If this email arrived normally, SMTP is working properly.")
        return redirect(url_for("config"))
    return tool.rt("smtp_test.html", title = "SMTP 테스트", to = os.getenv("SMTP_USER"))
@app.route("/member/change_email", methods = ["GET", "POST"])
def change_email():
    if not tool.is_login(): return redirect("/")
    evm = tool.get_config("email_verification_level")
    if evm == "0": return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    user = tool.get_user()
    if request.method == "POST":
        if not tool.check_password(user, request.form["pw"]):
            return tool.error("패스워드가 올바르지 않습니다.")
        email = request.form["email"]
        if email == "":
            if evm == "3" and not tool.has_perm("bypass_email_verify"):
                return tool.error("이메일의 값은 필수입니다.")
            else:
                tool.del_user_config(user, "email")
                return redirect(url_for("mypage"))
        email = tool.sanitize_email(email)
        if email is None:
            return tool.error("이메일의 값을 형식에 맞게 입력해주세요.")
        if not tool.has_perm("bypass_email_verify") and not tool.check_email_wblist(email):
            return tool.error("이메일 허용 목록에 있는 이메일이 아닙니다." if data.email_wblist_type else "이메일 차단 목록에 있는 이메일입니다.")
        if evm == "1" or tool.has_perm("bypass_email_verify"):
            tool.set_user_config(user, "email", email)
        else:
            token = secrets.token_hex(32)
            wiki_name = tool.get_config("wiki_name")
            ip = tool.getip()
            username = tool.id_to_user_name(user)
            title = tool.get_string_config("email_verification_change_title").format(wiki_name = wiki_name, user = username)
            limit = int(tool.get_config("email_limit"))
            with g.db.cursor() as c:
                if limit != 0 and c.execute("SELECT count(*) FROM user_config WHERE name = 'email' and value = ?", (email,)).fetchone()[0] >= limit:
                    tool.email(email, title, tool.get_string_config("email_verification_change_max").format(wiki_name = wiki_name, max = limit, ip = ip, user = username))
                else:
                    c.execute("INSERT INTO change_email_link (token, user, email, ip, expire) VALUES(?,?,?,?,?)", (token, user, email, ip, tool.get_utime() + 86400))
                    tool.email(email, title, tool.get_string_config("email_verification_change").format(wiki_name = wiki_name, link = url_for("change_email2", user = username, token = token, _external = True), ip = ip, user = username))
        return redirect(url_for("mypage"))
    return tool.rt("change_email.html", title = "이메일 변경", email = tool.get_user_config(user, "email", ""), wblist = tool.show_email_wblist())
@app.route("/member/auth/<user>/<token>")
def change_email2(user, token):
    tool.delete_expired_change_email_link
    with g.db.cursor() as c:
        user1 = tool.user_name_to_id(user)
        f = c.execute("SELECT email, ip FROM change_email_link WHERE token = ? AND user = ?", (token, user1)).fetchone()
        if f is None:
            return tool.error("인증 요청이 만료되었거나 올바르지 않습니다.")
        email, ip = f
        if ip != tool.getip():
            return tool.error("보안 상의 이유로 요청한 아이피 주소와 현재 아이피 주소가 같아야 합니다.")
        tool.set_user_config(user1, "email", email)
        c.execute("DELETE FROM change_email_link WHERE email = ?", (email,))
        return tool.rt("change_email_completed.html", title = "인증 완료", user = user)
@app.route("/skins/<skin>/<path:path>")
def skin_static(skin, path):
    if data.allow_skin_ext_id.fullmatch(skin):
        return send_from_directory(f"skins/{skin}/static", path)
    else:
        abort(404)
@app.route("/skin_config_css/<skin>")
def skin_config_css(skin):
    if skin not in data.skin_config_css:
        abort(404)
    return data.skin_config_css[skin], 200, {"Content-Type": "text/css"}
@app.route("/skin_config_js/<skin>")
def skin_config_js(skin):
    if skin not in data.skin_config_js:
        abort(404)
    return data.skin_config_js[skin], 200, {"Content-Type": "application/javascript"}
@app.route("/revert/<path:doc>", methods = ["GET", "POST"])
def revert(doc):
    ns, name = tool.split_ns(doc)
    docid = tool.get_docid(ns, name)
    if request.method == "POST":
        try:
            tool.revert(docid, int(request.args["rev"]), request.form["note"])
        except (exceptions.DocumentNotExistError, exceptions.RevisionNotExistError):
            return tool.error("해당 리비전이 존재하지 않습니다.")
        except exceptions.CannotRevertRevisionError:
            return tool.error("이 리비전으로 되돌릴 수 없습니다.")
        except exceptions.TrollRevisionError:
            return tool.error("이 리비전은 반달로 표시되었기 때문에 되돌릴 수 없습니다.")
        return redirect(url_for("doc_read", doc_title = doc))
    acl = tool.check_document_acl(docid, ns, "edit", name)
    if acl[0] == 0:
        return tool.error(acl[1], 403)
    rev = int(request.args["rev"])
    with g.db.cursor() as c:
        f = c.execute("SELECT type, content, troll FROM history WHERE doc_id = ? AND rev = ?", (docid, rev)).fetchone()
        if f is None:
            return tool.error("해당 리비전이 존재하지 않습니다.")
        type, content, troll = f
        if type not in data.revert_available:
            return tool.error("이 리비전으로 되돌릴 수 없습니다.")
        if troll != -1:
            return tool.error("이 리비전은 반달로 표시되었기 때문에 되돌릴 수 없습니다.")
        return tool.rt("revert.html", title = tool.render_docname(ns, name), subtitle = f"r{rev}로 되돌리기", content = content)
@app.route("/member/api_token", methods = ["GET", "POST"])
def api_token():
    if not tool.is_login(): return redirect("/")
    if request.method == "POST":
        user = tool.get_user()
        if not tool.check_password(user, request.form["pw"]):
            return tool.error("패스워드가 올바르지 않습니다.")
        token = base64.b64encode(secrets.token_bytes(128))
        tool.set_user_config(user, "api_token", hashlib.sha3_512(token).hexdigest())
        return tool.rt("api_token_2.html", title = "API Token 발급", token = token.decode("ascii"))
    return tool.rt("api_token.html", title = "API Token 발급")
@app.route("/api/edit/<path:document>", methods = ["GET", "POST", "KOREA"])
def api_edit(document):
    user = tool.check_api_token()
    if user is None:
        return data.json_403
    ns, name = tool.split_ns(document)
    docid = tool.get_docid(ns, name)
    if request.method == "POST":
        json = request.get_json()
        acl = tool.check_document_acl(docid, ns, "edit", name, user)
        if acl[0] == 0:
            return {"status": acl[1]}, 403
        try:
            if docid == -1:
                rev = tool.edit_or_new(ns, name, json["text"], json.get("log", ""), user)
            else:
                rev = tool.edit(docid, json["text"], json.get("log", ""), user)
        except exceptions.ACLDeniedError as e:
            return {"status": str(e)}, 403
        except exceptions.DocumentContentEqualError:
            return {"status": "문서 내용이 같습니다."}, 409
        return {"status": "success", "rev": rev}
    acl = tool.check_document_acl(docid, ns, "read", name, user)
    if acl[0] == 0:
        return {"status": acl[1]}, 403
    doc_data = tool.get_doc_data(docid, request.args.get("rev", None, int))
    return {
        "text": doc_data,
        "exists": doc_data is not None
    }
@app.route("/api/aclgroup", methods = ["GET", "POST", "DELETE"])
def api_aclgroup():
    user = tool.check_api_token()
    if user is None:
        return data.json_403
    with g.db.cursor() as c:
        if request.method == "GET":
            gid = int(request.args["group"])
            if not tool.has_aclgroup(gid):
                return {"status": "aclgroup_group_not_found"}, 400
            if not tool.check_aclgroup_flag(gid, "access_flags", user):
                return data.json_403
            r = []
            for i in c.execute("SELECT id, ip, user, note, start, end FROM aclgroup_log WHERE gid = ?", (gid,)).fetchall():
                r.append({"id": i[0], "mode": "user" if i[1] is None else "ip", "user": i[2] if i[1] is None else i[1], "note": i[3], "start": i[4], "end": i[5]})
            return {"status": "success", "result": r}
        elif request.method == "POST":
            json = request.get_json()
            #(gid: Any, mode: Any, user: Any, note: str = "", duration: int = 0, operator: Any | None = None, log: bool = True, note_required_check: bool = True, max_duration_check: bool = True, max_cidr_check: bool = True, flags_check: bool = True) -> None
            if not tool.check_json(json, {"group": (int, True), "mode": (str, True), "note": (str, False), "duration": (int, False)}):
                return {}, 400
            if "user" not in json:
                return {}, 400
            if json["mode"] == "ip":
                if not isinstance(json["user"], str): return {}, 400
            elif json["mode"] == "user":
                if not isinstance(json["user"], int): return {}, 400
            else:
                return {}, 400
            try:
                return {"status": "success", "id": tool.aclgroup_insert(json["group"], json["mode"], json["user"], json.get("note", ""), json.get("duration", 0), user)}, 201
            except exceptions.ACLGroupPermissionDeniedError:
                return data.json_403
            except exceptions.ACLGroupConfigError as e:
                return {"status": f"{e.name}은 {e.value}입니다."}, 400
            except exceptions.ACLGroupNoteRequiredError:
                return {"status": "note의 값은 필수입니다."}, 400
            except exceptions.ACLGroupAlreadyExistsError:
                return {"status": "aclgroup_already_exists"}, 400
            except exceptions.InvalidCIDRError:
                return {"status": "invalid_cidr"}, 400
            except exceptions.MaximumTimeExceedError:
                return {"status": "maximum_time_exceed"}, 400
            except exceptions.InvalidUserError:
                return {"status": "invalid_user"}, 400
            except exceptions.ACLGroupNotExistsError:
                return {"status": "aclgroup_group_not_found"}, 400
            except ValueError:
                return {}, 400
        elif request.method == "DELETE":
            json = request.get_json()
            print(user)
            if not tool.check_json(json, {"id": (int, True), "note": (str, False)}):
                return {}, 400
            try:
                tool.aclgroup_delete(json["id"], json.get("note", ""), user)
            except exceptions.ACLGroupPermissionDeniedError:
                return data.json_403
            except exceptions.ACLGroupElementNotExistsError:
                return {"status": "aclgroup_not_found"}, 400
            except exceptions.NoteRequiredError:
                return {"status": "note의 값은 필수입니다."}, 400
            return {"status": "success"}
@app.route("/api/user_id_to_name")
def api_user_id_to_name():
    if "id" not in request.args:
        return "", 400, {"Content-Type": "text/plain"}
    try:
        r = tool.id_to_user_name(int(request.args["id"]))
    except ValueError:
        return "", 400, {"Content-Type": "text/plain"}
    if r is None:
        return "", 404, {"Content-Type": "text/plain"}
    return r, 200, {"Content-Type": "text/plain"}
@app.route("/api/user_name_to_id")
def api_user_name_to_id():
    if "name" not in request.args:
        return "", 400, {"Content-Type": "text/plain"}
    r = tool.user_name_to_id(request.args["name"])
    if r == -1:
        return "-1", 404, {"Content-Type": "text/plain"}
    return str(r), 200, {"Content-Type": "text/plain"}
@app.route("/api/doc_name_to_id")
def api_doc_name_to_id():
    if "name" not in request.args:
        return "", 400, {"Content-Type": "text/plain"}
    r = tool.get_docid(*tool.split_ns(request.args["name"]))
    if r == -1:
        return "-1", 404, {"Content-Type": "text/plain"}
    return str(r), 200, {"Content-Type": "text/plain"}
@app.route("/api/doc_id_to_name")
def api_doc_id_to_name():
    if "id" not in request.args:
        return "", 400, {"Content-Type": "text/plain"}
    try:
        r = tool.get_doc_full_name(int(request.args["id"]))
    except ValueError:
        return "", 400, {"Content-Type": "text/plain"}
    if r is None:
        return "", 404, {"Content-Type": "text/plain"}
    return str(r), 200, {"Content-Type": "text/plain"}
@app.route("/api/recent_changes")
def api_recent_changes():
    type = request.args.get("type", -1, type=int)
    limit = request.args.get("limit", 10, type=int)
    time = request.args.get("time", None, type=int)
    with g.db.cursor() as c:
        if time is None:
            c.execute(f"SELECT doc_id, rev, type, content2, content3, author, edit_comment, datetime, length FROM history{'' if type == -1 else ' WHERE type = ?'} ORDER BY datetime DESC LIMIT ?", (limit,) if type == -1 else (type, limit))
        else:
            c.execute(f"SELECT doc_id, rev, type, content2, content3, author, edit_comment, datetime, length FROM history WHERE datetime > ?{'' if type == -1 else ' AND type = ?'} ORDER BY datetime DESC", (time,) if type == -1 else (time, type))
        return [{"doc": x[0], "rev": x[1], "type": x[2], "content2": x[3], "content3": x[4], "author": x[5], "log": x[6], "time": x[7], "length": x[8]} for x in c.fetchall()]
@app.route("/api/recent_discuss")
def api_recent_discuss():
    logtype = request.args.get("logtype", "normal_thread")
    limit = request.args.get("limit", 10, type=int)
    time = request.args.get("time", None, type=int)
    if logtype not in data.allow_recentthread_type:
        return [], 400
    old = logtype == "old_thread"
    if logtype == "normal_thread" or logtype == "old_thread": status = "normal"
    if logtype == "pause_thread": status = "pause"
    if logtype == "closed_thread": status = "close"
    with g.db.cursor() as c:
        if time is None:
            c.execute("SELECT D.slug, D.doc_id, D.topic, C.author, D.last FROM discuss D JOIN thread_comment C ON (D.slug = C.slug AND D.seq - 1 = C.no) WHERE D.status = ? ORDER BY D.last {0}, C.no {0} LIMIT ?".format("ASC" if old else "DESC"), (status, limit))
        else:
            c.execute("SELECT D.slug, D.doc_id, D.topic, C.author, D.last FROM discuss D JOIN thread_comment C ON (D.slug = C.slug AND D.seq - 1 = C.no) WHERE D.last {0} ? AND D.status = ? ORDER BY D.last {1}, C.no {1}".format("<" if old else ">", "ASC" if old else "DESC"), (time, status))
        return [{"slug": x[0], "doc": x[1], "topic": x[2], "author": x[3], "last": x[4]} for x in c.fetchall()]
@app.route("/api/thread_comment")
def api_thread_comment():
    user = tool.check_api_token()
    if user is None:
        return data.json_403
    slug = request.args.get("slug", type=int)
    if slug is None:
        return {}, 400
    no = request.args.get("no", 1, type=int)
    with g.db.cursor() as c:
        f = c.execute("SELECT namespace, name, doc_id FROM discuss JOIN doc_name ON (doc_id = id) WHERE slug = ?", (slug,)).fetchone()
        if f is None:
            return {"status": "thread_not_found"}, 404
        ns, name, docid = f
        acl = tool.check_document_acl(docid, ns, "read", name, user)
        if acl[0] == 0:
            return {"status": acl[1]}, 403
        f = c.execute("SELECT type, text, text2, author, time, blind, blind_operator, admin FROM thread_comment WHERE slug = ? AND no = ?", (slug, no)).fetchone()
        if f is None:
            return {"status": "thread_comment_not_found"}, 404
        blind = f[5] == 2 and not tool.has_perm("hide_thread_comment", user)
        return {"status": "blind" if blind else "success", "type": -1 if blind else f[0], "text": None if blind else f[1], "text2": None if blind else f[2], "author": f[3], "time": f[4], "blind": f[5], "blind_operator": f[6], "admin": f[7]}
@app.route("/api/login")
def api_login():
    user = tool.check_api_token()
    if user is None:
        return data.json_403
    session["id"] = user
    session["api"] = True
    tool.add_login_history()
    return {"status": "success"}
@app.route("/api/all_document")
def api_all_document():
    namespaces = request.args.get("namespaces", None)
    if namespaces == "" or namespaces == "-":
        namespaces = None
    with g.db.cursor() as c:
        if namespaces is None:
            p = c.execute("SELECT N.namespace, N.name FROM doc_name N JOIN data D ON (N.id = D.id) WHERE D.value IS NOT NULL").fetchall()
        else:
            if namespaces[0] == "-":
                black = True
                namespaces = namespaces[1:]
            else:
                black = False
            ns = []
            for i,v in enumerate(namespaces.split(",")):
                v2 = tool.ns_name_to_id(v)
                if v2 is None:
                    return {"status": f'{v} 이름공간은 존재하지 않습니다.'}, 400
                ns.append(v2)
            p = c.execute(f"SELECT N.namespace, N.name FROM doc_name N JOIN data D ON (N.id = D.id) WHERE D.value IS NOT NULL AND N.namespace{' NOT' if black else ''} IN ({','.join('?' * len(ns))})", ns).fetchall()
    r = []
    for i in p:
        r.append(tool.cat_namespace(*i))
    return r
@app.route("/admin/manage_account")
def manage_account():
    if not tool.has_perm("manage_account"):
        abort(403)
    uid = request.args.get("uid", None, type=int)
    if uid is None:
        return tool.rt("manage_account.html", title = "계정 관리")
    if not tool.has_user_id(uid):
        return tool.rt("manage_account.html", title = "계정 관리", error = "존재하지 않는 사용자입니다.")
    if tool.isip(uid):
        return tool.rt("manage_account.html", title = "계정 관리", error = "IP 사용자입니다.")
    name = tool.id_to_user_name(uid)
    if name is None:
        return tool.rt("manage_account.html", title = "계정 관리", error = "삭제된 사용자입니다.")
    return tool.rt("manage_account.html", title = "계정 관리", user2 = name, uid2 = uid, validuser = True, email = tool.get_user_config(uid, "email", ""))
@app.route("/admin/manage_account/change_email", methods = ["POST"])
def manage_account_change_email():
    email = request.form["email"]
    if email == "":
        tool.del_user_config(int(request.form["uid"]), "email")
    else:
        tool.set_user_config(int(request.form["uid"]), "email", email)
    return "", 204
@app.route("/admin/manage_account/change_name", methods = ["POST"])
def manage_account_change_name():
    if not tool.has_perm("manage_account"):
        abort(403)
    name = request.form["name"]
    if tool.has_user(name, True):
        return tool.error_400("이미 존재하는 사용자 이름입니다.")
    tool.change_name(int(request.form["uid"]), name)
    return "", 204
@app.route("/admin/manage_account/withdraw", methods = ["POST"])
def manage_account_withdraw():
    if not tool.has_perm("manage_account"):
        abort(403)
    tool.delete_user(int(request.form["uid"]))
    return "", 204
@app.route("/admin/manage_account/unlock_change_name_cooltime", methods = ["POST"])
def manage_account_unlock_change_name_cooltime():
    if not tool.has_perm("manage_account"):
        abort(403)
    tool.del_user_config(int(request.form["uid"]), "change_name")
    return "", 204
@app.route("/admin/manage_account/get_recover_password_link/<uid>", methods = ["POST"])
def manage_account_get_recover_password_link(uid):
    if not tool.has_perm("manage_account"):
        abort(403)
    if not tool.has_user_id(uid): return tool.error_400("계정이 존재하지 않습니다.")
    if tool.isip(uid) == 1: return tool.error_400("IP 계정입니다.")
    token = secrets.token_hex(32)
    with g.db.cursor() as c:
        c.execute("INSERT INTO recover_password_link (token, user, expire) VALUES(?,?,?)", (token, uid, tool.get_utime() + 86400))
    return url_for("recover_password2", user = tool.id_to_user_name(uid), token = token, _external = True)
"""@app.route("/admin/manage_account/unlock_withdraw_cooltime", methods = ["POST"])
def manage_account_unlock_withdraw_cooltime():
    if not tool.has_perm("manage_account"):
        abort(403)"""
@app.route("/member/recover_password", methods = ["GET", "POST"])
def recover_password():
    if tool.get_config("email_verification_level") == "0":
        return tool.error("이 기능이 비활성화되어 있습니다.", 501)
    if request.method == "POST":
        with g.db.cursor() as c:
            email = request.form["email"]
            f = c.execute("SELECT user FROM user_config WHERE name = 'email' and value = ?", (email,)).fetchone()
            if f is not None:
                user = f[0]
                token = secrets.token_hex(32)
                wiki_name = tool.get_config("wiki_name")
                ip = tool.getip()
                username = tool.id_to_user_name(user)
                title = tool.get_string_config("email_verification_recover_password_title").format(wiki_name = wiki_name, user = username)
                c.execute("INSERT INTO recover_password_link (token, user, ip, expire) VALUES(?,?,?,?)", (token, user, ip, tool.get_utime() + 86400))
                tool.email(email, title, tool.get_string_config("email_verification_recover_password").format(wiki_name = wiki_name, link = url_for("recover_password2", user = username, token = token, _external = True), ip = ip, user = username))
        return tool.rt("recover_password_email.html", title = "계정 찾기", email = email)
    return tool.rt("recover_password.html", title = "계정 찾기")
@app.route("/member/recover_password/auth/<user>/<token>", methods = ["GET", "POST"])
def recover_password2(user, token):
    tool.delete_expired_recover_password_link()
    with g.db.cursor() as c:
        user1 = tool.user_name_to_id(user)
        f = c.execute("SELECT ip FROM recover_password_link WHERE token = ? AND user = ?", (token, user1)).fetchone()
        if f is None:
            return tool.error("인증 요청이 만료되었거나 올바르지 않습니다.")
        ip = f[0]
        if ip is not None and ip != tool.getip():
            return tool.error("보안 상의 이유로 요청한 아이피 주소와 현재 아이피 주소가 같아야 합니다.")
        if request.method == "POST":
            if request.form["pw"] != request.form["pw2"]:
                return tool.error("패스워드 확인이 올바르지 않습니다.")
            c.execute("UPDATE user SET password = ? WHERE id = ?", (tool.hash_password(request.form["pw"]), user))
            c.execute("DELETE FROM recover_password_link WHERE token = ?", (token,))
            return redirect(url_for("login"))
        return tool.rt("recover_password2.html", title = "계정 찾기")
@app.route("/admin/batch_revert", methods = ["GET", "POST"])
def batch_revert():
    if not tool.has_perm("batch_revert"):
        abort(403)
    if request.method == "POST":
        uid = request.form.get("uid", type=int)
        duration = request.form.get("duration", type=int)
        reason = request.form.get("reason", "")
        weak_hide_thread_comment = "weak_hide_thread_comment" in request.form and tool.has_perm("weak_hide_thread_comment")
        hide_thread_comment = "hide_thread_comment" in request.form and tool.has_perm("hide_thread_comment")
        if hide_thread_comment: weak_hide_thread_comment = False
        close_thread = "close_thread" in request.form and tool.has_perm("update_thread_status")
        edit_revert = "edit_revert" in request.form
        mark_troll_revision = "mark_troll_revision" in request.form and tool.has_perm("mark_troll_revision")
        fails = []
        operator = tool.get_user()
        time = tool.get_utime()
        timelimit = time - duration
        result = [0,0,0,0]
        with g.db.cursor() as c:
            if weak_hide_thread_comment:
                c.execute("UPDATE thread_comment SET blind = 1, blind_operator = ? WHERE author = ? AND blind = 0 AND time >= ?", (operator, uid, timelimit))
                result[0] = c.rowcount
            if hide_thread_comment:
                c.execute("UPDATE thread_comment SET blind = 2, blind_operator = ? WHERE author = ? AND blind <= 1 AND time >= ?", (operator, uid, timelimit))
                result[0] = c.rowcount
            if close_thread:
                for s,d in c.execute("SELECT T.slug, D.doc_id FROM thread_comment T JOIN discuss D on (T.slug = D.slug) WHERE no = 1 AND author = ? AND time >= ?", (uid, timelimit)).fetchall():
                    acl = tool.check_document_acl2(d, "read")
                    if acl[0] == 0:
                        fails.append(f"토론 {s}: {acl[1]}")
                    else:
                        c.execute("UPDATE discuss SET status = 'close' WHERE slug = ?", (s,))
                        tool.write_thread_comment(s, 1, "close")
                        result[1] += 1
            user_namespace = int(tool.get_config("user_namespace"))
            if edit_revert:
                for d, in c.execute("SELECT DISTINCT doc_id FROM history WHERE author = ? AND datetime >= ?", (uid, timelimit)).fetchall():
                    ns, name2 = tool.get_doc_full_name(d)
                    if ns == user_namespace:
                        continue
                    name = tool.cat_namespace(ns, name2)
                    rev = c.execute("SELECT max(rev) FROM history WHERE doc_id = ? AND (datetime < ? OR author != ?) AND type IN (0,1,2,5) AND troll = -1", (d, timelimit, uid)).fetchone()[0]
                    try:
                        if rev is None or c.execute("SELECT type FROM history WHERE doc_id = ? AND rev = ?", (d, rev)).fetchone()[0] == 2:
                            tool.delete(d, reason)
                        else:
                            tool.revert(d, rev, reason)
                    except exceptions.ACLDeniedError as e:
                        fails.append(f"{name}: {e}")
                    except exceptions.DocumentNotExistError:
                        fails.append(f"{name}: 문서를 찾을 수 없습니다.")
                    except exceptions.RevisionNotExistError:
                        fails.append(f"{name}: 해당 리비전이 존재하지 않습니다.")
                    except exceptions.CannotRevertRevisionError:
                        fails.append(f"{name}: 이 리비전으로 되돌릴 수 없습니다.")
                    except exceptions.TrollRevisionError:
                        fails.append(f"{name}: 이 리비전은 반달로 표시되었기 때문에 되돌릴 수 없습니다.")
                    except exceptions.RevisionNotExistError:
                        fails.append(f"{name}: 존재하지 않는 리비전입니다.")
                    except exceptions.RevisionNotExistError:
                        fails.append(f"{name}: 존재하지 않는 리비전입니다.")
                    except exceptions.DocumentContentEqualError:
                        fails.append(f"{name}: 문서 내용이 같습니다.")
                    result[2] += 1
            if mark_troll_revision:
                c.execute("UPDATE history SET troll = ? WHERE author = ? AND datetime >= ? AND troll = -1", (operator, uid, timelimit))
                result[3] = c.rowcount
            c.execute("INSERT INTO block_log (type, operator, target, date, note) VALUES(5,?,?,?,?)", (operator, uid, tool.get_utime(), request.form["reason"]))
        return tool.rt("batch_revert.html", title = "일괄 되돌리기", result = result, fails = fails)
    return tool.rt("batch_revert.html", title = "일괄 되돌리기")
@app.route("/admin/mark_troll_revision/<path:doc>", methods = ["POST"])
def mark_troll_revision(doc):
    if not tool.has_perm("mark_troll_revision"):
        abort(403)
    with g.db.cursor() as c:
        c.execute("UPDATE history SET troll = ? WHERE doc_id = ? AND rev = ?", (tool.get_user(), tool.get_docid(*tool.split_ns(doc)), request.args.get("rev", type=int)))
    return "", 204
@app.route("/admin/unmark_troll_revision/<path:doc>", methods = ["POST"])
def unmark_troll_revision(doc):
    if not tool.has_perm("mark_troll_revision"):
        abort(403)
    with g.db.cursor() as c:
        c.execute("UPDATE history SET troll = -1 WHERE doc_id = ? AND rev = ?", (tool.get_docid(*tool.split_ns(doc)), request.args.get("rev", type=int)))
    return "", 204
hooks.Start4()
if __name__ == "__main__":
    DEBUG = os.getenv("DEBUG") == "1"
    if DEBUG:
        @app.before_request
        def clear_template_cache():
            app.jinja_env.cache.clear()
    app.run(debug=DEBUG, host=os.getenv("HOST"), port=int(os.getenv("PORT")))
