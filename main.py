import secrets
import mimetypes
import hashlib
import sys
import datetime
import types
import os
import shutil

from flask import Flask, request, redirect, session, send_file, abort, Response, url_for, g
from jinja2 import ChoiceLoader, FileSystemLoader
from git import Repo
from markupsafe import escape, Markup
import dotenv

import data
import tool
from render import render_set

# Development Server Config
HOST = "0.0.0.0"
PORT = 3000
DEBUG = True

if sys.version_info < (3, 9):
    if input("경고! NewTheSeed는 Python 3.9 미만의 Python 버전은 지원하지 않으며, 이로 인해 발생하는 버그(보안취약점 포함)는 수정되지 않습니다. 계속하려면 y를 입력해주세요. -> ") != "y":
        sys.exit()

# 초기 설정

try:
    repo = Repo(".", search_parent_directories=False)
except:
    repo = None
if repo is None:
    commit_id = "0000000"
else:
    commit_id = repo.commit().hexsha[:7]
if not os.path.exists(".env"):
    shutil.copy(".env.example", ".env")
dotenv.load_dotenv()
app = Flask(__name__)
with app.app_context():
    g.db = tool.getdb()
    tool.run_sqlscript("db_stu.sql") # DB 구조 만들기
    with g.db.cursor() as c:
        for k in data.default_config:
            if c.execute("select exists (select 1 from config where name = ?)", (k,)).fetchone()[0] == 0:
                c.execute('insert into config values(?, ?)', (k, data.default_config[k]() if isinstance(data.default_config[k], types.FunctionType) else data.default_config[k]))
        print(f"NewTheSeed [Version {data.version}]")
        print("(c) 1392-github, 2023-2025, MIT License")
        c.execute("UPDATE config SET name = 'version' WHERE name = 'majorversion'")
        c.execute("DELETE FROM config WHERE name = 'minorversion'")
        db_version = int(c.execute('''select value
        from config
        where name = "version"''').fetchone()[0])
        print(f"DB Version : {db_version}")
        if db_version > data.version:
            print("경고 : 상위 버전 NewTheSeed의 DB입니다")
            print("DB 손상 위험이 있을 수도 있습니다")
            if input("그래도 계속 진행하려면 Y를 입력해주세요 -> ") != "Y":
                sys.exit(0)

        # DB 변환 코드
        if db_version < 6:
            # discuss_seq 컬럼 추가
            c.execute("alter table doc_name add discuss_seq INTEGER")
        if db_version < 8:
            # discuss_seq 컬럼의 데이터 타입 오류 수정
            c.executescript('''alter table doc_name drop column discuss_seq;
                            alter table doc_name add column discuss_seq INTEGER;''')
            # config에 get_api_key 추가
            c.execute("insert into config values('get_api_key', 'disabled')")
        if db_version < 10:
            # ban, reason 컬럼 추가
            c.executescript('''alter table user add ban INTEGER;
        alter table user add reason TEXT;
        update user set ban=0;''')
        if db_version < 16:
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
        if db_version < 16 or tool.init:
            c.execute("INSERT INTO aclgroup (name) VALUES('차단된 사용자')")
        if db_version < 17:
            # owner 설정 삭제 및 권한 시스템으로 대체
            c.execute("DELETE FROM config WHERE name = 'owner'")
        if db_version < 19:
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
        if db_version < 19 or tool.init:
            # 기본 이름공간 및 ACL 생성
            tool.run_sqlscript("default_namespace.sql")
        if db_version < 22:
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
        if db_version < 27:
            # secret key 저장위치 변경
            dotenv.set_key(".env", "SECRET_KEY", tool.get_config("secret_key"))
            c.execute("DELETE FROM config WHERE name = 'secret_key'")
            # admin 컬럼 추가
            c.execute("ALTER TABLE thread_comment ADD COLUMN admin INTEGER NOT NULL DEFAULT 0")
            c.execute("UPDATE thread_comment SET admin = (SELECT EXISTS (SELECT 1 FROM perm WHERE user = author AND perm IN ('admin', 'developer')))")
        if db_version < 31:
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
        if db_version < 34:
            # file 테이블 삭제
            c.execute("DROP TABLE file")
        c.execute('''update config
        set value = ?
        where name = "version"''', (str(data.version),)) # 변환 후 버전 재설정
        """c.execute('''update config
        set value = ?
        where name = "minorversion"''', (str(version[1]),))""" # 일단 철회
    tool.reload_config(app)
    g.db.close()
if not os.getenv("SECRET_KEY"):
    key = secrets.token_hex(32)
    dotenv.set_key(".env", "SECRET_KEY", secrets.token_hex(32))
    app.secret_key = key
else:
    app.secret_key = os.getenv("SECRET_KEY")

@app.errorhandler(403)
def errorhandler_403(e):
    return tool.rt("error.html", error="권한이 부족합니다."), 403
@app.errorhandler(404)
def errorhandler_404(e):
    return tool.rt("404.html"), 404
@app.before_request
def before_request():
    g.db = tool.getdb()
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
        b = not tool.isip(user)
    elif bold == 1:
        b = True
    elif bold == 2:
        b = False
    return Markup(f'{"<b>" if b else ""}<a href="{url_for("doc_read", doc_title = tool.id_to_ns_name(int(tool.get_config("user_namespace"))) + ":" + name)}">{escape(name)}</a>{"</b>" if b else ""}')
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
app.jinja_loader = ChoiceLoader([
    FileSystemLoader("skins"),
    FileSystemLoader("templates")
])
app.jinja_env.globals["has_perm"] = tool.has_perm
app.jinja_env.globals["history_msg"] = history_msg
app.jinja_env.filters["user"] = render_username
app.jinja_env.filters["time"] = tool.utime_to_str
# 초기화 부분 끝, API 부분 시작
"""@app.route("/api/read_doc", methods=['POST'])
def api_read_doc():
    t = tool.key_req('read_doc', request.json.get('key', None))
    if t is None:
        abort(403)
    try:
        d = c.execute('''select content
from history
where doc_id = (
select id
from doc_name
where name = ?
and type = 0
)
group by doc_id
having rev = max(rev)''', (request.json['name'],)).fetchone()[0]
    except:
        return {'content':None}
    return {'content':d}
@app.route("/api/edit_doc", methods=['POST'])
def api_edit_doc():
    if 'id' in session:
        i = session['id']
    else:
        i = tool.ipuser()
    doc_name = request.json["name"]
    value = request.json["value"]
    
    try:
        prev_content = c.execute('''select content
from history
where doc_id = (
	select id
	from doc_name
	where name = ?
)
group by doc_id
having rev = max(rev)''', (doc_name,)).fetchone()[0]
    except:
        prev_content = ""
    i = tool.key_req('write_doc', request.json.get('key', None))
    if i is None:
        abort(403)
    tool.run_sqlscript("doc_edit.sql", (doc_name, value, 0, i, request.json.get('edit_comment', None), str(datetime.datetime.now()), len(value) - len(prev_content)))
    return {}
@app.route("/api/randompage", methods=['POST'])
def api_randompage():
    if tool.key_req('randompage', request.json.get('key', None)) is None:
        abort(403)
    c.execute('select name from doc_name order by random() limit 1')
    r = c.fetchone()[0]
    return {'name':r}"""
@app.route("/api/preview", methods=["POST"])
def api_preview():
    json = request.json
    r = render_set(g.db, json["name"], json["data"], "api_view")
    return {"html": r[0], "js": r[1]}
@app.route("/api/preview/thread", methods=["POST"])
def api_thread():
    json = request.json
    r = render_set(g.db, json["data"], "api_thread")
    return {"html": r[0], "js": r[1]}
# API 부분 끝, 주 페이지 시작
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
            return tool.rt("no_document.html", title=tool.render_docname(ns, name), raw_doc_title=doc_title, menu=menu), 404
        d = d[0]
        if "noredirect" not in request.args:
            re = data.redirect_regex.fullmatch(d)
            if re:
                return redirect(url_for("doc_read", doc_title = re.group(1), **{"from": doc_title}))
        d = render_set(g.db, doc_title, d)
        if "/" not in name and ns == int(tool.get_config("user_namespace")):
            admin_userdoc = tool.has_perm("admin", tool.user_name_to_id(name))
        else:
            admin_userdoc = False
        return tool.rt("document_read.html", admin_userdoc = admin_userdoc, title=tool.render_docname(ns, name), raw_doc_title=doc_title,
                       doc_data=d, menu=menu, fr=request.args.get("from", None), image = ns in data.file_namespace, docid = docid
                       ), 200, {} if rev is None else {"X-Robots-Tag": "noindex"}
@app.route("/raw/<path:doc_title>")
def doc_raw(doc_title):
    with g.db.cursor() as c:
        ns, name = tool.split_ns(doc_title)
        docid = tool.get_docid(ns, name)
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return tool.rt("error.html", error = acl[1]), 403
        rev = request.args.get('rev')
        if rev is None:
            d = c.execute("SELECT value FROM data WHERE id = ?", (docid,)).fetchone()
        else:
            d = c.execute("SELECT content FROM history WHERE doc_id = ? AND rev = ?", (docid, rev)).fetchone()
        if d is None or d[0] is None:
            return tool.rt("error.html", error="문서를 찾을 수 없습니다."), 404
        return tool.rt("document_raw.html", doc_title=tool.render_docname(ns, name), raw_doc_title=doc_title, doc_data=d[0]), 200, {} if rev is None else {"X-Robots-Tag": "noindex"}
@app.route("/edit/<path:doc_title>")
def doc_edit(doc_title):
    with g.db.cursor() as c:
        ns, name = tool.split_ns(doc_title)
        docid = tool.get_docid(ns, name)
        if 'id' in session:
            i = session['id']
        else:
            i = tool.ipuser()
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            return tool.rt("error.html", error = acl[1]), 403
        acl = tool.check_document_acl(docid, ns, "edit", name)
        d = c.execute("select value from data where id = ?", (docid,)).fetchone()
        d = "" if d is None else d[0]
        if d is None: d = ""
        r = c.execute("select history_seq - 1 from doc_name where id = ?", (docid,)).fetchone()
        r = 0 if r is None else r[0]
        return tool.rt("document_edit.html", title=tool.render_docname(ns, name), subtitle="새 문서 생성" if r == 0 else f"r{r} 편집", raw_doc_title=doc_title, doc_data=d, doc_rev=r, req_captcha = tool.is_required_captcha("edit"), aclmsg = acl[1], menu = [
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
        docid = tool.get_docid(ns, name)
        if tool.check_document_acl(docid, ns, "edit", name)[0] == 0:
            abort(403)
        if docid == -1:
            if ns in data.file_namespace or ("/" not in name and ns == int(tool.get_config("user_namespace"))):
                return tool.rt("error.html", error = "invalid_namespace")
            docid = tool.get_docid(ns, name, True)
        prev_content = c.execute("SELECT value FROM data WHERE id = ?", (docid,)).fetchone()
        new_document = prev_content is None
        prev_content = "" if new_document else prev_content[0]
        if prev_content is None:
            new_document = True
            prev_content = ""
        tool.record_history(docid, int(new_document), value, None, None, tool.ipuser(), request.form["edit_comment"], len(value) - len(prev_content))
        c.execute("UPDATE data SET value = ? WHERE id = ?", (value, docid))
        return redirect(f"/w/{doc_name}")
@app.route("/license")
def license():
    update = int(os.path.getmtime("data.py"))
    return tool.rt("license.html", title = "라이선스", engine_commit = commit_id, update = update, before = tool.time_to_str(tool.get_utime() - update))
"""@app.route("/admin/config")
def owner_settings():
    if not tool.has_perm("config"):
        abort(403)
    config = c.execute('''select value
from (
select name, value
from config
where name = "host"
or name = "port"
or name = "owner"
or name = "debug"
or name = "get_api_key"
order by name)''').fetchall()
    
    keys = []
    for i in keyl:
        a = c.execute('''select value
from api_policy
where name = ?''', (keyl[i],)).fetchone()
        try:
            keys.append([i, keyl[i], a[0]])
        except:
            keys.append([i, keyl[i], 2])
    return tool.rt("config.html",
                           wiki_host = config[2][0], wiki_port = config[4][0], wiki_owner = config[3][0], debug = config[0][0]=='1', token = config[1][0],
              keys = keys)
@app.route("/owner_settings_form", methods = ['POST'])
def owner_settings_save():
    if not tool.has_perm("config"):
        abort(403)
    if request.form.get('debug'):
        g.dbg = "1"
    else:
        g.dbg = "0"
    tool.run_sqlscript("save_owner_settings.sql", (request.form['host'], request.form['port'], request.form['owner'], g.dbg, request.form['apitoken']))
    apis = [(x[4:], request.form.to_dict()[x]) for x in request.form.to_dict() if x[:4] == "api_"]
    #g.db.autocommit = False
    c.execute('BEGIN')
    c.execute('DELETE FROM api_policy')
    for api in apis:
        if api[1] in ['allowed_without_key', 'allowed', 'request']:
            c.execute('''insert into api_policy
select ?, case ?
	when 'allowed_without_key' then 0
	when 'allowed' then 1
	when 'request' then 2
end''', (api[0], api[1]))
        else:
            c.execute('ROLLBACK')
            #g.db.autocommit = True
            abort(400)
            return
    else:
        c.execute('COMMIT')
        #g.db.autocommit = True
    return redirect('/')"""
@app.route("/user")
def user():
    with g.db.cursor() as c:
        if 'id' in session:
            try:
                api = c.execute('''select exists (
        select 1
        from config
        where name = 'get_api_key'
        and value <> 'disabled'
    )''').fetchone()[0]==1
                
                key = c.execute('''select key
    from api_keys
    where user_id = ?''', (session["id"],)).fetchone()
                return tool.rt("user.html", user_name = c.execute('''select name
    from user
    where id = ?''', (session["id"],)).fetchone()[0], login=True, api=api, key=None if key==None else key[0], api_enable=True)
            except:
                session.pop("id", None)
                return tool.rt("user.html", user_name = tool.getip(), login=False, api=False)
        else:
            return tool.rt("user.html", user_name = tool.getip(), login=False, api=False)
@app.route("/login")
def login():
    return tool.rt("login.html", req_captcha = tool.is_required_captcha("login"))
@app.route("/signup")
def signup():
    return tool.rt("signup.html", req_captcha = tool.is_required_captcha("signup"))
@app.route("/signup_form", methods=['POST'])
def signup_form():
    with g.db.cursor() as c:
        if not tool.captcha("signup"):
            return tool.captcha_failed()
        if tool.has_user(request.form["id"]):
            return tool.rt("error.html", error="이미 존재하는 사용자 이름입니다.")
        if data.username_format.fullmatch(request.form["id"]) is None:
            return tool.rt("error.html", error=f'계정명은 정규식 {escape(tool.get_config("username_format"))}을 충족해야 합니다.')
        if tool.is_valid_ip(request.form["id"]) or tool.is_valid_cidr(request.form["id"]):
            return tool.rt("error.html", error="IP나 CIDR 형식의 사용자 이름은 사용이 불가능합니다.")
        if request.form['pw'] != request.form['pw2']:
            return tool.rt("error.html", error="비밀번호가 일치하지 않습니다.")
        first = c.execute("SELECT NOT EXISTS (SELECT 1 FROM user WHERE isip = 0)").fetchone()[0]
        c.execute('''insert into user (name, password, isip)
    values (?,?,0)''', (request.form['id'], hashlib.sha3_512(request.form['pw'].encode()).hexdigest()))
        u = c.lastrowid
        c.execute('''insert into api_key_perm
    select ?, name, case value
        when 0 then 1
        when 1 then 1
        when 2 then 0
        end
    from api_policy''', (u,))
        docid = tool.get_docid(int(tool.get_config("user_namespace")), request.form["id"], True)
        c.execute("UPDATE data SET value = '' WHERE id = ?", (docid,))
        tool.record_history(docid, 1, "", None, None, u, "", 0)
        if first:
            c.execute("INSERT INTO perm VALUES(?, 'developer')", (u,))
        return redirect('/')
@app.route("/login_form", methods=['POST'])
def login_form():
    with g.db.cursor() as c:
        if not tool.captcha("login"):
            return tool.captcha_failed()
        f = c.execute('''select id
        from user
        where name = ?
        and password = ?
        and isip = 0''', (request.form['id'], hashlib.sha3_512(request.form['pw'].encode()).hexdigest())).fetchone()
        if f == None:
            return tool.rt("error.html", error="아이디나 비밀번호가 일치하지 않습니다.")
        if "keep" in request.form:
            session.permanent = True
        id = f[0]
        session['id'] = id
        if tool.has_perm("hideip", id):
            c.execute("INSERT INTO login_history (user, date, ip, ua, uach) VALUES(?,?,'127.0.0.1','<hideip>','<hideip>')", (id, tool.get_utime()))
        else:
            uach = []
            for i,v in request.headers:
                if not i.startswith("Sec-Ch-Ua"): continue
                uach.append(i + "=" + v)
            c.execute("INSERT INTO login_history (user, date, ip, ua, uach) VALUES(?,?,?,?,?)", (id, tool.get_utime(), tool.getip(), request.user_agent.string, ",".join(uach)))
        return redirect('/')
@app.route("/logout")
def logout():
    session.clear()
    return redirect('/')
@app.route("/history/<path:doc_name>")
def history(doc_name):
    with g.db.cursor() as c:
        ns, name = tool.split_ns(doc_name)
        docid = tool.get_docid(ns, name)
        if docid == -1:
            return tool.rt("error.html", error = "문서를 찾을 수 없습니다."), 404
        """h = c.execute('''select name, datetime, length, rev, edit_comment, dsc
    from (
        select author, edit_comment, datetime, length, rev, case
            when type = 0 then NULL
            when type = 1 then "삭제"
            when type = 2 then content
            else NULL
        end dsc
        from history
        where doc_id = (
            select id
            from doc_name
            where name = ?
        )
    ),
    user
    where author = id
    order by rev desc''', (doc_name,)).fetchall()"""
        c.execute("""SELECT rev, type, content, content2, content3, u1.name, edit_comment, datetime, length FROM history
    LEFT JOIN user AS u1 ON (author = u1.id) WHERE doc_id = ? ORDER BY rev DESC""", (docid,))
        history = [(x[0], x[1], x[2], x[3], x[4], x[5], x[6], tool.utime_to_str(x[7]), x[8]) for x in c.fetchall()]
        return tool.rt("history.html", history=history, title=tool.render_docname(ns, name), subtitle="역사", raw_doc_name=doc_name)
@app.route("/sql")
def sqldump():
    if not tool.has_perm("database"):
        abort(403)
    with open("dump.sql", "w", encoding='utf-8') as f:
        for l in g.db.iterdump():
            f.write("%s\n" % l)
    return send_file("dump.sql", as_attachment=True)
@app.route("/sql_shell", methods=['GET', 'POST'])
def sqlshell():
    if not tool.has_perm("database"):
        abort(403)
    if request.method == "GET":
        return tool.rt("sql_shell.html", title = "SQL Shell", prev_sql = "", result = "")
    else:
        try:
            with g.db.cursor() as c:
                result = str(c.execute(request.form["sql"]).fetchall())
        except Exception as e:
            result = str(e)
        return tool.rt("sql_shell.html", prev_sql = request.form["prev"] + "\n" + request.form["sql"], result = result)
@app.route("/delete/<path:doc_name>", methods = ["GET", "POST"])
def delete(doc_name):
    i = tool.ipuser(create = request.method == "POST")
    ns, name = tool.split_ns(doc_name)
    docid = tool.get_docid(ns, name)
    acl = tool.check_document_acl(docid, ns, "delete", name)
    if acl[0] == 0:
        return tool.rt("error.html", error = acl[1]), 403
    if request.method == "POST":
        data = tool.get_doc_data(docid)
        if data == None: return tool.rt("error.html", error = "문서를 찾을 수 없습니다.")
        tool.record_history(docid, 2, None, None, None, i, request.form["note"], -len(data))
        with g.db.cursor() as c:
            c.execute("UPDATE data SET value = NULL WHERE id = ?", (docid,))
        return redirect(url_for("doc_read", doc_title = doc_name))
    else:
        return tool.rt("document_delete.html", title = tool.render_docname(ns, name), subtitle = "삭제")
"""@app.route("/delete_full/<path:doc_name>")
def delete_full(doc_name):
    if not tool.has_perm("manage_history"):
        abort(403)
    return tool.rt("document_full_delete.html", doc_title = doc_name)
@app.route("/delete_full_form", methods=['POST'])
def delete_full_form():
    if not tool.has_perm("manage_history"):
        abort(403)
    tool.run_sqlscript("doc_full_delete.sql", (request.form['doc_name'],))
    return redirect("/")"""
"""@app.route("/api_tool.key_requests")
def api_tool.key_requests():
    if not isowner():
        abort(403)
    return tool.rt("api_request.html", reqs = c.execute('''select api_tool.key_requests.id, name
from user, api_tool.key_requests
where user.id = user_id''').fetchall())"""
"""@app.route("/api_keys")
def api_keys():
    with g.db.cursor() as c:
    if not tool.has_perm("grant"):
        abort(403)
    return tool.rt("api_key.html", keys = [x[0] for x in c.execute('''select name
from user, api_keys
where user.id = api_keys.user_id''').fetchall()])"""
@app.route("/move/<path:doc_name>", methods = ["GET", "POST"])
def move(doc_name):
    ns, name = tool.split_ns(doc_name)
    docid = tool.get_docid(ns, name)
    acl = tool.check_document_acl(docid, ns, "move", name)
    if acl[0] == 0:
        return tool.rt("error.html", error = acl[1]), 403
    if docid == -1:
        return tool.rt("error.html", error = "문서를 찾을 수 없습니다."), 404
    if request.method == "POST":
        to = request.form["to"]
        tons, toname = tool.split_ns(to)
        if (ns in data.file_namespace) ^ (tons in data.file_namespace):
            return tool.rt("error.html", error = "이 문서를 해당 이름 공간으로 이동할 수 없습니다."), 409
        if ns in data.file_namespace and os.path.splitext(name)[1] != os.path.splitext(toname)[1]:
            return tool.rt("error.html", error = "확장자가 다릅니다."), 409
        if "swap" in request.form:
            # 문서를 서로 맞바꾸기
            todocid = tool.get_docid(tons, toname)
            if todocid == -1 or todocid == docid:
                return tool.rt("error.html", error = "문서를 찾을 수 없습니다."), 404
            with g.db.cursor() as c:
                c.execute("UPDATE doc_name SET namespace = ?, name = ? WHERE id = ?", (tons, toname, docid))
                c.execute("UPDATE doc_name SET namespace = ?, name = ? WHERE id = ?", (ns, name, todocid))
            tool.record_history(docid, 3, tool.get_doc_data(docid), doc_name, to, tool.ipuser(), request.form["note"], 0)
            tool.record_history(todocid, 3, tool.get_doc_data(todocid), to, doc_name, tool.ipuser(), request.form["note"], 0)
        else:
            # 일반 문서 이동
            if tool.get_docid(tons, toname) != -1:
                return tool.rt("error.html", error = "문서가 이미 존재합니다."), 409
            acl = tool.check_document_acl(-1, tons, "move", toname)
            if acl[0] == 0:
                return tool.rt("error.html", error = acl[1]), 403
            with g.db.cursor() as c:
                c.execute("UPDATE doc_name SET namespace = ?, name = ? WHERE id = ?", (tons, toname, docid))
            tool.record_history(docid, 3, tool.get_doc_data(docid), doc_name, to, tool.ipuser(), request.form["note"], 0)
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
            json = request.json
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
                if no and condtype == "perm" and cond == "member":
                    no = False
                    cond = "ip"
                if no and condtype == "perm" and cond == "ip":
                    no = False
                    cond = "member"
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
                            (id, type2, condtype, cond, no, action, None if duration == 0 else tool.get_utime() + duration, ons[0] if action == "gotootherns" else None))
                if not nsacl: tool.record_history(docid, 4, tool.get_doc_data(docid), f'insert,{type2},{action},{"not:" if no else ""}{condtype}:{cond2 if condtype == "aclgroup" or condtype == "user" else cond}', None, tool.ipuser(), "", 0)
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
                if not nsacl: tool.record_history(docid, 4, tool.get_doc_data(docid), f'delete,{type2},{f[4]},{"not:" if f[3] else ""}{f[0]}:{v}', None, tool.ipuser(), "", 0)
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
        return tool.rt("acl.html", title=tool.render_docname(ns, name), raw_doc_name = doc_name, subtitle="ACL", type=data.acl_type[type2], type2 = type2,
                hasperm = tool.has_perm("nsacl") if nsacl else tool.has_perm("nsacl") or tool.check_document_acl(docid, ns, "acl", name, showmsg = False) == 1, perms = data.perm_type,
                acl = tool.render_acl(c.execute(f"""SELECT idx, condtype, value, value2, no, action, expire, otherns FROM {acl_t} WHERE {id_col} = ? AND acltype = ? ORDER BY idx""", (id, type2)).fetchall()),
                nsacl = nsacl, menu2 = (
            [
                tool.Menu("문서 ACL", url_for("acl", doc_name = doc_name, type1 = "document"), "menu2-selected" if not nsacl else ""),
                tool.Menu("이름공간 ACL", url_for("acl", doc_name = doc_name, type1 = "namespace"), "menu2-selected" if nsacl else "")
            ], acls
        ))
"""@app.route("/api_request_accept_or_decline", methods=['POST'])
def api_request_accept_or_decline():
    if not isowner():
        abort(403)
    if request.form['result'] == 'accept':
        k = gen_random_str(int(tool.get_config("api_key_length")))
        c.execute('''insert into api_keys
select user_id, NULL, 1
from api_tool.key_requests
where id = ?''', (request.form['id']))
        c.execute('''insert into api_key_perm
select ?, name, case value
	when 0 then 1
	when 1 then 1
	when 2 then 0
	end
from api_policy''', (k,))
    c.execute('''delete from api_tool.key_requests
where id=?''', (request.form['id']))
    return redirect('/')"""
"""@app.route("/api_perm/<id>", methods=['GET', 'POST'])
def api_perm(id):
    if not tool.get_config("grant"):
        abort(403)
    i = tool.user_name_to_id(id)
    if request.method == 'POST':
        c.execute('DELETE FROM api_key_perm WHERE user=?', (i,))
        for k in data.keyl:
            if request.form.get(data.keyl[k]):
                c.execute('''insert into api_key_perm
values(?,?,1)''', (i, data.keyl[k]))
            else:
                c.execute('''insert into api_key_perm
values(?,?,0)''', (i, data.keyl[k]))
        return redirect('/')
    tmp = []
    for k in data.keyl:
        try:
            p = c.execute("SELECT value FROM api_key_perm WHERE user = ? AND name = ?", (i, data.keyl[k])).fetchone()[0]
        except:
            p = 0
        tmp.append([k, data.keyl[k], p])
    return tool.rt('api_perm.html', ps=tmp, id=id)"""
@app.route("/getkey")
def getkey():
    return tool.rt("error.html", error="API 키 시스템 개편을 위해 현재 버전에서는 API를 사용할 수 없습니다. 이후 다시 사용 가능해질 예정입니다.")
    """if tool.get_config("get_api_key") == "disabled":
        return tool.rt("error.html", error="API가 비활성화된 위키입니다.")
    else:
        return tool.rt("api_key_ok.html", key = gen_random_str(int(tool.get_config("api_key_length"))))"""
"""@app.route("/api_key_delete", methods=['GET', 'POST'])
def api_key_delete():
    c.execute('delete from api_keys where key=?', (request.form['id'],))
    c.execute('delete from api_key_perm where key=?', (request.form['id'],))
    return redirect('/')"""
@app.route("/random")
def random_document():
    with g.db.cursor() as c:
        c.execute('SELECT name FROM doc_name LIMIT 1 OFFSET abs(random()) % (SELECT COUNT(*) FROM doc_name);')
        r = c.fetchone()[0]
        return redirect('/w/{0}'.format(r))
@app.route("/file/<id>")
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
@app.route("/aclgroup", methods = ["GET", "POST"])
def aclgroup():
    with g.db.cursor() as c:
        tool.delete_expired_aclgroup()
        if request.method == "POST":
            if not tool.has_perm("admin"):
                abort(403)
            t = tool.get_utime()
            if tool.get_config("aclgroup_note_required") == "1" and request.form["note"] == "":
                return tool.error_400("note의 값은 필수입니다.")
            dur = 0 if request.form["dur"] == "" else int(request.form["dur"])
            if tool.has_config("aclgroup_max_duration") and dur > int(tool.get_config("aclgroup_max_duration")):
                return tool.error_400(f"expire의 값은 {tool.get_config('aclgroup_max_duration')} 이하여야 합니다.")
            gid = c.execute("SELECT id FROM aclgroup WHERE name = ? AND deleted = 0", (request.form["group"],)).fetchone()
            if gid is None:
                return tool.error_400("aclgroup_group_not_found")
            gid = gid[0]
            if request.form["mode"] == "ip":
                ip = request.form["value"]
                if '/' not in ip:
                    ip += "/128" if ':' in ip else "/32"
                if not tool.is_valid_cidr(ip):
                    return tool.error_400("invalid_cidr")
                ip = tool.convert_cidr(ip)
                if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_log WHERE ip = ? AND gid = ?)", (ip, gid)).fetchone()[0]:
                    return tool.error_400("aclgroup_already_exists")
                c.execute("INSERT INTO aclgroup_log (gid, ip, note, start, end) VALUES(?, ?, ?, ?, ?)",
                        (gid, ip, request.form["note"], t, None if dur == 0 else t + dur))
                c.execute("INSERT INTO block_log (type, operator, target_ip, id, gid, date, duration, note) VALUES(1, ?, ?, ?, ?, ?, ?, ?)",
                        (session["id"], ip, c.lastrowid, gid, t, dur, request.form["note"]))
            else:
                if not tool.has_user(request.form["value"]):
                    return tool.error_400("사용자 이름이 올바르지 않습니다.")
                if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_log WHERE user = (SELECT id FROM user WHERE name = ?) AND gid = ?)", (request.form["value"], gid)).fetchone()[0]:
                    return tool.error_400("aclgroup_already_exists")
                c.execute("INSERT INTO aclgroup_log (gid, user, note, start, end) VALUES(?, (SELECT id FROM user WHERE name = ?), ?, ?, ?)",
                        (gid, request.form["value"], request.form["note"], t, None if dur == 0 else t + dur))
                c.execute("INSERT INTO block_log (type, operator, target, id, gid, date, duration, note) VALUES(1, ?, (SELECT id FROM user WHERE name = ?), ?, ?, ?, ?, ?)",
                        (session["id"], request.form["value"], c.lastrowid, gid, t, dur, request.form["note"]))
        groups = [x[0] for x in c.execute("SELECT name FROM aclgroup WHERE deleted = 0").fetchall()]
        current = request.args.get("group", groups[0] if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup WHERE deleted = 0)").fetchone()[0] else "")
        return tool.rt("aclgroup.html", title = "ACLGroup", groups = groups, current = current, newgroup_perm = tool.has_perm("aclgroup"), add_perm = tool.has_perm("admin"), delete_perm = tool.has_perm("admin"), record = (
            (x[0], x[1], x[2], tool.utime_to_str(x[3]), "영구" if x[4] is None else tool.utime_to_str(x[4]))
            for x in c.execute("SELECT id, (CASE WHEN ip IS NULL THEN (SELECT name FROM user WHERE id = user) ELSE ip END), note, start, end FROM aclgroup_log WHERE gid = (SELECT id FROM aclgroup WHERE name = ?)", (current,)).fetchall()
        ))
@app.route("/aclgroup/delete", methods = ["POST"])
def aclgroup_delete():
    if not tool.has_perm("admin"):
        abort(403)
    with g.db.cursor() as c:
        if tool.get_config("aclgroup_note_required") == "1" and request.form["note"] == "":
            return tool.error_400("note의 값은 필수입니다.")
        if not c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_log WHERE id = ?)", (request.form["id"],)).fetchone()[0]:
            return tool.error_400("aclgroup_not_found")
        c.execute("INSERT INTO block_log (type, operator, target_ip, target, id, gid, date, note) SELECT 2, ?1, ip, user, ?2, gid, ?3, ?4 FROM aclgroup_log WHERE id = ?2",
                (session["id"], request.form["id"], tool.get_utime(), request.form["note"]))
        c.execute("DELETE FROM aclgroup_log WHERE id = ?", (request.form["id"],))
        return '', 204
@app.route("/aclgroup/new_group", methods = ["POST"])
def aclgroup_new_group():
    if not tool.has_perm("aclgroup"):
        abort(403)
    with g.db.cursor() as c:
        c.execute("INSERT INTO aclgroup (name) VALUES(?)",
                (request.form["group"],))
        return redirect("/aclgroup?group={0}".format(request.form["group"]))
@app.route("/aclgroup/delete_group", methods = ["POST"])
def aclgroup_delete_group():
    if not tool.has_perm("aclgroup"):
        abort(403)
    with g.db.cursor() as c:
        gid = c.execute("SELECT id FROM aclgroup WHERE name = ?", (request.form["group"],)).fetchone()
        if gid == None:
            abort(400)
        gid = gid[0]
        c.execute("UPDATE aclgroup SET deleted = 1 WHERE id = ?", (gid,))
        c.execute("DELETE FROM aclgroup_log WHERE gid = ?", (gid,))
        return redirect("/aclgroup")
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
            (x[0], x[1], (x[3] if x[2] is None else x[2]), x[2] != None, x[4], x[5], tool.utime_to_str(x[6]), None if x[7] is None else tool.time_to_str(x[7]), x[8], x[9]) for x in
            c.execute("""SELECT type, u1.name, target_ip, u2.name, block_log.id, aclgroup.name, date, duration, grant_perm, note FROM block_log
    LEFT JOIN user AS u1 ON block_log.operator = u1.id
    LEFT JOIN user AS u2 ON block_log.target = u2.id
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
            placeholder = ','.join('?' * len(data.grantable))
            oldperm = set(x[0] for x in c.execute(f"SELECT perm FROM perm WHERE user = ? AND perm IN ({placeholder})", [user] + data.grantable).fetchall())
            c.execute(f"DELETE FROM perm WHERE user = ? AND perm IN ({placeholder})", [user] + data.grantable)
            newperm = set()
            for p in data.grantable:
                if p in request.form:
                    newperm.add(p)
            c.executemany("INSERT INTO perm VALUES(?,?)", ((user, x) for x in newperm))
            logstr = []
            for p in newperm - oldperm:
                logstr.append("+" + p) 
            for p in oldperm - newperm:
                logstr.append("-" + p)
            if len(logstr) != 0: c.execute("INSERT INTO block_log (type, operator, target, date, grant_perm, note) VALUES(3,?,?,?,?,?)",
                    (tool.ipuser(), user, tool.get_utime(), " ".join(logstr), request.form["note"] if tool.get_config("ext_note") == "1" else ""))
            return '', 204
        else:
            user = request.args.get("username", "")
            if user == "":
                return tool.rt("grant.html", title="권한 부여", user = "")
            else:
                if not tool.has_user(user):
                    return tool.rt("grant.html", title="권한 부여", user = user, error = 1)
                else:
                    return tool.rt("grant.html", title="권한 부여", user = user, grantable = data.grantable, vailduser = True, ext_note = tool.get_config("ext_note") == "1",
                            perm = set(x[0] for x in c.execute(f"SELECT perm FROM perm WHERE user = ? AND perm IN ({','.join('?' * len(data.grantable))})", [tool.user_name_to_id(user)] + data.grantable).fetchall()))
@app.route("/admin/captcha_test", methods = ["GET", "POST"])
def captcha_test():
    if not tool.has_perm("config"):
        abort(403)
    if request.method == "POST":
        return tool.rt("captcha_test.html", title = "CAPTCHA 테스트", result = int(tool.captcha("test")))
    return tool.rt("captcha_test.html", title = "CAPTCHA 테스트", req_captcha = tool.is_required_captcha("test"), result = -1)
@app.route("/admin/sysman")
def sysman():
    if not tool.has_perm("sysman"):
        abort(403)
    return tool.rt("sysman.html", title="시스템 관리")
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
            return tool.rt("error.html", error = acl[1]), 403
        if request.method == "POST":
            acl = tool.check_document_acl(docid, ns, "create_thread", name)
            if acl[0] == 0:
                return tool.rt("error.html", error = acl[1]), 403
            if docid == -1: docid = tool.get_docid(ns, name, True)
            time = tool.get_utime()
            c.execute("INSERT INTO discuss (doc_id, topic, last) VALUES(?,?,?)", (docid, request.form["topic"], time))
            slug = c.lastrowid
            #c.execute("INSERT INTO thread_comment (slug, no, text, type, author, time) VALUES(?,1,?,0,?,?)", (slug, request.form["content"], tool.ipuser(), time))
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
            return tool.rt("error.html", error = acl[1]), 403
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
#SELECT ?1, (SELECT seq FROM discuss WHERE slug = ?1), 0, ?2, ?3, ?4""", (slug, request.form["value"], tool.ipuser(), tool.get_utime()))
            #c.execute("UPDATE discuss SET seq = seq + 1 WHERE slug = ?", (slug,))
            return "", 204
        html, js = tool.render_thread(slug)
        return tool.rt("thread.html", topic = topic, title = tool.render_docname(ns, name), raw_title = fullname, subtitle = "토론", comment = html,
                       js = js, status = status, slug = slug, menu = [
            tool.Menu("토론 목록", url_for("discuss", doc = fullname)),
            tool.Menu("ACL", url_for("acl", doc_name = fullname))
        ])
@app.route("/api/render_thread/<int:slug>")
def render_thread(slug):
    with g.db.cursor() as c:
        ns, name, docid = c.execute("SELECT namespace, name, doc_id FROM discuss JOIN doc_name ON (doc_id = id) WHERE slug = ?", (slug,)).fetchone()
        acl = tool.check_document_acl(docid, ns, "read", name)
        if acl[0] == 0:
            abort(403)
        html, js = tool.render_thread(slug)
        return {"html": html, "js": js}
@app.route("/topic/<int:slug>")
def topic_redirect(slug):
    return redirect(url_for("thread", slug = slug))
@app.route("/robots.txt")
def robots():
    return send_file("robots.txt")
@app.route("/admin/sysman/update", methods = ["GET", "POST"])
def update():
    if not tool.has_perm("sysman"):
        abort(403)
    if request.method == "POST":
        if repo.is_dirty(untracked_files=True):
            repo.index.add(".")
            repo.index.commit(tool.get_config("update_local_change_commit"))
        try:
            repo.remotes.origin.pull(request.form["branch"])
        except Exception as e:
            print(e)
        os.system("pip install -r requirements.txt")
        if repo.index.unmerged_blobs():
            return tool.rt("update_conflict.html", title="업데이트")
        return redirect(url_for("restart"))
    if repo is None:
        return tool.rt("error.html", error = "엔진이 git 저장소로 다운로드 되지 않았기 때문에 업데이트 기능을 사용할 수 없습니다.")
    else:
        repo.remotes.origin.fetch(tags = True)
        branch = [r.name[7:] for r in repo.remotes.origin.refs]
        latest = {}
        for i in branch:
            latest[i] = repo.git.describe(repo.remotes.origin.refs[i].commit.hexsha, tags = True)
        return tool.rt("update.html", dirty = repo.is_dirty(untracked_files=True), title = "업데이트", current = repo.git.describe(tags = True), latest = latest, branch = branch)
@app.route("/admin/sysman/update/cancel")
def update_cancel():
    if not tool.has_perm("sysman"):
        abort(403)
    repo.git.merge("--abort")
    return url_for("sysman")
@app.route("/admin/sysman/restart")
def restart():
    return tool.rt("restart.html", title = "재시작")
@app.route("/RecentChanges")
def recent_changes():
    type = request.args.get("type", -1, type=int)
    with g.db.cursor() as c:
        return tool.rt("recent_changes.html", title = "최근 변경", recent = 
            ((tool.get_doc_full_name(x[0]), x[1], None if x[2] == 0 and x[7] == "" else f"{x[7]} <i>{escape(history_msg(x[2], x[3], x[4]))}</i>", x[5], tool.time_to_str(x[6])) for x in
            c.execute(f"SELECT doc_id, length, type, content2, content3, author, ? - datetime, edit_comment FROM history{'' if type == -1 else ' WHERE type = ?'} ORDER BY datetime DESC LIMIT 100", (tool.get_utime(),) if type == -1 else (tool.get_utime(),type)).fetchall()), menu2 = [[
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
            c.execute("SELECT D.slug, D.doc_id, D.topic, C.author, ? - D.last FROM discuss D JOIN thread_comment C ON (D.slug = C.slug AND D.seq - 1 = C.no) WHERE D.status = ? ORDER BY D.last {0} LIMIT 100".format("ASC" if old else "DESC"), (tool.get_utime(), status)).fetchall()), menu2 = [[
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
            return tool.rt("error.html", error = "이 기능이 비활성화되어 있습니다.")
        if exp != -1:
            c.execute("DELETE FROM login_history WHERE date < ?", (tool.get_utime() - exp,))
        if "user" in request.args:
            user = request.args["user"]
            id = tool.user_name_to_id(user)
            c.execute("INSERT INTO block_log (type, operator, target, date, note) VALUES(4,?,?,?,?)", (tool.ipuser(), id, tool.get_utime(), request.args["note"] if tool.get_config("ext_note") == "1" else ""))
            return tool.rt("login_history_1.html", title = f"{user} 로그인 내역", lh = c.execute("SELECT date, ip, ua, uach FROM login_history WHERE user = ?", (id,)).fetchall())
        else:
            return tool.rt("login_history.html", title = "로그인 내역", ext_note = tool.get_config("ext_note") == "1")
@app.route("/Upload", methods=['GET','POST'])
def upload():
    if request.method == "POST":
        with g.db.cursor() as c:
            if "file" not in request.files: abort(400)
            file = request.files["file"]
            if file.filename == "": abort(400)
            if not tool.has_perm("bypass_image_size_limit"):
                file.seek(0, 2)
                max_size = int(tool.get_config("max_file_size"))
                if file.tell() > max_size:
                    return tool.rt("error.html", error = f"파일 최대 용량({max_size} 바이트)을 초과합니다."), 413
                file.seek(0)
            ns, name = tool.split_ns(request.form["name"])
            if ns not in data.file_namespace:
                return tool.rt("error.html", error = "invalid_namespace"), 400
            if tool.get_docid(ns, name) != -1:
                return tool.rt("error.html", error = "이미 해당 이름의 문서가 존재합니다."), 400
            acl = tool.check_document_acl(-1, ns, "edit", name)
            if acl[0] == 0:
                return tool.rt("error.html", error = acl[1]), 403
            ext = os.path.splitext(request.form["name"])[1][1:]
            if ext not in data.allow_file_extension:
                return tool.rt("error.html", error = f"{ext} 확장자는 허용되지 않습니다."), 400
            docid = tool.get_docid(ns, name, True)
            content = f'[include({tool.get_config("image_license")}{request.form["license"]})]\n[[{tool.get_namespace_name(int(tool.get_config("category_namespace")))}:{tool.get_config("file_category")}{request.form["category"]}]]\n{request.form["content"]}'
            c.execute("UPDATE data SET value = ? WHERE id = ?", (content, docid))
            tool.record_history(docid, 1, content, None, None, tool.ipuser(), request.form["note"], len(content))
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
if __name__ == "__main__":
    if DEBUG:
        @app.before_request
        def clear_template_cache():
            app.jinja_env.cache.clear()
    app.run(debug=DEBUG, host=HOST, port=PORT)
