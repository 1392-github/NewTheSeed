from flask import Flask, request, redirect, session, send_file, abort, Response
from flask import render_template
from io import BytesIO
import sqlite3
import hashlib
import sys
import datetime
import random
import re
import types
import ipaddress
import os
if sys.version_info < (3, 9):
    if input("경고! NewTheSeed는 Python 3.9 미만의 Python 버전은 지원하지 않으며, 이로 인해 발생하는 버그(보안취약점 포함)는 수정되지 않습니다. 계속하려면 y를 입력해주세요. -> ") != "y":
        sys.exit()
# 상수 데이터들
version = 16
keyl = {'문서 읽기' : 'read_doc',
        '문서 편집':'write_doc',
        '랜덤 문서':'randompage',
        '사용자 차단':'ban',
        '문서 역사 보기':'history',
}
extension = {
    #"document_read_acl": "문서 ACL에서 읽기 ACL 사용 가능",
    #"twe_api": "TWE식 API 사용",
    #"split_blind": "strong_blind, weak_blind 이원화",
    #"split_lock_edit_request": "편집 요청 잠금과 내용 숨김 분리",
    #"split_aclgroup_perm": "ACL Group 생성/삭제 권한과 ACL Group 사용자 추가 권한 분리",
    #"show_reaming_time": "ACL Group 메시지에 남은 기간 표시"
}
rng_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
sql_max_detector = re.compile(r'\?(\d+)')
default_config = {
    "version": str(version),
    "host": "0.0.0.0",
    "port": lambda : input('위키 포트 입력 -> '),
    "owner": lambda : input('위키 소유자 입력 -> '),
    "debug": "0",
    "get_api_key": "disabled",
    "secret_key": lambda : gen_random_str(64),
    "api_key_length": "64",
    "time_mode": "real",
    "time_format": "%Y-%m-%d %H:%M:%S",
    "wiki_title": "NewTheSeed",
    "wiki_name": "NewTheSeed",
    "keep_login_time": "2678400",
    "aclgroup_note_required": "0"
}
# 함수 정의 부분 시작

def hash(path):
    f = open(path, 'rb')
    data = f.read()
    hash = hashlib.md5(data).hexdigest()
    return hash
'''def save_db():
    with open('data.json', 'w', encoding='UTF-8') as f:
        json.dump(db, f, indent=4, ensure_ascii=False)'''
'''def run_sqlscript(filename, args = (), no_replace = []):
    with open(f"sql_script/{filename}", 'r') as f:
        args = list(args)
        for i in range(len(args)):
            if i not in no_replace:
                args[i] = str(args[i]).replace('"', '""')
        c.executescript(f.read().format(*args))
    
    return c.fetchall()'''
def run_sqlscript(filename, args = ()):
    with open(f"sql_script/{filename}", 'r') as f:
        q = f.read().split(';')
        for i in q:
            if i == "":
                continue
            i = i.strip()
            if '?' in i:
                c.execute(i, args[:max(int(x) for x in sql_max_detector.findall(i))])
            else:
                c.execute(i)
    return c.fetchall()
'''owner 권한 체크
/sql, /sqlshell, /owner_settings 에서 사용
권한이 있으면 True, 없으면 False'''
def isowner(user = None):
    if user != None:
        return c.execute('''select exists (
	select 1
	from user
	where id = ?
	and name = (
		select value
		from config
		where name = "owner"
	)
)''', (user,)).fetchone()[0] == 1
    if 'id' not in session:
        return False
    return c.execute('''select exists (
	select 1
	from user
	where id = ?
	and name = (
		select value
		from config
		where name = "owner"
	)
)''', (str(session['id']),)).fetchone()[0] == 1
def ipuser():
    if 'id' in session:
        return int(session['id'])
    c.execute('''insert into user (name, isip)
select ?, 1
where not exists (
	select *
	from user
	where name = ?
	and isip = 1
)''', (request.remote_addr, request.remote_addr))
    return c.execute('''select id
from user
where name = ?
and isip = 1''', (request.remote_addr,)).fetchone()[0]
def hasacl(cond):
    if 'id' in session:
        user = session['id']
    else:
        user = ipuser()
    if cond == 'any' or cond == 'any_with_ban':
        return True
    if cond == 'member':
        return c.execute('''select isip
from user
where id = ?''').fetchone()[0] == '0'
    if cond == 'admin' or cond == 'owner':
        return isowner()
# API 키 요구여부 확인 및 키에 연결된 사용자 가져오기
# 유효하지 않은 키인경우 None 반환
# API 키가 None인 경우, 키가 필요없으면 IP에 해당하는 ID 반환, 키가 필요하면 None 반환
def key_req(name, key):
    return None
"""
    16 버전에서는 API 임시 비활성화
    try:
        policy = c.execute('''select case value
when 0 then 0
when 1 then 1
when 2 then 1
end
from api_policy
where name = ?''',(name,)).fetchone()[0]
    except:
        policy = 1
    if key == None:
        if policy == 0:
            return ipuser()
        else:
            return None
    if c.execute('''select exists (
    select 1
    from api_keys
    where key = ?
)''', (key,)).fetchone()[0]==0:
        return None
    perm = c.execute('''select value
from api_key_perm
where key = ?
and name = ?''', (key, name)).fetchone()[0]
    if perm == 0:
        return None
    return c.execute('''select user_id
from api_keys
where key = ?''', (key,)).fetchone()[0]
"""
# 차단 여부 확인 (None : 차단안됨, -1 : 영구차단, -2 : 경고)
def isban():
    if 'id' in session:
        return c.execute("select case when ban<0 or ban>strftime('%s','now') then ban else 0 end from user where id=?", (session['id'],)).fetchone()[0]
    else:
        return c.execute("select case when ban<0 or ban>strftime('%s','now') then ban else 0 end from user where id=?", (ipuser(),)).fetchone()[0]
def rt(t, **kwargs):
    k = kwargs
    k['wiki_title'] = get_config("wiki_title")
    k['wiki_name'] = get_config("wiki_name")
    k['isowner'] = isowner()
    k['version'] = version
    k['timemode'] = get_config("time_mode")
    return render_template(t, **k)
def gen_random_str(len):
    s = ""
    for _ in range(len):
        s += rng_string[random.randint(0, 62)]
    return s
def has_config(key):
    return c.execute("SELECT EXISTS (SELECT 1 FROM config WHERE name = ?)", (key,)).fetchone()[0] == 1
def get_config(key, default = None):
    # 16 버전에서는 임시로 API 비활성화
    if key == "get_api_key":
        return "disabled"
    if has_config(key):
        return c.execute("SELECT value FROM config WHERE name = ?", (key,)).fetchone()[0]
    else:
        return default
def user_name_to_id(name):
    return c.execute("SELECT id FROM user WHERE name = ?", (name,)).fetchone()[0]
def id_to_user_name(id):
    return c.execute("SELECT name FROM user WHERE id = ?", (id,)).fetchone()[0]
def time_to_str(time, zero = "0초"):
    if time == 0:
        return zero
    day_year = 29030400 if get_config("time_mode") == "theseed" else 31536000
    result = ""
    c = time // day_year
    if c > 0:
        result += f"{c}년 "
        time -= c * day_year
    c = time // 86400
    if c > 0:
        result += f"{c}일 "
        time -= c * 86400
    c = time // 3600
    if c > 0:
        result += f"{c}시간 "
        time -= c * 3600
    c = time // 60
    if c > 0:
        result += f"{c}분 "
        time -= c * 60
    if time > 0:
        result += f"{time}초 "
    return result[:-1]
def utime_to_str(utime):
    return datetime.datetime.fromtimestamp(utime).strftime(get_config("time_format"))
def get_utime():
    return int(datetime.datetime.now().timestamp())
def has_user(name, ip_allow = False):
    if ip_allow:
        return c.execute("SELECT EXISTS (SELECT 1 FROM user WHERE name = ?)", (name,)).fetchone()[0] == 1
    else:
        return c.execute("SELECT EXISTS (SELECT 1 FROM user WHERE name = ? AND isip = 0)", (name,)).fetchone()[0] == 1
def ip_in_cidr(ip_str, cidr_str):
    return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr_str, strict=False)
def is_valid_cidr(cidr_str):
    try:
        ipaddress.ip_network(cidr_str)
        return True
    except ValueError:
        return False
def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False
def delete_expired_aclgroup():
    c.execute("DELETE FROM aclgroup_log WHERE end IS NOT NULL AND end < ?", (get_utime(),))
def error_400(msg):
    return Response(msg, 400, mimetype="text/plain")
def convert_ip(ip):
    return str(ipaddress.ip_address(ip))
def convert_cidr(cidr):
    return str(ipaddress.ip_network(cidr))
def user_in_aclgroup(group, user = None):
    delete_expired_aclgroup()
    if user == None:
        user = ipuser()
    if c.execute("SELECT isip FROM user WHERE id = ?", (user,)).fetchone()[0] == 1:
        ip = c.execute("SELECT name FROM user WHERE id = ?", (user,)).fetchone()[0]
        for i in c.execute("SELECT ip FROM aclgroup_log WHERE gid = ?", (group,)).fetchall():
            i = i[0]
            if i == None:
                continue
            if ip_in_cidr(ip, i):
                return True
        return False
    else:
        return c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_log WHERE gid = ? AND user = ?)", (group, user)).fetchone()[0] == 1
# 함수 정의 끝, 초기화 부분 시작
# DB 로딩
init = not os.path.exists("data.db")
db = sqlite3.connect("data.db", isolation_level=None, check_same_thread=False)
c = db.cursor()
run_sqlscript("db_stu.sql") # DB 구조 만들기
# 초기 설정
for k in default_config:
    if c.execute("select exists (select 1 from config where name = ?)", (k,)).fetchone()[0] == 0:
        c.execute('insert into config values(?, ?)', (k, default_config[k]() if isinstance(default_config[k], types.FunctionType) else default_config[k]))
print(f"The Wiki Engine 버전 : {version}")
c.execute("UPDATE config SET name = 'version' WHERE name = 'majorversion'")
c.execute("DELETE FROM config WHERE name = 'minorversion'")
db_version = int(c.execute('''select value
from config
where name = "version";''').fetchone()[0])
print(f"DB 버전 : {db_version}")
if db_version > version:
    print("경고 : 상위 버전 The Wiki Engine의 DB입니다")
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
    run_sqlscript('db_stu.sql')
    c.executemany('''insert into api_key_perm
select ?, name, case value
	when 0 then 1
	when 1 then 1
	when 2 then 0
	end
from api_policy''', c.execute("SELECT id FROM user WHERE isip = 0").fetchall())
    c.execute("INSERT INTO api_keys SELECT id, NULL, 0 FROM user WHERE isip = 0")
if db_version < 16 or init:
    c.execute("""INSERT INTO aclgroup (name, readperm, addperm, deleteperm, warn_msg, style)
              VALUES('차단된 사용자','admin','admin','admin','','color: gray; text-decoration: line-through;')""")

c.execute('''update config
set value = ?
where name = "version"''', (str(version),)) # 변환 후 버전 재설정
"""c.execute('''update config
set value = ?
where name = "minorversion"''', (str(version[1]),))""" # 일단 철회
if get_config("init") == "0":
    pass
app = Flask(__name__)
app.secret_key = get_config("secret_key")
app.permanent_session_lifetime = datetime.timedelta(seconds = int(get_config("keep_login_time")))
# 초기화 부분 끝, API 부분 시작
@app.route("/api/read_doc", methods=['POST'])
def api_read_doc():
    t = key_req('read_doc', request.json.get('key', None))
    if t == None:
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
        i = ipuser()
    if isban() != 0:
        if isban() == -2:
            return rt("banned.html", warn=True, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        elif isban() == -1:
            return rt("banned.html", warn=False, time=None, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        else:
            return rt("banned.html", warn=False, time=datetime.datetime.fromtimestamp(isban()).strftime('%Y-%m-%d %p %I:%M:%S'), reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
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
    i = key_req('write_doc', request.json.get('key', None))
    if i == None:
        abort(403)
    run_sqlscript("doc_edit.sql", (doc_name, value, 0, i, request.json.get('edit_comment', None), str(datetime.datetime.now()), len(value) - len(prev_content)))
    return {}
@app.route("/api/randompage", methods=['POST'])
def api_randompage():
    if key_req('randompage', request.json.get('key', None)) == None:
        abort(403)
    c.execute('select name from doc_name order by random() limit 1')
    r = c.fetchone()[0]
    return {'name':r}
@app.route("/api/ban", methods=['POST'])
def api_ban():
    if key_req('ban', request.json.get('key', None)) == None:
        abort(403)
    print(key_req('ban', request.json.get('key', None)))
    if not isowner(key_req('ban', request.json.get('key', None))):
        abort(403)
    c.execute("update user set ban=case ? when '0' then case when cast(? as integer)<=0 then ? else strftime('%s','now')+? end else strftime('%s',?) end where name=?", (request.json['method'],request.json['time'],request.json['time'],request.json['time'],request.json['time'],request.json['user']))
    c.execute("update user set reason=? where name=?", (request.json['reason'],request.json['user']))
    return {}
# API 부분 끝, 주 페이지 시작
@app.route("/")
def redirect_frontpage():
    return redirect("/w/FrontPage")
@app.route("/template_test/<t>")
def master(t):
    if not request.remote_addr == '127.0.0.1' and not request.remote_addr == '::1':
        return '', 404
    return rt(t, doc_title = "123", doc_data="<h1>Test</h1><br>Test")
@app.route("/w/<path:doc_title>")
def doc_read(doc_title):
    try:
        rev = request.args.get('rev')
        if rev == None:
            d = c.execute('''select content
from history
where doc_id = (
select id
from doc_name
where name = ?
and type = 0
)
group by NULL
having rev = max(rev)''', (doc_title,)).fetchone()[0]
        else:
            d = c.execute('''select content
from history
where doc_id = (
select id
from doc_name
where name = ?
)
and rev = ?
and type = 0''', (doc_title,rev)).fetchone()[0]
        #d = db['document'][doc_title]["content"]
        if d == None:
            raise Exception
        code = 200
    except:
        d = f'''<h2>오류! 이 문서는 존재하지 않습니다</h2>
<a href="/edit/{doc_title}" style="border: 1px solid #808080;
            padding: 5px 13px;
            color: unset;
            text-decoration: none;
            line-height: 23px;">새 문서 만들기</a>'''
        code = 404
    return rt("document_read.html", doc_title=doc_title, doc_data=d), code
@app.route("/raw/<path:doc_title>")
def doc_raw(doc_title):
    try:
        rev = request.args.get('rev')
        if rev == None:
            d = c.execute('''select content
from history
where doc_id = (
select id
from doc_name
where name = ?
and type = 0
)
group by doc_id
having rev = max(rev)''', (doc_title,)).fetchone()[0]
        else:
            d = c.execute('''select content
from history
where doc_id = (
select id
from doc_name
where name = ?
)
and rev = ?
and type = 0''', (doc_title,rev)).fetchone()[0]
        #d = db['document'][doc_title]["content"]
        if d == None:
            raise Exception
        code = 200
        if d == None:
            raise Exception
        code = 200
    except:
        d = ""
        code = 404
    return rt("document_raw.html", doc_title=doc_title, doc_data=d), code
@app.route("/edit/<path:doc_title>")
def doc_edit(doc_title):
    if 'id' in session:
        i = session['id']
    else:
        i = ipuser()
    if isban() != 0:
        if isban() == -2:
            return rt("banned.html", warn=True, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        elif isban() == -1:
            return rt("banned.html", warn=False, time=None, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        else:
            return rt("banned.html", warn=False, time=datetime.datetime.fromtimestamp(isban()).strftime('%Y-%m-%d %p %I:%M:%S'), reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
    try:
        d = c.execute('''select content
from history
where doc_id = (
	select id
	from doc_name
	where name = ?
)
group by doc_id
having rev = max(rev)''', (doc_title,)).fetchone()[0]
    except:
        d = ""
    try:
        r = c.execute('''select history_seq - 1
from doc_name
where name = ?''', (doc_title,)).fetchone()[0]
    except:
        r = "0"
    
    return rt("document_edit.html", doc_title=doc_title, doc_data=d, doc_rev=r)

@app.route("/edit_form", methods = ['POST'])
def doc_edit_form():
    doc_name = request.form["doc_name"]
    value = request.form["value"]
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
    if 'id' in session:
        i = session['id']
    else:
        i = ipuser()
    if isban() != 0:
        if isban() == -2:
            return rt("banned.html", warn=True, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        elif isban() == -1:
            return rt("banned.html", warn=False, time=None, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        else:
            return rt("banned.html", warn=False, time=datetime.datetime.fromtimestamp(isban()).strftime('%Y-%m-%d %p %I:%M:%S'), reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
    run_sqlscript("doc_edit.sql", (doc_name, value, 0, i, request.form["edit_comment"], str(datetime.datetime.now()), len(value) - len(prev_content)))
    #db.commit()
    return redirect(f"/w/{doc_name}")
@app.route("/license")
def license():
    return rt("license.html")
@app.route("/admin/config")
def owner_settings():
    if not isowner():
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
    return rt("owner_settings.html",
                           wiki_host = config[2][0], wiki_port = config[4][0], wiki_owner = config[3][0], debug = config[0][0]=='1', token = config[1][0],
              keys = keys)
@app.route("/owner_settings_form", methods = ['POST'])
def owner_settings_save():
    if not isowner():
        abort(403)
    if request.form.get('debug'):
        dbg = "1"
    else:
        dbg = "0"
    run_sqlscript("save_owner_settings.sql", (request.form['host'], request.form['port'], request.form['owner'], dbg, request.form['apitoken']))
    apis = [(x[4:], request.form.to_dict()[x]) for x in request.form.to_dict() if x[:4] == "api_"]
    #db.autocommit = False
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
            #db.autocommit = True
            abort(400)
            return
    else:
        c.execute('COMMIT')
        #db.autocommit = True
    return redirect('/')
@app.route("/user")
def user():
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
            return rt("user.html", user_name = c.execute('''select name
from user
where id = ?''', (session["id"],)).fetchone()[0], login=True, api=api, key=None if key==None else key[0], api_enable=True)
        except:
            session.pop("id", None)
            return rt("user.html", user_name = request.remote_addr, login=False, api=False)
    else:
        return rt("user.html", user_name = request.remote_addr, login=False, api=False)
@app.route("/login")
def login():
    return rt("login.html")
@app.route("/signup")
def signup():
    return rt("signup.html")
@app.route("/signup_form", methods=['POST'])
def signup_form():
    if has_user(request.form["id"]):
        return rt("error.html", error="이미 존재하는 사용자 이름입니다.")
    if is_valid_ip(request.form["id"]) or is_valid_cidr(request.form["id"]):
        return rt("error.html", error="IP나 CIDR 형식의 사용자 이름은 사용이 불가능합니다.")
    if request.form['pw'] != request.form['pw2']:
        return rt("error.html", error="비밀번호가 일치하지 않습니다.")
    c.execute('''insert into user (name, password, isip, ban)
values (?,?,0,0)''', (request.form['id'], hashlib.sha3_512(request.form['pw'].encode()).hexdigest()))
    u = c.lastrowid
    #run_sqlscript("doc_edit.sql", ("사용자:{0}".format(request.form['id']), '', 0, u, "NULL", str(datetime.datetime.now()), 0))
    c.execute('''insert into api_key_perm
select ?, name, case value
	when 0 then 1
	when 1 then 1
	when 2 then 0
	end
from api_policy''', (u,))
    return redirect('/')
@app.route("/login_form", methods=['POST'])
def login_form():
    if c.execute('''select exists (
	select 1
	from user
	where name = ?
	and password = ?
	and isip = 0
)''', (request.form['id'], hashlib.sha3_512(request.form['pw'].encode()).hexdigest())).fetchone()[0]:
        if "keep" in request.form:
            session.permanent = True
        session['id'] = c.execute('''select id
from user
where name = ?''', (request.form['id'],)).fetchone()[0]
        return redirect('/')
    else:
        return rt("error.html", error="아이디나 비밀번호가 일치하지 않습니다.")
@app.route("/logout")
def logout():
    session.clear()
    return redirect('/')
@app.route("/history/<path:doc_name>")
def history(doc_name):
    h = c.execute('''select name, datetime, length, rev, edit_comment, dsc
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
order by rev desc''', (doc_name,)).fetchall()
    return rt("history.html", history=h, doc_name=doc_name)
@app.route("/sql")
def sqldump():
    if not isowner():
        abort(403)
    with open("dump.sql", "w", encoding='utf-8') as f:
        for l in db.iterdump():
            f.write("%s\n" % l)
    return send_file("dump.sql", as_attachment=True)
@app.route("/sql_shell", methods=['GET', 'POST'])
def sqlshell():
    if not isowner():
        abort(403)
    if request.method == "GET":
        return rt("sql_shell.html", prev_sql = "", result = "")
    else:
        try:
            result = str(c.execute(request.form["sql"]).fetchall())
        except:
            result = "SQL 문이 잘못되었습니다"
        return rt("sql_shell.html", prev_sql = request.form["prev"] + "\n" + request.form["sql"], result = result)
@app.route("/owner_tool")
def owner_tool():
    if not isowner():
        abort(403)
    return rt("owner_tool.html")
@app.route("/delete/<path:doc_name>")
def delete(doc_name):
    if 'id' in session:
        i = session['id']
    else:
        i = ipuser()
    if isban() != 0:
        if isban() == -2:
            return rt("banned.html", warn=True, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        elif isban() == -1:
            return rt("banned.html", warn=False, time=None, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        else:
            return rt("banned.html", warn=False, time=datetime.datetime.fromtimestamp(isban()).strftime('%Y-%m-%d %p %I:%M:%S'), reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
    return rt("document_delete.html", doc_title = doc_name, admin=isowner())
@app.route("/delete_full/<path:doc_name>")
def delete_full(doc_name):
    if 'id' in session:
        i = session['id']
    else:
        i = ipuser()
    if isban() != 0:
        if isban() == -2:
            return rt("banned.html", warn=True, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        elif isban() == -1:
            return rt("banned.html", warn=False, time=None, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        else:
            return rt("banned.html", warn=False, time=datetime.datetime.fromtimestamp(isban()).strftime('%Y-%m-%d %p %I:%M:%S'), reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
    if not isowner():
        abort(403)
    return rt("document_full_delete.html", doc_title = doc_name)
@app.route("/delete_full_form", methods=['POST'])
def delete_full_form():
    if 'id' in session:
        i = session['id']
    else:
        i = ipuser()
    if isban() != 0:
        if isban() == -2:
            return rt("banned.html", warn=True, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        elif isban() == -1:
            return rt("banned.html", warn=False, time=None, reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
        else:
            return rt("banned.html", warn=False, time=datetime.datetime.fromtimestamp(isban()).strftime('%Y-%m-%d %p %I:%M:%S'), reason=c.execute('select reason from user where id=?',(i,)).fetchone()[0])
    run_sqlscript("doc_full_delete.sql", (request.form['doc_name'],))
    return redirect("/")
"""@app.route("/api_key_requests")
def api_key_requests():
    if not isowner():
        abort(403)
    return rt("api_request.html", reqs = c.execute('''select api_key_requests.id, name
from user, api_key_requests
where user.id = user_id''').fetchall())"""
@app.route("/api_keys")
def api_keys():
    if not isowner():
        abort(403)
    return rt("api_key.html", keys = [x[0] for x in c.execute('''select name
from user, api_keys
where user.id = api_keys.user_id''').fetchall()])
@app.route("/move/<path:doc_name>")
def move(doc_name):
    return rt("document_move.html", doc_title = doc_name)
@app.route("/move_form", methods=['POST'])
def move_form():
    if 'id' in session:
        i = session['id']
    else:
        i = ipuser()
    c.execute('''update doc_name
set name = ?
where name = ?''', (request.form['to'], request.form['doc_name']))
    run_sqlscript("doc_edit.sql", (request.form['to'], f"{request.form['doc_name']}에서 {request.form['to']}로 문서 이동", 2, i, request.form["edit_comment"], str(datetime.datetime.now()), 0), [4])
    return redirect('/w/' + request.form['to'])
@app.route("/acl/<path:doc_name>")
def acl(doc_name):
    return rt("acl.html", aclcs = [
        ('문서 편집','edit'),
        ('문서 이동','move'),
        ('문서 삭제','delete'),
        ('ACL','acl')
        ], acls = [
            'any',
            'any_with_ban',
            'member',
            'admin',
            'owner'], doc_title = doc_name, hasperm = False)
"""@app.route("/api_request_accept_or_decline", methods=['POST'])
def api_request_accept_or_decline():
    if not isowner():
        abort(403)
    if request.form['result'] == 'accept':
        k = gen_random_str(int(get_config("api_key_length")))
        c.execute('''insert into api_keys
select user_id, NULL, 1
from api_key_requests
where id = ?''', (request.form['id']))
        c.execute('''insert into api_key_perm
select ?, name, case value
	when 0 then 1
	when 1 then 1
	when 2 then 0
	end
from api_policy''', (k,))
    c.execute('''delete from api_key_requests
where id=?''', (request.form['id']))
    return redirect('/')"""
@app.route("/api_perm/<id>", methods=['GET', 'POST'])
def api_perm(id):
    if not isowner():
        abort(403)
    i = user_name_to_id(id)
    if request.method == 'POST':
        c.execute('DELETE FROM api_key_perm WHERE user=?', (i,))
        for k in keyl:
            if request.form.get(keyl[k]):
                c.execute('''insert into api_key_perm
values(?,?,1)''', (i, keyl[k]))
            else:
                c.execute('''insert into api_key_perm
values(?,?,0)''', (i, keyl[k]))
        return redirect('/')
    tmp = []
    for k in keyl:
        try:
            p = c.execute("SELECT value FROM api_key_perm WHERE user = ? AND name = ?", (i, keyl[k])).fetchone()[0]
        except:
            p = 0
        tmp.append([k, keyl[k], p])
    return rt('api_perm.html', ps=tmp, id=id)
@app.route("/getkey")
def getkey():
    return rt("error.html", error="API 키 시스템 개편을 위해 현재 버전에서는 API를 사용할 수 없습니다. 이후 다시 사용 가능해질 예정입니다.")
    """if get_config("get_api_key") == "disabled":
        return rt("error.html", error="API가 비활성화된 위키입니다.")
    else:
        return rt("api_key_ok.html", key = gen_random_str(int(get_config("api_key_length"))))"""
@app.route("/api_key_delete", methods=['GET', 'POST'])
def api_key_delete():
    c.execute('delete from api_keys where key=?', (request.form['id'],))
    c.execute('delete from api_key_perm where key=?', (request.form['id'],))
    return redirect('/')
@app.route("/random")
def random_document():
    c.execute('SELECT name FROM doc_name LIMIT 1 OFFSET abs(random()) % (SELECT COUNT(*) FROM doc_name);')
    r = c.fetchone()[0]
    return redirect('/w/{0}'.format(r))
@app.route("/admin/suspend_account", methods=['GET','POST'])
def ban():
    if not isowner():
        abort(403)
    if request.method == 'POST':
        c.execute("update user set ban=case ? when '0' then case when cast(? as integer)<=0 then ? else strftime('%s','now')+? end else strftime('%s',?) end where name=?", (request.form['method'],request.form['time'],request.form['time'],request.form['time'],request.form['time'],request.form['user']))
        c.execute("update user set reason=? where name=?", (request.form['reason'],request.form['user']))
        return redirect('/')
    return rt("ban.html")
@app.route("/warn_ok")
def warn_ok():
    c.execute("update user set ban=0 where id=? and ban=-2", (ipuser(),))
    return redirect('/')
config = c.execute('''select name, value
from config
where name = "host"
or name = "port"
or name = "debug"
order by name''').fetchall()
@app.route("/upload", methods=['GET','POST'])
def upload():
    if request.method == 'POST':
        c.execute('insert into file (type,data) values(?,?)', (request.files['file'].content_type, request.files['file'].getvalue()))
        return rt('dialog_redirect.html',message='업로드된 파일은 /file/{0}(으)로 사용할수 있습니다'.format(c.execute("select seq from sqlite_sequence where name='file'").fetchone()[0]))
    return rt('upload.html')
@app.route("/file/<int:fid>")
def file(fid):
    try:
        return send_file(BytesIO(c.execute('select data from file where id=?',(fid,)).fetchone()[0]),mimetype=c.execute('select type from file where id=?',(fid,)).fetchone()[0])
    except:
        abort(404)
@app.route("/admin/extension", methods = ["GET", "POST"])
def extension_route():
    if not isowner():
        abort(403)
    if request.method == "POST":
        c.execute("DELETE from extension")
        c.executemany("INSERT INTO extension VALUES(?)", ((x,) for x in request.form.keys()))
        return redirect("/")
    else:
        return rt("extension.html", ext = extension, ena = [x[0] for x in c.execute("SELECT name FROM extension").fetchall()])
if config[0][1]=="1":
    @app.before_request
    def clear_template_cache():
        app.jinja_env.cache.clear()
@app.route("/admin/config/advanced", methods = ["GET", "POST"])
def config_advanced():
    if not isowner():
        abort(403)
    if request.method == "POST":
        c.execute("DELETE FROM config")
        c.executemany("INSERT INTO config VALUES(?,?)", request.form.items())
    return rt("owner_settings_advanced.html", settings = c.execute("SELECT name, value FROM config").fetchall(), save = request.method == "POST")
@app.route("/aclgroup", methods = ["GET", "POST"])
def aclgroup():
    delete_expired_aclgroup()
    if request.method == "POST":
        if not isowner():
            abort(403)
        t = get_utime()
        if get_config("aclgroup_note_required") == "1" and request.form["note"] == "":
            return error_400("note의 값은 필수입니다.")
        dur = 0 if request.form["dur"] == "" else int(request.form["dur"])
        if has_config("aclgroup_max_duration") and dur > int(get_config("aclgroup_max_duration")):
            return error_400(f"expire의 값은 {get_config('aclgroup_max_duration')} 이하여야 합니다.")
        gid = c.execute("SELECT id FROM aclgroup WHERE name = ?", (request.form["group"],)).fetchone()
        if gid == None:
            return error_400("aclgroup_group_not_found")
        gid = gid[0]
        if request.form["mode"] == "ip":
            ip = request.form["value"]
            if '/' not in ip:
                ip += "/128" if ':' in ip else "/32"
            if not is_valid_cidr(ip):
                return error_400("invalid_cidr")
            ip = convert_cidr(ip)
            if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_log WHERE ip = ?)", (ip,)).fetchone()[0]:
                return error_400("aclgroup_already_exists")
            c.execute("INSERT INTO aclgroup_log (gid, ip, note, start, end) VALUES(?, ?, ?, ?, ?)",
                      (gid, ip, request.form["note"], t, None if dur == 0 else t + dur))
            c.execute("INSERT INTO block_log (type, operator, target_ip, id, gid, date, duration, note) VALUES(1, ?, ?, ?, ?, ?, ?, ?)",
                      (session["id"], ip, c.lastrowid, gid, t, dur, request.form["note"]))
        else:
            if not has_user(request.form["value"]):
                return error_400("사용자 이름이 올바르지 않습니다.")
            if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_log WHERE user = (SELECT id FROM user WHERE name = ?))", (request.form["value"],)).fetchone()[0]:
                return error_400("aclgroup_already_exists")
            c.execute("INSERT INTO aclgroup_log (gid, user, note, start, end) VALUES(?, (SELECT id FROM user WHERE name = ?), ?, ?, ?)",
                      (gid, request.form["value"], request.form["note"], t, None if request.form["dur"] == "" else t + dur))
            c.execute("INSERT INTO block_log (type, operator, target, id, gid, date, duration, note) VALUES(1, ?, (SELECT id FROM user WHERE name = ?), ?, ?, ?, ?, ?)",
                      (session["id"], request.form["value"], c.lastrowid, gid, t, dur, request.form["note"]))
    groups = [x[0] for x in c.execute("SELECT name FROM aclgroup").fetchall()]
    current = request.args.get("group", groups[0] if c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup)").fetchone()[0] else "")
    return rt("aclgroup.html", groups = groups, current = current, perm = isowner(), newgroup_perm = isowner(), add_perm = isowner(), delete_perm = isowner(), record = (
        (x[0], x[1], x[2], utime_to_str(x[3]), "영구" if x[4] == None else utime_to_str(x[4]))
        for x in c.execute("SELECT id, (CASE WHEN ip IS NULL THEN (SELECT name FROM user WHERE id = user) ELSE ip END), note, start, end FROM aclgroup_log WHERE gid = (SELECT id FROM aclgroup WHERE name = ?)", (current,)).fetchall()
    ))
@app.route("/aclgroup/delete", methods = ["POST"])
def aclgroup_delete():
    if not isowner():
        abort(403)
    if get_config("aclgroup_note_required") == "1" and request.form["note"] == "":
        return error_400("note의 값은 필수입니다.")
    if not c.execute("SELECT EXISTS (SELECT 1 FROM aclgroup_log WHERE id = ?)", (request.form["id"],)).fetchone()[0]:
        return error_400("aclgroup_not_found")
    c.execute("INSERT INTO block_log (type, operator, target_ip, target, id, gid, date, note) SELECT 2, ?1, ip, user, ?2, gid, ?3, ?4 FROM aclgroup_log WHERE id = ?2",
              (session["id"], request.form["id"], get_utime(), request.form["note"]))
    c.execute("DELETE FROM aclgroup_log WHERE id = ?", (request.form["id"],))
    return '', 204
@app.route("/aclgroup/new_group", methods = ["POST"])
def aclgroup_new_group():
    if not isowner():
        abort(403)
    c.execute("INSERT INTO aclgroup (name, readperm, addperm, deleteperm, warn_msg, style) VALUES(?,?,?,?,?,?)",
              (request.form["group"],request.form["read"],request.form["add"],request.form["delete"],request.form["warn"],request.form["css"]))
    return redirect("/aclgroup?group={0}".format(request.form["group"]))
@app.route("/aclgroup/delete_group", methods = ["POST"])
def aclgroup_delete_group():
    if not isowner():
        abort(403)
    c.execute("DELETE FROM aclgroup WHERE name = ?", (request.form["group"],))
    return redirect("/aclgroup")
@app.route("/api/hasuser/<name>")
def api_hasuser(name):
    return Response("1" if has_user(name) else "0", mimetype="text/plain")
@app.route("/api/hasuser1/<name>")
def api_hasuser1(name):
    return Response("1" if has_user(name, True) else "0", mimetype="text/plain")
@app.route("/BlockHistory")
def block_history():
    return rt("block_history.html", log = [
        (x[0], x[1], (x[3] if x[2] == None else x[2]), x[2] != None, x[4], x[5], utime_to_str(x[6]), None if x[7] == None else time_to_str(x[7]), x[8], x[9]) for x in
        c.execute("""SELECT type, u1.name, target_ip, u2.name, block_log.id, aclgroup.name, date, duration, grant_perm, note FROM block_log
LEFT JOIN user AS u1 ON block_log.operator = u1.id
LEFT JOIN user AS u2 ON block_log.target = u2.id
LEFT JOIN aclgroup ON block_log.gid = aclgroup.id""").fetchall()], note_ext = True)
app.run(debug=get_config("debug")=="1", host=get_config("host"), port=int(get_config("port")))
