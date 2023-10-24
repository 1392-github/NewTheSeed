#select (case when ban<0 or ban>strftime('%s','now') then ban else 
#None", "", 0); update config set value="12345" where name = "owner";--
from flask import Flask, request, redirect, session, send_file, abort
from flask import render_template
import sqlite3
import json
import hashlib
import os
import secrets
import socket
import datetime

version = 10

keyl = {'문서 읽기' : 'read_doc',
        '문서 편집':'write_doc',
        '랜덤 문서':'randompage'
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
def run_sqlscript(filename, args = (), no_replace = []):
    with open(f"sql_script/{filename}", 'r') as f:
        args = list(args)
        for i in range(len(args)):
            if i not in no_replace:
                args[i] = str(args[i]).replace('"', '""') # SQL Injection 방지
        #print(f.read().format(*args))
        c.executescript(f.read().format(*args))
    
    return c.fetchall()
'''owner 권한 체크
/sql, /sqlshell, /owner_settings 에서 사용
권한이 있으면 True, 없으면 False'''
def isowner():
    if 'id' not in session:
        return False
    return c.execute('''select exists (
	select *
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

'''with open('pure.json') as f:
    md5t = json.load(f)
print("순정 검사 시작")
for f in md5t:
    print(f"순정 검사 중 - {f}")
    if hash(f) != md5t[f]:
        print("경고! 순정 버전이 아닙니다")
        print(f"순정 MD5 - {md5t[f]}, 검사된 MD5 - {hash(f)}")
        print("엔진을 직접 수정했거나, 다운로드 중 손상된 것 같습니다")
        print("직접 수정한 변경사항 손실 방지를 위해 업데이트 기능이 비활성화됩니다")
        break'''
# API 키 요구여부 확인 및 키에 연결된 사용자 가져오기
# 유효하지 않은 키인경우 None 반환
# API 키가 None인 경우, 키가 필요없으면 IP에 해당하는 ID 반환, 키가 필요하면 None 반환
def key_req(name, key):
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
    select *
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
# 차단 여부 확인 (None : 차단안됨, -1 : 영구차단, -2 : 경고)
def isban():
    if 'id' in session:
        return c.execute("select case when ban<0 or ban>strftime('%s','now') then ban else 0 end from user where id=?", (session['id'],)).fetchone()[0]
    else:
        return c.execute("select case when ban<0 or ban>strftime('%s','now') then ban else 0 end from user where id=?", (ipuser(),)).fetchone()[0]
def rt(t, **kwargs):
    k = kwargs
    k['wiki_title'] = "TheWiki"
    k['wiki_name'] = "TheWiki"
    k['isowner'] = isowner()
    return render_template(t, **k)

# 함수 정의 끝, 초기화 부분 시작

# DB 로딩
db = sqlite3.connect("data.db", isolation_level=None, check_same_thread=False)
c = db.cursor()
run_sqlscript("db_stu.sql") # DB 구조 만들기
c.execute('''insert into config
select "version", ?
where not exists (
	select *
	from config
	where name = "version"
);''', (version,))
print(f"The Wiki Engine 버전 : {version}")
db_version = c.execute('''select value
from config
where name = "version";''').fetchone()[0]
print(f"DB 버전 : {db_version}")
if int(db_version) > version:
    print("경고 : 상위 버전 The Wiki Engine의 DB입니다")
    print("DB 손상 위험이 있을 수도 있습니다")
    if input("그래도 계속 진행하려면 Y를 입력해주세요 -> ") != "Y":
        os.exit(0)

# DB 변환 코드
if int(db_version) < 6:
    # discuss_seq 컬럼 추가
    c.execute("alter table doc_name add discuss_seq INTEGER")
if int(db_version) < 8:
    # discuss_seq 컬럼의 데이터 타입 오류 수정
    c.executescript('''alter table doc_name drop column discuss_seq;
                       alter table doc_name add column discuss_seq INTEGER;''')
    # config에 get_api_key 추가
    c.execute("insert into config values('get_api_key', 'disabled')")
if int(db_version) < 10:
    # ban, reason 컬럼 추가
    c.executescript('''alter table user add ban INTEGER;
alter table user add reason TEXT;
update user set ban=0;''')

c.execute('''update config
set value = ?
where name = "version"''', (str(version),)) # 변환 후 버전 재설정
if c.execute('''select exists (
	select *
	from config
	where name = "host"
);''').fetchone()[0] == 0:
    c.execute('insert into config values("host", ?)', (input('위키 호스트 입력 -> '),))
if c.execute('''select exists (
	select *
	from config
	where name = "port"
);''').fetchone()[0] == 0:
    c.execute('insert into config values("port", ?)', (input('위키 포트 입력 -> '),))
if c.execute('''select exists (
	select *
	from config
	where name = "owner"
);''').fetchone()[0] == 0:
    c.execute('insert into config values("owner", ?)', (input('위키 소유자 입력 -> '),))
if c.execute('''select exists (
	select *
	from config
	where name = "debug"
);''').fetchone()[0] == 0:
    c.execute('insert into config values("debug", "0")')
if c.execute('''select exists (
	select *
	from config
	where name = "get_api_key"
);''').fetchone()[0] == 0:
    c.execute('insert into config values("get_api_key", "disabled")')

app = Flask(__name__)
app.secret_key = "32948j1928741ajdsfsdajfkl"
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
    run_sqlscript("doc_edit.sql", (doc_name, value, 0, i, ('"' + (request.json.get('edit_comment', "None").replace('"', '""')) + '"') if request.json.get("edit_comment", None) != "" else "NULL", str(datetime.datetime.now()), len(value) - len(prev_content)), [4])
    return {}
@app.route("/api/randompage", methods=['POST'])
def api_randompage():
    if key_req('randompage', request.json.get('key', None)) == None:
        abort(403)
    c.execute('select name from doc_name order by random() limit 1')
    r = c.fetchone()[0]
    return {'name':r}
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
    print(i)
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
    run_sqlscript("doc_edit.sql", (doc_name, value, 0, i, ('"' + request.form["edit_comment"].replace('"', '""') + '"') if request.form["edit_comment"] != "" else "NULL", str(datetime.datetime.now()), len(value) - len(prev_content)), [4])
    #db.commit()
    return redirect(f"/w/{doc_name}")
@app.route("/license")
def license():
    with open("license.html", encoding='utf-8') as f:
        license = f.read()
    return rt("license.html", l = license)
@app.route("/owner_settings")
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
    print(apis)
    #db.autocommit = False
    c.execute('BEGIN')
    c.execute('DELETE FROM api_policy')
    for api in apis:
        if api[1] not in ['allowed_without_key', 'allowed', 'request']:
            c.execute('ROLLBACK')
            #db.autocommit = True
            abort(400)
            return
        else:
            c.execute('''insert into api_policy
select ?, case ?
	when 'allowed_without_key' then 0
	when 'allowed' then 1
	when 'request' then 2
end''', (api[0], api[1]))
    else:
        c.execute('COMMIT')
        #db.autocommit = True
    return redirect('/')
@app.route("/user")
def user():
    if 'id' in session:
        try:
            api = c.execute('''select exists (
	select *
	from config
	where name = 'get_api_key'
	and value <> 'disabled'
)''').fetchone()[0]==1
            
            key = c.execute('''select key
from api_keys
where user_id = ?''', (session["id"],)).fetchone()
            return rt("user.html", user_name = c.execute('''select name
from user
where id = ?''', (session["id"],)).fetchone()[0], login=True, api=api, key=None if key==None else key[0])
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
    if request.form['pw'] != request.form['pw2']:
        return rt("wrong_password2.html")
    c.execute('''insert into user (name, password, isip, ban)
values (?,?,0,0)''', (request.form['id'], hashlib.sha3_512(request.form['pw'].encode()).hexdigest()))
    return redirect('/')
@app.route("/login_form", methods=['POST'])
def login_form():
    #if db['user'][request.form['id']]['pw'] == hashlib.sha3_512(request.form['pw'].encode()).hexdigest():
    if c.execute('''select exists (
	select *
	from user
	where name = ?
	and password = ?
	and isip = 0
)''', (request.form['id'], hashlib.sha3_512(request.form['pw'].encode()).hexdigest())).fetchone()[0]:
        session['id'] = c.execute('''select id
from user
where name = ?''', (request.form['id'],)).fetchone()[0]
        print("Session - " + str(session['id']))
        return redirect('/')
    else:
        return rt("wrong_password.html")
@app.route("/logout")
def logout():
    session.pop("id", None)
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
    with open("dump.sql", "w") as f:
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
@app.route("/api_key_requests")
def api_key_requests():
    if not isowner():
        abort(403)
    return rt("api_request.html", reqs = c.execute('''select api_key_requests.id, name
from user, api_key_requests
where user.id = user_id''').fetchall())
@app.route("/api_keys")
def api_keys():
    if not isowner():
        abort(403)
    return rt("api_key.html", keys = c.execute('''select name, key
from user, api_keys
where user.id = api_keys.user_id''').fetchall())
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
    run_sqlscript("doc_edit.sql", (request.form['to'], f"{request.form['doc_name']}에서 {request.form['to']}로 문서 이동", 2, i, ('"' + request.form["edit_comment"] + '"') if request.form["edit_comment"] != "" else "NULL", str(datetime.datetime.now()), 0), [4])
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
@app.route("/api_request_accept_or_decline", methods=['POST'])
def api_request_accept_or_decline():
    if not isowner():
        abort(403)
    if request.form['result'] == 'accept':
        k = secrets.token_hex(64)
        c.execute('''insert into api_keys
select user_id, ?
from api_key_requests
where id = ?''', (k, request.form['id']))
        c.execute('''insert into api_key_perm
select ?, name, case value
	when 0 then 1
	when 1 then 1
	when 2 then 0
	end
from api_policy''', (k,))
    c.execute('''delete from api_key_requests
where id=?''', (request.form['id']))
    return redirect('/')
@app.route("/api_perm/<key>", methods=['GET', 'POST'])
def api_perm(key):
    if not isowner():
        abort(403)
    if request.method == 'POST':
        c.execute('DELETE FROM api_key_perm WHERE key=?', (key,))
        for k in keyl:
            if request.form.get(keyl[k]):
                c.execute('''insert into api_key_perm
values(?,?,1)''', (key, keyl[k]))
            else:
                c.execute('''insert into api_key_perm
values(?,?,0)''', (key, keyl[k]))
        return redirect('/')
    tmp = []
    for k in keyl:
        try:
            p = c.execute('''select value
    from api_key_perm
    where key = ?
    and name = ?''', (key, keyl[k])).fetchone()[0]
        except:
            p = 0
        tmp.append([k, keyl[k], p])
    return rt('api_perm.html', ps=tmp, key=key)
@app.route("/getkey")
def getkey():
    if 'id' not in session:
        abort(403)
    api = c.execute('''select exists (
	select *
	from config
	where name = 'get_api_key'
	and value <> 'disabled'
)''').fetchone()[0]==1
    if not api:
        abort(403)
    c.execute('''insert into api_key_requests (user_id)
values(?)''', (session['id'],))
    return redirect('/')
@app.route("/api_key_delete", methods=['POST'])
def api_key_delete():
    c.execute('delete from api_keys where key=?', (request.form['id'],))
    c.execute('delete from api_key_perm where key=?', (request.form['id'],))
    return redirect('/')
@app.route("/random")
def random():
    c.execute('select name from doc_name order by random() limit 1')
    r = c.fetchone()[0]
    return redirect('/w/{0}'.format(r))
@app.route("/ban", methods=['GET','POST'])
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
app.run(debug=config[0][1]=="1", host=config[1][1], port=config[2][1])
