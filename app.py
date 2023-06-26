from flask import Flask, request, redirect, session, send_file
from flask import render_template
import sqlite3
import json
import hashlib
import os
import secrets
import socket
import datetime

version = 5

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
def rt(t, **kwargs):
    k = kwargs
    k['wiki_title'] = "TheWiki"
    k['wiki_name'] = "TheWiki"
    k['isowner'] = isowner()
    return render_template(t, **k)
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
)''', (str(session['id']))).fetchone()[0] == 1
# DB 로딩
db = sqlite3.connect("data.db", isolation_level=None, check_same_thread=False)
c = db.cursor()
run_sqlscript("db_stu.sql") # DB 구조 만들기
c.execute('''insert into config
select "version", "5"
where not exists (
	select *
	from config
	where name = "version"
);''')
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

c.execute('''update config
set value = ?
where name = "version"''', str(version)) # 변환 후 버전 재설정
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
app = Flask(__name__)
app.secret_key = "32948j1928741ajdsfsdajfkl"
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
        d = c.execute('''select content
from history
where doc_id = (
	select id
	from doc_name
	where name = ?
)
group by doc_id
having rev = max(rev)''', (doc_title,)).fetchone()[0]
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
        d = c.execute('''select content
from history
where doc_id = (
	select id
	from doc_name
	where name = ?
)
group by doc_id
having rev = max(rev)''', (doc_title,)).fetchone()[0]
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
    return rt("document_raw.html", doc_title=doc_title, doc_data=d), code
@app.route("/edit/<path:doc_title>")
def doc_edit(doc_title):
    try:
        d = db['document'][doc_title]["content"]
    except:
        d = ""
    return rt("document_edit.html", doc_title=doc_title, doc_data=d, doc_rev="1")

@app.route("/edit_form", methods = ['POST'])
def doc_edit_form():
    doc_name = request.form["doc_name"]
    value = request.form["value"]
    """if c.execute('''select exists (
	select *
	from doc_name
	where name = ?
)''', (doc_name,)).fetchone()[0] == 0:
        c.execute('''
        insert into doc_name (name)
values("Test Document 2")'''
                  )"""
        
        
    
    try:
        prev_content = c.execute('''select content
from history
where doc_id = (
	select id
	from doc_name
	where name = ?
)
group by doc_id
having rev = max(rev)''', (doc_title,)).fetchone()[0]
    except:
        prev_content = ""
    if 'id' in session:
        i = session['id']
    else:
        c.execute('''insert into user (name, isip)
select ?, 1
where not exists (
	select *
	from user
	where name = ?
	and isip = 1
)''', (request.remote_addr, request.remote_addr))
        i = c.execute('''select id
from user
where name = ?
and isip = 1''', (request.remote_addr,)).fetchone()[0]
    run_sqlscript("doc_edit.sql", (doc_name, value, 0, i, ('"' + request.form["edit_comment"] + '"') if request.form["edit_comment"] != "" else "NULL", str(datetime.datetime.now()), len(value) - len(prev_content)), [4])
    db.commit()
    return redirect(f"/w/{doc_name}")
@app.route("/license")
def license():
    with open("license.html", encoding='utf-8') as f:
        license = f.read()
    return rt("license.html", l = license)
@app.route("/owner_settings")
def owner_settings():
    if not isowner():
        return '', 403
    config = c.execute('''select value
from (
select name, value
from config
where name = "host"
or name = "port"
or name = "owner"
or name = "debug"
order by name)''').fetchall()
    return rt("owner_settings.html",
                           wiki_host = config[1][0], wiki_port = config[3][0], wiki_owner = config[2][0], debug = config[0][0]==1)
@app.route("/owner_settings_form", methods = ['POST'])
def owner_settings_save():
    if not isowner():
        return '', 403
    if request.form.get('debug'):
        dbg = "1"
    else:
        dbg = "0"
    run_sqlscript("save_owner_settings.sql", (request.form['host'], request.form['port'], request.form['owner'], dbg))
    return redirect('/')
@app.route("/user")
def user():
    if 'id' in session:
        return rt("user.html", user_name = c.execute('''select name
from user
where id = ?''', (session["id"],)).fetchone()[0], login=True)
    else:
        return rt("user.html", user_name = request.remote_addr, login=False)
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
    c.execute('''insert into user (name, password, isip)
values (?,?,0)''', (request.form['id'], hashlib.sha3_512(request.form['pw'].encode()).hexdigest()))
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
@app.route("/history/<doc_name>")
def history(doc_name):
    return rt("history.html", history=db['document'][doc_name]['history'])
@app.route("/sql")
def sqldump():
    if not isowner():
        return '', 403
    with open("dump.sql", "w") as f:
        for l in db.iterdump():
            f.write("%s\n" % l)
    return send_file("dump.sql", as_attachment=True)
@app.route("/sql_shell", methods=['GET', 'POST'])
def sqlshell():
    if not isowner():
        return '', 403
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
        return '', 403
    return rt("owner_tool.html")
#app.run(debug=db['other']['debug'], host=db['other']['host'], port=db['other']['port'])
config = c.execute('''select name, value
from config
where name = "host"
or name = "port"
or name = "debug"
order by name''').fetchall()
app.run(debug=config[0][1]=="1", host=config[1][1], port=config[2][1])
