from flask import Flask, request, redirect, session, send_file, abort, Response
from flask import render_template
from io import BytesIO
import hashlib
import sys
import datetime
import random
import re
import types
import ipaddress
import os
#from data import *
from tool import *
if sys.version_info < (3, 9):
    if input("경고! NewTheSeed는 Python 3.9 미만의 Python 버전은 지원하지 않으며, 이로 인해 발생하는 버그(보안취약점 포함)는 수정되지 않습니다. 계속하려면 y를 입력해주세요. -> ") != "y":
        sys.exit()

reload_config()

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
    #print(key_req('ban', request.json.get('key', None)))
    #if not isowner(key_req('ban', request.json.get('key', None))):
    #    abort(403)
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
    
    return rt("document_edit.html", doc_title=doc_title, doc_data=d, doc_rev=r, req_captcha = is_required_captcha("edit"))

@app.route("/edit_form", methods = ['POST'])
def doc_edit_form():
    if not captcha("edit"):
        return captcha_failed()
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
"""@app.route("/admin/config")
def owner_settings():
    if not has_perm("config"):
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
    return rt("config.html",
                           wiki_host = config[2][0], wiki_port = config[4][0], wiki_owner = config[3][0], debug = config[0][0]=='1', token = config[1][0],
              keys = keys)
@app.route("/owner_settings_form", methods = ['POST'])
def owner_settings_save():
    if not has_perm("config"):
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
    return redirect('/')"""
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
    return rt("login.html", req_captcha = is_required_captcha("login"))
@app.route("/signup")
def signup():
    return rt("signup.html", req_captcha = is_required_captcha("signup"))
@app.route("/signup_form", methods=['POST'])
def signup_form():
    if not captcha("signup"):
        return captcha_failed()
    if has_user(request.form["id"]):
        return rt("error.html", error="이미 존재하는 사용자 이름입니다.")
    if is_valid_ip(request.form["id"]) or is_valid_cidr(request.form["id"]):
        return rt("error.html", error="IP나 CIDR 형식의 사용자 이름은 사용이 불가능합니다.")
    if request.form['pw'] != request.form['pw2']:
        return rt("error.html", error="비밀번호가 일치하지 않습니다.")
    first = c.execute("SELECT EXISTS (SELECT 1 FROM user)").fetchone()[0] == 0
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
    if first:
        c.executemany("INSERT INTO perm VALUES(?,?)", ((u, x) for x in first_perminssion))
    return redirect('/')
@app.route("/login_form", methods=['POST'])
def login_form():
    if not captcha("login"):
        return captcha_failed()
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
    if not has_perm("database"):
        abort(403)
    with open("dump.sql", "w", encoding='utf-8') as f:
        for l in db.iterdump():
            f.write("%s\n" % l)
    return send_file("dump.sql", as_attachment=True)
@app.route("/sql_shell", methods=['GET', 'POST'])
def sqlshell():
    if not has_perm("database"):
        abort(403)
    if request.method == "GET":
        return rt("sql_shell.html", prev_sql = "", result = "")
    else:
        try:
            result = str(c.execute(request.form["sql"]).fetchall())
        except:
            result = "SQL 문이 잘못되었습니다"
        return rt("sql_shell.html", prev_sql = request.form["prev"] + "\n" + request.form["sql"], result = result)
@app.route("/admin_tool")
def admin_tool():
    return rt("admin_tool.html")
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
    return rt("document_delete.html", doc_title = doc_name, admin=has_perm("manage_history"))
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
    if not has_perm("manage_history"):
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
    if not get_config("grant"):
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
    if not get_config("grant"):
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
    if not has_perm("admin"):
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
    if not has_perm("config"):
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
@app.route("/admin/config", methods = ["GET", "POST"])
def config_advanced():
    if not has_perm("config"):
        abort(403)
    if request.method == "POST":
        c.execute("DELETE FROM config")
        c.executemany("INSERT INTO config VALUES(?,?)", request.form.items())
    reload_config()
    return rt("owner_settings_advanced.html", settings = c.execute("SELECT name, value FROM config").fetchall(), save = request.method == "POST")
@app.route("/aclgroup", methods = ["GET", "POST"])
def aclgroup():
    delete_expired_aclgroup()
    if request.method == "POST":
        if not has_perm("admin"):
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
    return rt("aclgroup.html", groups = groups, current = current, newgroup_perm = has_perm("aclgroup"), add_perm = has_perm("admin"), delete_perm = has_perm("admin"), record = (
        (x[0], x[1], x[2], utime_to_str(x[3]), "영구" if x[4] == None else utime_to_str(x[4]))
        for x in c.execute("SELECT id, (CASE WHEN ip IS NULL THEN (SELECT name FROM user WHERE id = user) ELSE ip END), note, start, end FROM aclgroup_log WHERE gid = (SELECT id FROM aclgroup WHERE name = ?)", (current,)).fetchall()
    ))
@app.route("/aclgroup/delete", methods = ["POST"])
def aclgroup_delete():
    if not has_perm("admin"):
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
    if not has_perm("aclgroup"):
        abort(403)
    c.execute("INSERT INTO aclgroup (name, readperm, addperm, deleteperm, warn_msg, style) VALUES(?,?,?,?,?,?)",
              (request.form["group"],request.form["read"],request.form["add"],request.form["delete"],request.form["warn"],request.form["css"]))
    return redirect("/aclgroup?group={0}".format(request.form["group"]))
@app.route("/aclgroup/delete_group", methods = ["POST"])
def aclgroup_delete_group():
    if not has_perm("aclgroup"):
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
LEFT JOIN aclgroup ON block_log.gid = aclgroup.id""").fetchall()], note_ext = get_config("ext_note") == "1")
@app.route("/admin/grant", methods = ["GET", "POST"])
def grant():
    if not has_perm("grant"):
        abort(403)
    if request.method == "POST":
        if not has_user(request.args.get("username", "")):
            return error_400("사용자 이름이 올바르지 않습니다.")
        user = user_name_to_id(request.args.get("username", ""))
        placeholder = ','.join('?' * len(shared["grantable"]))
        oldperm = set(x[0] for x in c.execute(f"SELECT perm FROM perm WHERE user = ? AND perm IN ({placeholder})", [user] + shared["grantable"]).fetchall())
        c.execute(f"DELETE FROM perm WHERE user = ? AND perm IN ({placeholder})", [user] + shared["grantable"])
        newperm = set()
        for p in shared["grantable"]:
            if p in request.form:
                newperm.add(p)
        c.executemany("INSERT INTO perm VALUES(?,?)", ((user, x) for x in newperm))
        logstr = []
        for p in newperm - oldperm:
            logstr.append("+" + p) 
        for p in oldperm - newperm:
            logstr.append("-" + p)
        c.execute("INSERT INTO block_log (type, operator, target, date, grant_perm, note) VALUES(3,?,?,?,?,?)",
                  (ipuser(), user, get_utime(), " ".join(logstr), request.form["note"] if get_config("ext_note") == "1" else None))
        return '', 204
    else:
        user = request.args.get("username", "")
        if user == "":
            return rt("grant.html", user = "")
        else:
            if not has_user(user):
                return rt("grant.html", user = user, error = 1)
            else:
                return rt("grant.html", user = user, grantable = shared["grantable"], vailduser = True, ext_note = get_config("ext_note") == "1",
                        perm = set(x[0] for x in c.execute(f"SELECT perm FROM perm WHERE user = ? AND perm IN ({','.join('?' * len(shared['grantable']))})", [user_name_to_id(user)] + shared["grantable"]).fetchall()))
@app.route("/admin/captcha_test", methods = ["GET", "POST"])
def captcha_test():
    if not has_perm("config"):
        abort(403)
    if request.method == "POST":
        return rt("captcha_test.html", result = int(captcha("test")))
    return rt("captcha_test.html", req_captcha = is_required_captcha("test"), result = -1)

app.run(debug=get_config("debug")=="1", host=get_config("host"), port=int(get_config("port")))
