from flask import Flask, request, redirect, session
from flask import render_template
import sqlite3
import json
import hashlib
import os
import secrets
import socket
import datetime
def hash(path):
    f = open(path, 'rb')
    data = f.read()
    hash = hashlib.md5(data).hexdigest()
    return hash
def save_db():
    with open('data.json', 'w', encoding='UTF-8') as f:
        json.dump(db, f, indent=4, ensure_ascii=False)
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
    return render_template(t, **k)
# DB 로딩
try:
    with open('data.json') as f:
        db = json.load(f)
except:
    db = {}
initial_table = ['document', 'user', 'other']
for t in initial_table:
    if t not in db:
        db[t] = {}
if 'host' not in db['other']:
    db['other']['host'] = input('위키 호스트 입력 -> ')
if 'port' not in db['other']:
    db['other']['port'] = input('위키 포트 입력 -> ')
if 'owner' not in db['other']:
    db['other']['owner'] = input('위키 소유자 입력 -> ')
if 'debug' not in db['other']:
    db['other']['debug'] = False
save_db()
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
        d = db['document'][doc_title]["content"]
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
        d = db['document'][doc_title]["content"]
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
    if doc_name not in db['document']:
        db['document'][doc_name] = {}
    if 'history' not in db['document'][doc_name]:
        db['document'][doc_name]['history'] = []
    nh = {}
    try:
        nh['contributor'] = session['id']
    except:
        nh['contributor'] = request.remote_addr
    nh['content'] = request.form["value"]
    nh['date'] = str(datetime.datetime.now())
    nh['edit_comment'] = request.form["edit_comment"]
    try:
        nh['length'] = len(request.form["value"]) - len(db['document'][doc_name]['content'])
    except:
        nh['length'] = len(request.form["value"])
    db['document'][doc_name]['history'].append(nh)
    db['document'][doc_name]["content"] = value
    save_db()
    return redirect(f"/w/{doc_name}")
@app.route("/license")
def license():
    with open("license.html", encoding='utf-8') as f:
        license = f.read()
    return rt("license.html", l = license)
@app.route("/owner_settings")
def owner_settings():
    if 'id' not in session:
        return '', 403
    if session['id'] != db['other']['owner']:
        return '', 403
    return rt("owner_settings.html",
                           wiki_host = db['other']['host'], wiki_port = db['other']['port'], wiki_owner = db['other']['owner'], debug = db['other']['debug'])
@app.route("/owner_settings_form", methods = ['POST'])
def owner_settings_save():
    if 'id' not in session:
        return '', 403
    if session['id'] != db['other']['owner']:
        return '', 403
    db['other']['host'] = request.form['host']
    db['other']['port'] = request.form['port']
    db['other']['owner'] = request.form['owner']
    
    if request.form.get('debug'):
        db['other']['debug'] = True
    else:
        db['other']['debug'] = False
    save_db()
    return redirect('/')
@app.route("/user")
def user():
    if 'id' in session:
        return rt("user.html", user_name = session['id'], login=True)
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
        return rt("wrong_password2.html", )
    db['user'][request.form['id']] = {}
    db['user'][request.form['id']]['pw'] = hashlib.sha3_512(request.form['pw'].encode()).hexdigest()
    save_db()
    return redirect('/')
@app.route("/login_form", methods=['POST'])
def login_form():
    if db['user'][request.form['id']]['pw'] == hashlib.sha3_512(request.form['pw'].encode()).hexdigest():
        '''token = secrets.token_hex(8)
        session[token] = request.form['id']
        resp = redirect('/')
        resp.set_cookie('session', token)'''
        session['id'] = request.form['id']
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
app.run(debug=db['other']['debug'], host=db['other']['host'], port=db['other']['port'])
 
