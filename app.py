from flask import Flask, render_template, request, redirect
import sqlite3
import json
import hashlib
import os
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
# DB 로딩
try:
    with open('data.json') as f:
        db = json.load(f)
except:
    db = {}
print(db)
initial_table = ['document', 'other']
for t in initial_table:
    if t not in db:
        db[t] = {}
print(db)
if 'host' not in db['other']:
    db['other']['host'] = input('위키 호스트 입력 -> ')
if 'port' not in db['other']:
    db['other']['port'] = input('위키 포트 입력 -> ')
if 'debug' not in db['other']:
    db['other']['debug'] = False
save_db()
app = Flask(__name__)
@app.route("/")
def redirect_frontpage():
    return redirect("/w/FrontPage")
@app.route("/template_test/<t>")
def master(t):
    if not request.remote_addr == '127.0.0.1' and not request.remote_addr == '::1':
        return '', 404
    return render_template(t, wiki_title = "TheWiki", wiki_name = "TheWiki", doc_title = "123", doc_data="<h1>Test</h1><br>Test")
@app.route("/w/<path:doc_title>")
def doc_read(doc_title):
    try:
        d = db['document'][doc_title]
        code = 200
    except:
        d = f'''<h2>오류! 이 문서는 존재하지 않습니다</h2>
<a href="/edit/{doc_title}" style="border: 1px solid #808080;
            padding: 5px 13px;
            color: unset;
            text-decoration: none;
            line-height: 23px;">새 문서 만들기</a>'''
        code = 404
    return render_template("document_read.html", wiki_title = "Wiki",
    wiki_name = "Wiki", doc_title=doc_title, doc_data=d), code
@app.route("/edit/<path:doc_title>")
def doc_edit(doc_title):
    try:
        d = db['document'][doc_title]
    except:
        d = ""
    return render_template("document_edit.html", wiki_title = "Wiki",
    wiki_name = "Wiki", doc_title=doc_title, doc_data=d, doc_rev="1")

@app.route("/edit_form", methods = ['POST'])
def doc_edit_form():
    doc_name = request.form["doc_name"]
    value = request.form["value"]
    print(f'{doc_name} 문서를 {value} 내용으로 편집할 려고 했습니다')
    db['document'][doc_name] = value
    save_db()
    return redirect(f"/w/{doc_name}")
@app.route("/license")
def license():
    with open("license.html", encoding='utf-8') as f:
        license = f.read()
    return render_template("license.html", wiki_title = "Wiki", wiki_name = "Wiki", l = license)
@app.route("/owner_settings")
def owner_settings():
    if request.remote_addr != '127.0.0.1':
        return '', 403
    return render_template("owner_settings.html", wiki_title = "Wiki", wiki_name = "Wiki",
                           wiki_host = db['other']['host'], wiki_port = db['other']['port'], debug = db['other']['debug'])
@app.route("/owner_settings_form", methods = ['POST'])
def owner_settings_save():
    db['other']['host'] = request.form['host']
    db['other']['port'] = request.form['port']
    if request.form.get('debug'):
        db['other']['debug'] = True
    else:
        db['other']['debug'] = False
    save_db()
    return redirect('/')
#@app.route("/commit")
def commit():
    print("COMMIT")
    conn.commit()
    conn.close()
    return redirect("/")
app.run(debug=db['other']['debug'], host=db['other']['host'], port=db['other']['port'])
