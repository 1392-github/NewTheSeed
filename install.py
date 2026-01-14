import secrets
import os
import sys
import platform
import hashlib

from flask import Flask, request, redirect, abort, Response, url_for, render_template, g
#import distro

import tool
import data

os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.environ["GIT_TERMINAL_PROMPT"]="0"
print("Installing PIP Package")
#os.system("pip install -r requirements.txt")
#install_pin = str(secrets.randbelow(1000000000)).zfill(9)
install_pin = "000000000"
app = Flask(__name__, template_folder="install_templates")
print(f"Install PIN : {install_pin}")
wiki_name = "00위키"
namespace_name = [
    ("deluser", "삭제된사용자"),
    ("wikiname", None),
    ("templete", "템플릿"),
    ("trash", "휴지통"),
    ("filetrash", "파일휴지통"),
    ("wikisec", "위키운영"),
]
if os.path.exists("INSTALL_STATUS"):
    with open("INSTALL_STATUS", "r", encoding="utf-8") as f:
        install_status = int(f.read()[-1])
else:
    install_status = 0
@app.before_request
def before_request():
    global install_status
    if request.endpoint != "input_pin":
        if request.cookies.get("pin", "") != install_pin:
            return render_template("password.html"), 403
        if request.endpoint != "restart":
            if install_status == 1: return render_template("install_crash_error.html")
            if install_status == 2: return render_template("reinstall.html")
            else:
                with open("INSTALL_STATUS", "w", encoding="utf-8") as f:
                    f.write(data.install_status + "1")
    g.db = tool.getdb()
tool.run_sqlscript("db_stu.sql")
@app.teardown_request
def closedb(e):
    if hasattr(g, "db"):
        g.db.close()
@app.route("/input_pin", methods = ["POST"])
def input_pin():
    resp = redirect(url_for("welcome"))
    request.cookies["admin"] == "true"
    resp.set_cookie("pin", request.form["pin"], httponly=True)
    return resp
@app.route("/", methods = ["GET", "POST"])
def select_lang():
    return redirect(url_for("welcome"))
    #return render_template("select_lang.html")
@app.route("/restart", methods = ["POST"])
def restart():
    global install_status
    with g.db.cursor() as c:
        for i in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
            c.execute(f"DELETE FROM {i[0]}")
    install_status = 0
    with open("INSTALL_STATUS", "w", encoding="utf-8") as f:
        f.write(data.install_status + "1")
    return redirect(url_for("welcome"))
@app.route("/0")
def welcome():
    """system = platform.system()
    release = platform.release()
    os_name = f"{system} {release}"
    os_good = False
    if system == "Windows":
        if release in ["7", "8", "8.1", "10"]:
            os_good = True
        if sys.getwindowsversion().build >= 22000:
            os_name = "Windows 11"
    elif system == "Linux":
        id = distro.id() or "unknown"
        major = int(distro.major_version() or 0)
        minor = int(distro.minor_version() or 0)
        os_name = f"{distro.name() or 'unknown'} {distro.version() or '0'}"
        if id == "ubuntu":
            if major > 20: os_good = True
            if major == 20 and minor >= 4: os_good = True
        elif id == "debian":
            if major >= 12: os_good = True
        elif id == "rhel":
            if major >= 9: os_good = True
        elif id == "centos":
            if major >= 9: os_good = True
        elif id == "sles":
            if major >= 15: os_good = True"""
    python = sys.version_info
    python_good = python >= (3, 10)
    return render_template("welcome.html", version = data.version, python = f"Python {python.major}.{python.minor}.{python.micro}",
                           python_good = python_good)
@app.route("/1", methods = ["GET", "POST"])
def wiki_name_set():
    if request.method == "POST":
        global wiki_name
        wiki_name = request.form["name"]
        data.default_config["wiki_name"] = wiki_name
        if request.form["license_type"] == "ccl":
            license_name = "CC BY"
            license_link = "https://creativecommons.org/licenses/by"
            if "nc" in request.form:
                license_name += "-NC"
                license_link += "-nc"
            if "sa" in request.form:
                license_name += "-SA"
                license_link += "-sa"
            elif "nd" in request.form:
                license_name += "-ND"
                license_link += "-nd"
            ver = request.form["ccl_version"]
            if ver == "1":
                license_name += " 1.0"
                license_link += "/1.0/"
                if license_name == "CC BY-NC-ND 1.0":
                    license_name = "CC BY-ND-NC 1.0"
                    license_link = "https://creativecommons.org/licenses/by-nd-nc/1.0/"
            elif ver == "2":
                license_name += " 2.0"
                license_link += "/2.0/"
            elif ver == "2k":
                license_name += " 2.0 KR"
                license_link += "/2.0/kr/"
            elif ver == "25":
                license_name += " 2.5"
                license_link += "/2.5/"
            elif ver == "3":
                license_name += " 3.0 Unported"
                license_link += "/3.0/"
            else:
                license_name += " 4.0"
                license_link += "/4.0/"
        elif request.form["license_type"] == "cc0":
            license_name = "CC0 1.0"
            license_link = "https://creativecommons.org/publicdomain/zero/1.0/"
        else:
            license_name = "라이선스 미설정"
            license_link = "https://example.com"
        data.default_config["document_license"] = f'이 저작물은 <a href="{license_link}">{license_name}</a>에 따라 이용할 수 있습니다. (단, 라이선스가 명시된 일부 문서 및 삽화 제외)<br>\
기여하신 문서의 저작권은 각 기여자에게 있으며, 각 기여자는 기여하신 부분의 저작권을 갖습니다.'
        data.default_config["document_license_checkbox"] = f'문서 편집을 저장하면 당신은 기여한 내용을 <b>{license_name}</b>으로 배포하고 기여한 문서에 대한 하이퍼링크나 URL을 이용하여 저작자 표시를 하는 것으로 충분하다는 데 동의하는 것입니다. <b>이 동의는 철회할 수 없습니다.</b>'
        return redirect(url_for("create_owner"))
    return render_template("wiki_name.html")
@app.route("/2", methods = ["GET", "POST"])
def create_owner():
    if request.method == "POST":
        if request.form["pw"] != request.form["pw2"]:
            return render_template("create_owner.html", error = True)
        with g.db.cursor() as c:
            id = tool.signup(request.form["id"], request.form["pw"])
            c.execute("INSERT INTO perm (user, perm) VALUES(?, 'developer')", (id,))
        return redirect(url_for("create_namespace"))
    return render_template("create_owner.html")
@app.route("/3", methods = ["GET", "POST"])
def create_namespace():
    if request.method == "POST":
        global namespace
        namespace = [0,0,0,0,0,0] # 삭제된사용자, 00위키, 템플릿, 휴지통, 파일휴지통, 위키운영 / 0은 미생성
        with g.db.cursor() as c:
            if "frame" in request.form: tool.run_sqlscript("default_namespace1.sql")
            else:
                tool.run_sqlscript("default_namespace.sql")
                data.default_config["file_namespace"] = "2"
                data.default_config["category_namespace"] = "3"
                data.default_config["user_namespace"] = "4"
            for i,v in enumerate(namespace_name):
                if v[0] in request.form:
                    c.execute("INSERT INTO namespace (name) VALUES(?)", (wiki_name if i == 1 else v[1],))
                    namespace[i] = c.lastrowid
        data.default_config["deleted_user_namespace"] = str(namespace[0])
        return redirect(url_for("aclgroup_nsacl"))
    return render_template("create_namespace.html", wikiname = wiki_name)
@app.route("/4", methods = ["GET", "POST"])
def aclgroup_nsacl():
    if request.method == "POST":
        global aclgroup
        aclgroup = [0,0,0,0,0] # 차단된 사용자, 로그인 허용 차단, 편집요청 차단, 경고, 인증된 사용자
        with g.db.cursor() as c:
            # ACLGroup 생성
            for i,k,v in (
                (0, "blocked_user", "차단된 사용자"),
                (1, "login_allow_block", "로그인 허용 차단"),
                (2, "edit_request_block", "편집요청 차단"),
                (3, "warning", "경고"),
                (4, "verified", "인증된 사용자"),
            ):
                if k not in request.form: continue
                c.execute("INSERT INTO aclgroup (name) VALUES(?)", (v,))
                id = c.lastrowid
                c.executemany("INSERT INTO aclgroup_config (gid, name, value) VALUES(?,?,?)",
                            ((id, x[0], x[1]) for x in data.default_aclgroup_config))
                aclgroup[i] = id
            # condtype, value, value2, action
            # 읽기 acl
            read_nsacl = [("aclgroup", None, aclgroup[4], "allow") if "block_unverified_read" in request.form else ("perm", "any", None, "allow")]
            """
                <label><input type="checkbox" name="allow_editreq_normal_block" checked> 일반 차단 시에도 편집 요청 허용</label><br>
                <label><input type="checkbox" name="allow_editreq_loginallow_block" checked> 로그인 허용 차단 시에도 편집 요청 허용</label><br>
                <label><input type="checkbox" name="allow_userdoc_acl"> 사용자 문서의 ACL을 본인이 조정할 수 있도록 허용</label><br>
                <label><input type="checkbox" name="only_allow_login"> 모든 IP에서 로그인 상태에서만 활동 가능</label><br>
                <label><input type="checkbox" name="block_deleteuser_read"{% if disable_block_deleteuser_read %} disabled{% endif %}> 삭제된사용자 이름공간을 관리자만 읽기 가능</label><br>
                <label><input type="checkbox" name="block_blocked_read"> 일반 차단 시 읽기 차단</label><br>
                <label><input type="checkbox" name="block_login_allow_blocked_read"> 로그인 허용 차단 시 비로그인 읽기 차단</label><br>
                <label><input type="checkbox" name="allow_editreq_unauth" disabled> 미인증 시에도 편집 요청 허용</label><br>
                <label><input type="checkbox" name="block_unverified_read" disabled> 미인증 시 읽기 차단</label><br><br>
            """
            if "block_blocked_read" in request.form:
                read_nsacl.insert(0, ("aclgroup", None, aclgroup[0], "deny"))
            
    return render_template("aclgroup_nsacl.html", disable_block_deleteuser_read = namespace[0] == 0)
if __name__ == "__main__":
    @app.before_request
    def clear_template_cache():
        app.jinja_env.cache.clear()
    app.run(port = 5000, debug = True)