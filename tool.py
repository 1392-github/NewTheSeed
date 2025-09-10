from flask import Flask, request, redirect, session, send_file, abort, Response, render_template
from markupsafe import escape
from io import BytesIO
import re
import sqlite3
import hashlib
import sys
import datetime
import time
import random
import types
import ipaddress
import os
from requests import get, post
from data import *
from dataclasses import dataclass

init = not os.path.exists("data.db")
db = sqlite3.connect("data.db", isolation_level=None, check_same_thread=False)
c = db.cursor()

@dataclass
class Menu:
    name: str
    link: str
    clas: str = ""
    style: str = ""

def run_sqlscript(filename, args = ()):
    with open(f"sql_script/{filename}", 'r', encoding = 'utf-8') as f:
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
"""def isowner(user = None):
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
)''', (str(session['id']),)).fetchone()[0] == 1"""
def ipuser(create = True):
    if 'id' in session:
        return session['id']
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
"""def hasacl(cond):
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
        return isowner()"""
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
    if key is None:
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
def rt(t, **kwargs):
    k = kwargs
    k["wiki_title"] = get_config("wiki_title")
    k["wiki_name"] = get_config("wiki_name")
    k["isowner"] = has_perm("admin")
    k["version"] = version
    k["timemode"] = get_config("time_mode")
    k["captcha"] = get_config("captcha_mode") != "0"
    k["sitekey"] = get_config("captcha_sitekey")
    k["brand_color"] = get_config("brand_color")
    return render_template(t, **k)
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
    return int(time.time())
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
    if user is None:
        user = ipuser()
    ip = None
    if isinstance(user, str):
        ip = user
    elif c.execute("SELECT isip FROM user WHERE id = ?", (user,)).fetchone()[0] == 1:
        ip = c.execute("SELECT name FROM user WHERE id = ?", (user,)).fetchone()[0]
    if ip is not None:
        for i in c.execute("SELECT ip, id FROM aclgroup_log WHERE gid = ?", (group,)).fetchall():
            if i[0] is None:
                continue
            if ip_in_cidr(ip, i[0]):
                return i[1]
        return None
    else:
        r = c.execute("SELECT id FROM aclgroup_log WHERE gid = ? AND user = ?", (group, user)).fetchone()
        if r is None:
            return None
        return r[0]
def isip(user):
    if user == -1: return True
    return bool(c.execute("SELECT isip FROM user WHERE id = ?", (user,)).fetchone()[0])
def has_perm(perm, user = None, basedoc = None, docname = None):
    if user is None:
        if "id" in session:
            user = session["id"]
        else:
            return False
    if perm == "any":
        return True
    if perm == "ip":
        return isip(user)
    if user == -1:
        return False
    if perm == "member":
        return not isip(user)
    if perm == "match_username_and_document_title":
        if docname is None: return False
        colon = docname.find(":")
        if colon != -1:
            if c.execute("SELECT EXISTS (SELECT 1 FROM namespace WHERE name = ?)", (docname[:colon],)).fetchone()[0]: docname = docname[colon + 1:]
        if get_config("allow_muadt_subdoc") == "1":
            slash = docname.find("/")
            if slash != -1: docname = docname[:slash]
        return docname == id_to_user_name(user)
    if perm == "contributor":
        return bool(c.execute("SELECT EXISTS (SELECT 1 FROM history WHERE author = ?)", (user,)).fetchone()[0])
    if perm == "document_contributor":
        if basedoc is None: return False
        return bool(c.execute("SELECT EXISTS (SELECT 1 FROM history WHERE doc_id = ? AND author = ?)", (basedoc, user)).fetchone()[0])
    if perm != "developer" and has_perm("developer", user):
        return perm not in get_config("ingore_developer_perm").split(",")
    return c.execute("SELECT EXISTS (SELECT 1 FROM perm WHERE user = ? AND perm = ?)", (user, perm)).fetchone()[0] == 1
def captcha(action):
    mode = get_config("captcha_mode")
    if mode == "0": return True
    if has_perm("skip_captcha") or has_perm("no_force_captcha"): return True
    shared["captcha_bypass_cnt"].setdefault(request.remote_addr, 0)
    if shared["captcha_bypass_cnt"][request.remote_addr] > 0:
        shared["captcha_bypass_cnt"][request.remote_addr] -= 1
        return True
    if mode == "2":
        if not is_required_captcha(action): return True
        if "g-recaptcha-response" not in request.form: return False
        if post("https://www.google.com/recaptcha/api/siteverify",
                    data = {"secret": get_config("captcha_secretkey"), "response": request.form["g-recaptcha-response"]}).json()["success"]:
            shared["captcha_bypass_cnt"][request.remote_addr] = int(get_config("captcha_bypass_count"))
            return True
        else:
            return False
    elif mode == "3":
        print("경고! captcha_mode 3은 초안으로 현재 사용 불가합니다")
        return True
    elif mode == "32":
        print("경고! captcha_mode 32는 초안으로 현재 사용 불가합니다")
        return True
    else:
        print("경고! captcha_mode 는 0, 2, 3, 32 중 하나여야 합니다")
        return True
def reload_config():
    shared["grantable"] = get_config("grantable_permission").split(",")
    if has_config("captcha_required"): shared["captcha_required"] = set(get_config("captcha_required").split(","))
    if has_config("captcha_always"): shared["captcha_always"] = set(get_config("captcha_always").split(","))
    shared["username_format"] = re.compile(get_config("username_format"))
def is_required_captcha(action):
    if get_config("captcha_mode") == "0": return False
    if action == "test": return True
    if has_perm("skip_captcha") or has_perm("no_force_captcha"): return False
    req = False
    if get_config("captcha_required_type") == "black": req = action not in shared["captcha_required"]
    else: req = action in shared["captcha_required"]
    if req:
        if action in shared["captcha_always"]:
            return True
        if has_config("captcha_bypass_count"):
            shared["captcha_bypass_cnt"].setdefault(request.remote_addr, 0)
            return shared["captcha_bypass_cnt"][request.remote_addr] <= 0
        else:
            return True
    else:
        return False
def captcha_failed():
    return rt("error.html", error = "CAPTCHA 인증이 실패하였습니다.")
def get_max_captcha_bypass_count():
    if has_perm("no_force_captcha"):
        return int(get_config("captcha_bypass_count_nfc")) if has_config("captcha_bypass_count_nfc") else float("inf")
    else:
        return int(get_config("captcha_bypass_count")) if has_config("captcha_bypass_count") else 0
def split_ns(path):
    dns = int(get_config("default_namespace"))
    colon = path.find(":")
    if colon == -1: return dns, path
    else:
        c.execute("SELECT id FROM namespace WHERE name = ?", (path[:colon],))
        r = c.fetchone()
        if r is None: return dns, path
        else: return r[0], path[colon + 1:]
def render_docname(namespace, name, link=True):
    dns = int(get_config("default_namespace"))
    colon = name.find(":")
    show_ns = False
    if namespace == dns:
        if colon != -1:
            b = name[:colon]
            if c.execute("SELECT EXISTS (SELECT 1 FROM namespace WHERE name = ?)", (b,)).fetchone()[0]: show_ns = True
    else:
        show_ns = True
    ns = escape(c.execute("SELECT name FROM namespace WHERE id = ?", (namespace,)).fetchone()[0])
    name = escape(name)
    if show_ns:
        r = f'<span class="namespace">{ns}:</span>{name}'
        fn = ns + ":" + name
    else:
        r = f"{escape(name)}"
        fn = name
    if link:
        r = f'<a href="/w/{fn}" style="color: unset;">{r}</a>'
    return r
def get_docid(ns, name, create = False):
    c.execute("SELECT id FROM doc_name WHERE namespace = ? AND name = ?", (ns, name))
    r = c.fetchone()
    if r is None:
        if create:
            c.execute("INSERT INTO doc_name (namespace, name, history_seq) VALUES(?,?,1)", (ns, name))
            lr = c.lastrowid
            c.execute("INSERT INTO data (id, value) VALUES(?, NULL)", (lr,))
            return lr
        else: return -1
    else: return r[0]
def record_history(docid, type, content, content2, content3, author, edit_comment, length):
    c.execute("""INSERT INTO history (doc_id, rev, type, content, content2, content3, author, edit_comment, datetime, length, hide, hidecomm, troll)
              SELECT ?1, (SELECT history_seq FROM doc_name WHERE id = ?1), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, -1, -1""",
              (docid, type, content, content2, content3, author, edit_comment, get_utime(), length))
    c.execute("UPDATE doc_name SET history_seq = history_seq + 1 WHERE id = ?", (docid,))
def render_acl(acl):
    # index, condtype, value, value2, not, action, expire 순으로 입력
    r = []
    for n in acl:
        perml = (perm_type_not if n[4] else perm_type)
        trg = True
        if n[1] == "perm" and n[2] in perml:
            cond = perml[n[2]]
            trg = False
        elif n[1] == "aclgroup":
            cond = "aclgroup:" + c.execute("SELECT name FROM aclgroup WHERE id = ?", (n[3],)).fetchone()[0]
        elif n[1] == "user":
            cond = "user:" + id_to_user_name(n[3])
        else:
            cond = n[1] + ":" + n[2]
        if trg and n[4]:
            cond = "not:" + cond
        r.append((n[0], cond, acl_action.get(n[5], "???"), "영구" if n[6] is None else utime_to_str(n[6])))
    return r
def delete_expired_acl():
    idx = c.execute("SELECT doc_id, acltype, idx FROM acl WHERE expire IS NOT NULL AND expire < ? ORDER BY idx DESC", (get_utime(),)).fetchall()
    c.executemany("DELETE FROM acl WHERE doc_id = ? AND acltype = ? AND idx = ?", idx)
    c.executemany("UPDATE acl SET idx = idx - 1 WHERE doc_id = ? AND acltype = ? AND idx > ?", idx)
    idx = c.execute("SELECT ns_id, acltype, idx FROM nsacl WHERE expire IS NOT NULL AND expire < ? ORDER BY idx DESC", (get_utime(),)).fetchall()
    c.executemany("DELETE FROM nsacl WHERE ns_id = ? AND acltype = ? AND idx = ?", idx)
    c.executemany("UPDATE nsacl SET idx = idx - 1 WHERE ns_id = ? AND acltype = ? AND idx > ?", idx)
def check_cond(cond, value, value2, user, ip, basedoc = None, docname = None):
    if cond == "user":
        return value2 == user, 0
    elif cond == "ip":
        if "/" in value:
            return ip_in_cidr(ip, value), 0
        else:
            return ip == value, 0
    elif cond == "perm":
        return has_perm(value, user, basedoc, docname), 0
    elif cond == "aclgroup":
        t = user_in_aclgroup(value2, user)
        if t:
            return True, t
        t = user_in_aclgroup(value2, ip)
        if t:
            return True, t
        return False, 0
    return False, 0
def cond_repr(cond, value, value2, no, denied, gid):
    r = None
    if cond == "user":
        r = "(not) 특정 사용자" if no else "특정 사용자"
    elif cond == "perm":
        l = perm_type_not if no else perm_type
        if value in l:
            r = l[value]
            no = False
    elif cond == "aclgroup":
        gname = c.execute("SELECT name FROM aclgroup WHERE id = ?", (value2,)).fetchone()[0]
        return f'현재 사용중인 계정이 ACL그룹 {gname}{"" if no else " #" + str(gid)}에 {"있지 않기" if no else "있기"}' if denied else f'ACL그룹 {gname}에 속해 {"있지 않는" if no else "있는"} 사용자'
    if r is None: r = f"{cond}:{value}"
    if no:
        r = "not:" + r
    if denied:
        return r + "이기"
    return r
def check_acl(acl, type = None, acl_tab = None, user = None, basedoc = None, docname = None):
    # condtype, value, value2, not, action 순으로 입력
    # 0 : 거부, 1 : 허용, 2 : 이름공간ACL 실행
    if user is None: user = ipuser(False)
    for i in acl:
        c = check_cond(i[0], i[1], i[2], user, request.remote_addr, basedoc, docname)
        if c[0] ^ i[3]:
            r = acl_action_key.get(i[4], 0)
            if type is None:
                return r
            else:
                if r == 0:
                    return 0, f'{cond_repr(i[0], i[1], i[2], i[3], True, c[1])} 때문에 {type} 권한이 부족합니다. 해당 문서의 <a href="{acl_tab}">ACL 탭</a>을 확인하시기 바랍니다.'
                else:
                    return r, None
    if type is None:
        return 0
    else:
        allow = []
        for i in acl:
            if i[4] == "allow" or i[4] == "gotons":
                allow.append(i)
        if len(allow) == 0:
            return 0, f'ACL에 허용 규칙이 없기 때문에 {type} 권한이 부족합니다. 해당 문서의 <a href="{acl_tab}">ACL 탭</a>을 확인하시기 바랍니다.'
        else:
            r = []
            for i in allow:
                r.append(cond_repr(i[0], i[1], i[2], i[3], False, 0))
            return 0, f'{type} 권한이 부족합니다. {" OR ".join(r)}(이)여야 합니다. 해당 문서의 <a href="{acl_tab}">ACL 탭</a>을 확인하시기 바랍니다.'
def check_namespace_acl(nsid, type, name, user = None, basedoc = None):
    delete_expired_acl()
    return check_acl(c.execute("SELECT condtype, value, value2, no, action FROM nsacl WHERE ns_id = ? AND acltype = ? ORDER BY idx", (nsid, type)).fetchall(),
                     None if type == "acl" else acl_type[type], None if type == "acl" else f"/acl/document/edit/{name}", user, basedoc, name)
def check_document_acl(docid, ns, type, name, user = None):
    delete_expired_acl()
    if type != "read" and type != "edit" and type != "acl":
        r = check_document_acl(docid, ns, "read", name, user)
        if r[0] == 0:
            return r
    if type == "move" or type == "delete":
        r = check_document_acl(docid, ns, "edit", name, user)
        if r[0] == 0:
            return r
    def cns():
        return check_namespace_acl(ns, type, name, user, docid)
    acl = c.execute("SELECT condtype, value, value2, no, action FROM acl WHERE doc_id = ? AND acltype = ? ORDER BY idx", (docid, type)).fetchall()
    if type == "read" and get_config("document_read_acl") == "0": return cns()
    if len(acl) == 0: return cns()
    r = check_acl(acl, None if type == "acl" else acl_type[type], None if type == "acl" else f"/acl/document/edit/{name}", user, docid)
    if (r if type == "acl" else r[0]) == 2: return cns()
    return r
def nvl(a, b):
    return b if a is None else a
def get_doc_data(docid):
    r = c.execute("SELECT value FROM data WHERE id = ?", (docid,)).fetchone()
    if r is None:
        return None
    return r[0]