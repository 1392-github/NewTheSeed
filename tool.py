from flask import Flask, request, redirect, session, send_file, abort, Response
from flask import render_template
from io import BytesIO
import sqlite3
import hashlib
import sys
import datetime
import random
import types
import ipaddress
import os
from requests import get, post
from data import *

db = sqlite3.connect("data.db", isolation_level=None, check_same_thread=False)
c = db.cursor()

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
    k['isowner'] = has_perm("admin")
    k['version'] = version
    k['timemode'] = get_config("time_mode")
    k['captcha'] = get_config("captcha_mode") != "0"
    k['sitekey'] = get_config("captcha_sitekey")
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
def has_perm(perm, user = None):
    if user == None:
        if "id" in session:
            user = session["id"]
        else:
            return False
    if perm != "developer" and has_perm("developer"):
        return perm not in get_config("ingore_developer_perm").split(",")
    return c.execute("SELECT EXISTS (SELECT 1 FROM perm WHERE user = ? AND perm = ?)", (user, perm)).fetchone()[0] == 1
def captcha(action):
    mode = get_config("captcha_mode")
    if mode == "0": return True
    if has_perm("skip_captcha") or has_perm("no_force_captcha"): return True
    captcha_bypass_cnt.setdefault(request.remote_addr, 0)
    if captcha_bypass_cnt[request.remote_addr] > 0:
        captcha_bypass_cnt[request.remote_addr] -= 1
        return True
    if mode == "2":
        if not is_required_captcha(action): return True
        if "g-recaptcha-response" not in request.form: return False
        if post("https://www.google.com/recaptcha/api/siteverify",
                    data = {"secret": get_config("captcha_secretkey"), "response": request.form["g-recaptcha-response"]}).json()["success"]:
            captcha_bypass_cnt[request.remote_addr] = int(get_config("captcha_bypass_count"))
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
            captcha_bypass_cnt.setdefault(request.remote_addr, 0)
            return captcha_bypass_cnt[request.remote_addr] <= 0
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
init = not os.path.exists("data.db")
db = sqlite3.connect("data.db", isolation_level=None, check_same_thread=False)
c = db.cursor()
run_sqlscript("db_stu.sql") # DB 구조 만들기
captcha_bypass_cnt = {}
# 초기 설정
for k in default_config:
    if c.execute("select exists (select 1 from config where name = ?)", (k,)).fetchone()[0] == 0:
        c.execute('insert into config values(?, ?)', (k, default_config[k]() if isinstance(default_config[k], types.FunctionType) else default_config[k]))
print(f"NewTheSeed 버전 : {version}")
c.execute("UPDATE config SET name = 'version' WHERE name = 'majorversion'")
c.execute("DELETE FROM config WHERE name = 'minorversion'")
db_version = int(c.execute('''select value
from config
where name = "version";''').fetchone()[0])
print(f"DB 버전 : {db_version}")
if db_version > version:
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
if db_version < 17:
    # owner 설정 삭제 및 권한 시스템으로 대체
    c.execute("DELETE FROM config WHERE name = 'owner'")

c.execute('''update config
set value = ?
where name = "version"''', (str(version),)) # 변환 후 버전 재설정
"""c.execute('''update config
set value = ?
where name = "minorversion"''', (str(version[1]),))""" # 일단 철회