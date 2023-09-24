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
)''', (str(session['id']))).fetchone()[0] == 1
def ipuser():
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

def rt(t, **kwargs):
    k = kwargs
    k['wiki_title'] = "TheWiki"
    k['wiki_name'] = "TheWiki"
    k['isowner'] = isowner()
    return render_template(t, **k)
