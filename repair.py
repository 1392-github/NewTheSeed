import sqlite3
import hashlib
import random
import os

db = sqlite3.connect("data.db", isolation_level=None)
c = db.cursor()

def user_name_to_id(name):
    return c.execute("SELECT id FROM user WHERE name = ?", (name,)).fetchone()[0]

print("NewTheSeed 복구 도구")
while True:
    print()
    print("0 - 종료")
    print("1 - config 조회")
    print("2 - config 추가")
    print("3 - config 변경")
    print("4 - config 삭제")
    print("5 - 권한 부여")
    print("6 - 권한 회수")
    print("7 - 사용자 비밀번호 변경")
    print("999 - 위키 전체 초기화")
    o = input("옵션 선택 -> ")
    if o == "0":
        break
    elif o == "1":
        for i in c.execute("SELECT name, value FROM config").fetchall():
            print(f"{i[0]} = {i[1]}")
    elif o == "2":
        key = input("추가할 설정 Key -> ")
        value = input("추가할 설정 Value -> ")
        if c.execute("SELECT EXISTS (SELECT 1 FROM config WHERE name = ?)", (key,)).fetchone()[0]:
            print("이미 존재하는 Key입니다.")
            continue
        c.execute("INSERT INTO config (name, value) VALUES(?,?)", (key, value))
    elif o == "3":
        key = input("변경할 설정 Key -> ")
        value = input("변경할 설정 Value -> ")
        c.execute("UPDATE config SET value = ? WHERE name = ?", (value, key))
        if c.rowcount == 0:
            print("설정이 존재하지 않습니다.")
    elif o == "4":
        c.execute("DELETE FROM config WHERE name = ?", (input("삭제할 설정 Key -> "),))
        if c.rowcount == 0:
            print("설정이 존재하지 않습니다.")
    elif o == "5":
        c.execute("INSERT INTO perm VALUES(?,?)", (user_name_to_id(input("권한을 부여할 사용자명 -> ")), input("부여할 권한 -> ")))
    elif o == "6":
        c.execute("DELETE FROM perm WHERE user = ? AND perm = ?", (user_name_to_id(input("권한을 회수할 사용자명 -> ")), input("회수할 권한 -> ")))
    elif o == "7":
        c.execute("UPDATE user SET password = ?2 WHERE name = ?1", (input("비밀번호를 변경할 사용자명 -> "), hashlib.sha3_512(input("변경할 비밀번호 -> ").encode()).hexdigest()))
    elif o == "999":
        key = str(random.randint(0, 9999999999)).zfill(10)
        print("[경  고]")
        print("이 기능을 사용할 경우 위키의 모든 데이터(문서, 계정, 권한 등)는 복구가 영구적으로 불가능합니다.")
        if input(f"위키 전체 초기화를 실행하려면 {key}를 입력해주세요. -> ") == key:
            db.close()
            os.remove("data.db")
            print("초기화가 완료되었습니다.")
            break
        else:
            print("초기화가 되지 않았습니다.")