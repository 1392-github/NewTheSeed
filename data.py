import re
import random

def gen_random_str(len):
    s = ""
    for _ in range(len):
        s += rng_string[random.randint(0, 62)]
    return s

version = 19
keyl = {'문서 읽기' : 'read_doc',
        '문서 편집':'write_doc',
        '랜덤 문서':'randompage',
        '사용자 차단':'ban',
        '문서 역사 보기':'history',
}
extension = {
    #"document_read_acl": "문서 ACL에서 읽기 ACL 사용 가능",
    #"twe_api": "TWE식 API 사용",
    #"split_blind": "strong_blind, weak_blind 이원화",
    #"split_lock_edit_request": "편집 요청 잠금과 내용 숨김 분리",
    #"split_aclgroup_perm": "ACL Group 생성/삭제 권한과 ACL Group 사용자 추가 권한 분리",
    #"show_reaming_time": "ACL Group 메시지에 남은 기간 표시"
}
rng_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
sql_max_detector = re.compile(r'\?(\d+)')
default_config = {
    "version": str(version),
    "get_api_key": "disabled",
    "secret_key": lambda : gen_random_str(64),
    "api_key_length": "64",
    "time_mode": "real",
    "time_format": "%Y-%m-%d %H:%M:%S",
    "wiki_title": "NewTheSeed",
    "wiki_name": "NewTheSeed",
    "keep_login_time": "2678400",
    "aclgroup_note_required": "0",
    "grantable_permission": "grant,delete_thread,admin,aclgroup,update_thread_document,update_thread_status,update_thread_topic,nsacl,hide_thread_comment,no_force_captcha,login_history,api_access,hide_document_history_log,hide_revision,batch_revert,mark_troll_revision,disable_two_factor_login,member_info",
    "ext_note": "0",
    "ingore_developer_perm": "disable_two_factor_login,hideip",
    "captcha_mode": "0",
    "captcha_required_type": "black",
    "captcha_required": "",
    "default_namespace": "1",
    "file_namespace": "3",
    "category_namespace": "4",
    "user_namespace": "5",
    "deleted_user_namespace": "6",
    "brand_color": "#8080ff",
    "document_read_acl": "1",
    "allow_muadt_subdoc": "1",
    "username_format": r"[A-Za-z]\w{2,31}",
    "frontpage": "FrontPage"
}
shared = {"grantable": None, "captcha_required": None, "username_format": None}
acl_type = {
    "read": "읽기",
    "edit": "편집",
    "move": "이동",
    "delete": "삭제",
    "create_thread": "토론 생성",
    "write_thread_comment": "토론 댓글",
    "edit_request": "편집 요청",
    "acl": "ACL"
}
acl_type_key = tuple(acl_type.keys())
acl_type_key2 = acl_type_key[1:]
perm_type = {
    "any": "아무나",
    "ip": "아이피 사용자",
    "member": "로그인된 사용자",
    "admin": "관리자",
    #"member_signup_15days_ago": "가입한지 15일 지난 사용자",
    "document_contributor": "해당 문서 기여자",
    "contributor": "위키 기여자",
    "match_username_and_document_title": "문서 제목과 사용자 이름이 일치"
}
perm_type_not = {
    "ip": "로그인된 사용자",
    "member": "아이피 사용자",
    "admin": "관리자가 아닌 사용자",
    #"member_signup_15days_ago": "가입한지 15일 지나지 않은 사용자",
    "document_contributor": "해당 문서 미기여자",
    "contributor": "위키 미기여자",
    "match_username_and_document_title": "문서 제목과 사용자 이름이 불일치"
}
acl_action = {"allow": "허용", "deny": "거부", "gotons": "이름공간ACL 실행"}
acl_action_key = {"allow": 1, "deny": 0, "gotons": 2}