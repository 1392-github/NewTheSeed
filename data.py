import re
import random

from dataclasses import dataclass
@dataclass
class SpecialFunction:
    name: str
    url: str
    perm: str = "any"
    urlfor: bool = True
def gen_random_str(len):
    s = ""
    for _ in range(len):
        s += rng_string[random.randint(0, 62)]
    return s

version = 40
keyl = {'문서 읽기' : 'read_doc',
        '문서 편집':'write_doc',
        '랜덤 문서':'randompage',
        '사용자 차단':'ban',
        '문서 역사 보기':'history',
}
rng_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
sql_max_detector = re.compile(r'\?(\d+)')
default_config = {
    "version": str(version),
    "get_api_key": "disabled",
    "api_key_length": "64",
    "time_mode": "real",
    "time_format": "%Y-%m-%d %H:%M:%S",
    "wiki_name": "00위키",
    "keep_login_time": "2678400",
    "aclgroup_note_required": "0",
    "grantable_permission": "grant,delete_thread,admin,aclgroup,update_thread_document,update_thread_status,update_thread_topic,nsacl,weak_hide_thread_comment,hide_thread_comment,pin_thread_comment,bypass_thread_status,no_force_captcha,login_history,api_access,hide_document_history_log,hide_revision,batch_revert,mark_troll_revision,disable_two_factor_login,member_info,bypass_resizing,bypass_image_size_limit",
    "ext_note": "0",
    "ignore_developer_perm": "disable_two_factor_login,hideip",
    "captcha_mode": "0",
    "captcha_sitekey": "Put your reCAPTCHA site key",
    "captcha_secretkey": "Put your reCAPTCHA secret key",
    "captcha_required_type": "black",
    "captcha_required": "",
    "captcha_always": "signup",
    "captcha_bypass_count": "10",
    "default_namespace": "1",
    "file_namespace": "3",
    "category_namespace": "4",
    "user_namespace": "5",
    "deleted_user_namespace": "6",
    "brand_color": "#8080ff",
    "document_read_acl": "1",
    "allow_muadt_subdoc": "1",
    "username_format": r"[\w_가-힣]{1,128}",
    "frontpage": "FrontPage",
    "use_x_real_ip": "0",
    "document_license": '별도의 언급이 없는 경우 <a href="https://creativecommons.org/licenses/by/2.0">크리에이티브 커먼즈 저작자표시 2.0</a>에 따라 사용할 수 있습니다.',
    "update_local_change_commit": "Update local change commit",
    "limit_acl": "3",
    "keep_login_history": "0",
    "accept_ch": "Sec-CH-UA, Sec-CH-UA-Platform, Sec-CH-UA-Full-Version",
    "accept_ch_lifetime": "604800",
    "max_file_size": "20000000",
    "image_license": "틀:이미지 라이선스/",
    "default_image_license": "제한적 이용",
    "image_upload_templete": "템플릿:이미지 업로드",
    "file_category": "파일/",
    "default_file_category": "미분류",
    "google_site_verification": "",
    "pythonanywhere": "0",
    "pythonanywhere_eu": "0",
    "pythonanywhere_user": "Your pythonanywhere user name",
    "pythonanywhere_domain": "Your pythonanywhere domain name"
}
grantable = None
captcha_bypass_cnt = {}
captcha_required = None
captcha_always = None
username_format = None
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
acl_type_key = None
acl_type_key2 = None
def load_acl_data():
    global acl_type_key, acl_type_key2
    acl_type_key = tuple(acl_type.keys())
    acl_type_key2 = acl_type_key[1:]
load_acl_data()
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
acl_action = {"allow": "허용", "deny": "거부", "gotons": "이름공간ACL 실행", "gotootherns": "다른 이름공간ACL 실행"}
acl_action_key = {"allow": 1, "deny": 0, "gotons": 2, "gotootherns": 3}
redirect_regex = re.compile("#(?:redirect|넘겨주기) (.+)")
special_function = [
    SpecialFunction("파일 올리기", "upload"),
    SpecialFunction("차단 내역", "block_history"),
    SpecialFunction("라이선스", "license"),
    SpecialFunction("[관리] 권한 부여", "grant", "grant"),
    SpecialFunction("[관리] ACLGroup", "aclgroup", "admin"),
    SpecialFunction("[관리] 로그인 내역 조회", "login_history", "login_history"),
    SpecialFunction("[관리] Config", "config", "config"),
    SpecialFunction("[관리] SQL 덤프", "sqldump", "developer"),
    SpecialFunction("[관리] SQL 셀", "sqlshell", "developer"),
    SpecialFunction("[관리] 시스템 관리", "sysman", "developer"),
]
allow_recentthread_type = {"normal_thread", "old_thread", "pause_thread", "closed_thread"}
allow_file_extension = {"jpg", "png", "gif", "webp", "bmp", "svg", "webp", "ico"}
file_namespace = [3]
