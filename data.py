import re
import argon2
import hashlib

from dataclasses import dataclass
@dataclass
class SpecialFunction:
    name: str
    url: str
    perm: str = "any"
    urlfor: bool = True

version = (83, 1)
default_config = {
    "version": str(version[0]),
    "version2": str(version[1]),
    "time_mode": "real",
    "time_format": "%Y-%m-%d %H:%M:%S",
    "wiki_name": "00위키",
    "keep_login_time": "2678400",
    "aclgroup_note_required": "0",
    "ignore_grant_has_check": "disable_two_factor_login",
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
    "top_text_color": "#ffffff",
    "document_read_acl": "1",
    "allow_muadt_subdoc": "1",
    "username_format": r"[\w_가-힣]{1,128}",
    "frontpage": "FrontPage",
    "use_x_real_ip": "0",
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
    "pythonanywhere_domain": "Your pythonanywhere domain name",
    "change_name_enable": "1",
    "change_name_block": "1",
    "change_name_cooltime": "2592000",
    "withdraw_enable": "1",
    "withdraw_cooltime": "86400",
    "withdraw_resignup_block": "2592000",
    "email_verification_level": "0",
    "email_wblist_type": "white",
    "email_wblist": "",
    "email_wblist_public": "1",
    "email_limit": "1",
    "email_limit2": "",
    "default_skin": "ntsds",
    "gravatar_default": "retro",
    "gravatar_rating": "g",
    "password_hashing_type": "a",
    "salt_length": "16",
    "argon2_parameter": "id,3,65536,4,32",
    "enable_rehash": "1"
}
default_string_config = {
    "document_license": '이 저작물은 <a href="https://creativecommons.org/licenses/by/4.0">CC BY 4.0</a>에 따라 이용할 수 있습니다. (단, 라이선스가 명시된 일부 문서 및 삽화 제외)<br>기여하신 문서의 저작권은 각 기여자에게 있으며, 각 기여자는 기여하신 부분의 저작권을 갖습니다.',
    "document_license_checkbox": "문서 편집을 저장하면 당신은 기여한 내용을 <b>CC BY 4.0 KR</b>으로 배포하고 기여한 문서에 대한 하이퍼링크나 URL을 이용하여 저작자 표시를 하는 것으로 충분하다는 데 동의하는 것입니다. <b>이 동의는 철회할 수 없습니다.</b>",
    "withdraw_pledgeinput": '본인은 계정 삭제를 하면 본인이 기여한 문서나 그 복제물에 또는 해당 문서의 공표 매체(이하 "문서등")에 본인의 실명 또는 이명 대신에 <삭제된 사용자>로 표시됨을 동의합니다. 또한, 본인은 계정 삭제 이후 문서등의 기여자임을 증명할 수 없게 된다는 사실을 인지하고, 문서등에 대하여 저작인격권을 행사하지 않을 것에 동의합니다.',
    "policy": "여기에 약관을 입력해주세요.",
    "email_verification_signup_title": "[{wiki_name}] 계정 생성 이메일 주소 인증",
    "email_verification_signup": '''안녕하세요. {wiki_name} 입니다.<br><br>
{wiki_name} 계정 생성 이메일 인증 메일입니다.<br>
직접 계정 생성을 진행하신 것이 맞다면 아래 링크를 클릭해서 계정 생성을 계속 진행해주세요.<br>
<a href="{link}">[인증]</a><br><br>
이 메일은 24시간동안 유효합니다.<br>
요청 아이피 : {ip}''',
    "email_verification_signup_max": '''안녕하세요. {wiki_name} 입니다.<br><br>
{wiki_name} 계정 생성 이메일 인증 메일입니다.<br>
누군가 이 이메일로 계정 생성을 시도했지만 이미 이 이메일로 계정 생성을 할 수 있는 최대 횟수({max}번)를 초과해서 더 이상 계정을 생성할 수 없습니다.<br><br>
요청 아이피 : {ip}''',
    "email_verification_change_title": "[{wiki_name}] {user}님의 이메일 변경 인증 메일 입니다.",
    "email_verification_change": '''안녕하세요. {wiki_name}입니다.<br><br>
{user}님의 이메일 변경 인증 메일입니다.<br>
해당 아이디로 변경한게 맞으시면 아래 링크를 클릭해주세요.<br>
<a href="{link}">[인증]</a><br><br>
이 메일은 24시간동안 유효합니다.<br>
요청 아이피 : {ip}''',
    "email_verification_change_max": '''안녕하세요. {wiki_name}입니다.<br><br>
{user}님의 이메일 변경 인증 메일입니다.<br>
이 이메일로 이메일 변경을 시도했지만 이미 이 이메일로 계정 생성을 할 수 있는 최대 횟수({max}번)를 초과해서 더 이상 계정을 생성할 수 없습니다.<br><br>
요청 아이피 : {ip}''',
    "email_verification_recover_password_title": "[{wiki_name}] {user}님의 아이디/비밀번호 찾기 메일 입니다.",
    "email_verification_recover_password": '''안녕하세요. {wiki_name}입니다.<br><br>
{user}님의 아이디/비밀번호 찾기 메일입니다.<br>
해당 계정의 비밀번호를 찾으시려면 아래 링크를 클릭해주세요.<br>
<a href="{link}">[인증]</a><br><br>
이 메일은 24시간동안 유효합니다.<br>
요청 아이피 : {ip}'''
}
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
    "member_signup_15days_ago": "가입한지 15일 지난 사용자",
    "document_contributor": "해당 문서 기여자",
    "contributor": "위키 기여자",
    "match_username_and_document_title": "문서 제목과 사용자 이름이 일치",
    "email_verified_member": "이메일 인증된 사용자"
}
perm_type_not = {
    "ip": "로그인된 사용자",
    "member": "아이피 사용자",
    "admin": "관리자가 아닌 사용자",
    "member_signup_15days_ago": "가입한지 15일 지나지 않은 사용자",
    "document_contributor": "해당 문서 미기여자",
    "contributor": "위키 미기여자",
    "match_username_and_document_title": "문서 제목과 사용자 이름이 불일치",
    "email_verified_member": "이메일 미인증된 사용자"
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
    SpecialFunction("[관리] 계정 관리", "manage_account", "manage_account"),
    SpecialFunction("[관리] Config", "config", "config"),
    SpecialFunction("[관리] SQL 덤프", "sqldump", "developer"),
    SpecialFunction("[관리] SQL 셀", "sqlshell", "developer"),
    SpecialFunction("[관리] 시스템 관리", "sysman", "developer"),
]
allow_recentthread_type = {"normal_thread", "old_thread", "pause_thread", "closed_thread"}
allow_file_extension = {"jpg", "png", "gif", "webp", "bmp", "svg", "webp", "ico"}
file_namespace = [3]
install_status = """This file indicates the progress/completion of the installation in the NewTheSeed installer.
If the last character is "1", the installation is in progress, and if it's "2", the installation is complete.
"""
batch_blind_regex = re.compile(r"(\d+)[~-](\d+)")
default_aclgroup_config = [
    ("withdraw_period", "0"),
    ("signup_policy", "none"),
    ("max_duration_ip", "0"),
    ("max_duration_account", "0"),
    ("max_ipv4_cidr", "0"),
    ("max_ipv6_cidr", "0"),
    ("access_flags", "any"),
    ("add_flags", "admin"),
    ("remove_flags", "admin"),
    ("style", ""),
    ("message", ""),
    ("self_remove_note", "SELF REMOVE"),
    ("show_user_document", "0"),
    ("self_removable", "0"),
]
default_aclgroup_message = "ACL그룹 {group} #{id}에 있기 때문에 {type} 권한이 부족합니다.<br>만료일 : {end}<br>사유 : {note}"
member_signup_days_ago_regex = re.compile("member_signup_(\d+)days_ago")
member_signup_ago_regex = re.compile("member_signup_(\d+)_ago")
change_name_block = []
email_wblist_type = None
email_wblist = []
skins = []
skin_info = {}
skin_git = set()
skin_commit = {}
allow_skin_ext_id = re.compile("[a-zA-Z0-9_]+")
skin_config_css = {}
skin_config_js = {}
revert_available = {0, 1, 5}
json_403 = {"status": '권한이 부족합니다.'}, 403
max_utime = 32503647600 # 3000-01-01 00:00:00 UTC
permissions = ["developer", "nsacl", "admin", "config", "delete_thread", "aclgroup", "hideip", "aclgroup_hidelog", "no_force_captcha",
               "skip_captcha", "update_thread_document", "update_thread_status", "update_thread_topic", "weak_hide_thread_comment",
               "hide_thread_comment", "pin_thread_comment", "bypass_thread_status", "grant", "login_history", "api_access", "hide_document_history_log",
               "hide_revision", "mark_troll_revision", "batch_revert", "manage_account", "bypass_resizing", "bypass_image_size_limit", "disable_two_factor_login"]
permissions_order = {}
for i,v in enumerate(permissions):
    permissions_order[v] = i
ignore_grant_has_check = ["disable_two_factor_login"]
all_extensions = []
extensions = []
extension_info = {}
extension_git = set()
extension_commit = {}
extension_module = {}
argon2_password_hasher: argon2.PasswordHasher | None = None
hash_functions = {"1": hashlib.sha256, "2": hashlib.sha512, "3": hashlib.sha3_256, "4": hashlib.sha3_512}
argon2_types = {"i": argon2.Type.I, "d": argon2.Type.D, "id": argon2.Type.ID}