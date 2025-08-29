import re

version = 18
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
    "host": "0.0.0.0",
    "port": lambda : input('위키 포트 입력 -> '),
    "debug": "0",
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
    "captcha_required": ""
}
first_perminssion = ["grant", "delete_thread", "admin", "aclgroup", "update_thread_document",
                     "update_thread_status", "update_thread_topic", "nsacl", "hide_thread_comment",
                     "no_force_captcha", "login_history", "api_access", "hide_document_history_log",
                     "hide_revision", "batch_revert", "mark_troll_revision","member_info",
                     "developer", "config", "aclgroup_hidelog", "skip_captcha", "database"]
shared = {"grantable": None, "captcha_required": None}