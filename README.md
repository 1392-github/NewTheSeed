# TheWikiEngine
Python 기반 위키 엔진 (개발중)
## DB
DB는 sqlite을 사용합니다
## 예정사항
- [x] 기본 스킨 (v1)
- [x] 문서 편집 기능 (v1)
- [x] 문서 역사 기능 (v6)
- [x] 사용자 기능 (v4)
- [ ] 사용자 문서 기능
- [ ] 이미지 업로드 기능
- [ ] namumark 지원
- [ ] ACL 기능 (기본)
- [ ] ACL 기능 (세부)
- [ ] API 기능
## PR 시 규칙
* ```version = 숫자``` 형식으로 된 부분의 숫자를 1씩 올려주세요 (예: 원본에서 10으로 되어있으면 11로 변경)
* DB 구조는 ```sql_script/db_stu.sql```에 정의합니다
  * DB Browser for SQLite 등으로 확인한 스키마를 넣고, ```CREATE TABLE``` 뒤에 ```IF NOT EXISTS```를 붙여주세요
* DB에 자동 커밋이 설정되어 있으므로 따로 commit 명령어를 넣지 마세요
* 커밋 메시지는 v 뒤에 버전을 넣으세요
  * 이때 수정한 Issue의 ID는 버전 뒤에 넣으세요
