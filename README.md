# TheWikiEngine
Python 기반 위키 엔진 (개발중)
## DB
DB는 sqlite을 사용합니다
## PR 시 규칙
* ```version = 숫자``` 형식으로 된 부분의 숫자를 1씩 올려주세요 (예: 원본에서 10으로 되어있으면 11로 변경)
* DB 구조는 ```sql_script/db_stu.sql```에 정의합니다
  * DB Browser for SQLite 등으로 확인한 스키마를 넣고, ```CREATE TABLE``` 뒤에 ```IF NOT EXISTS```를 붙여주세요
* DB에 자동 커밋이 설정되어 있으므로 따로 commit 명령어를 넣지 마세요
* 커밋 메시지는 v 뒤에 버전을 넣으세요 (예 : v15)
  * 이때 관련된 Issue의 ID는 버전 뒤에 넣으며, 관련된 Issue가 2개 이상인 경우 Issue ID가 작은 것부터 나열하며, 공백으로 구분합니다 (예 : v15 #1 #2)
