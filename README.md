# NewTheSeed (NTS)
Python 기반 위키 엔진 (개발중)
아직 beta 버전입니다.
## DB
DB는 sqlite을 사용합니다.
## 설치 방법
1. NewTheSeed를 다운로드합니다.
2. 3.9 이상 버전의 Python을 설치합니다.
3. pip install -r requirements.txt을 실행합니다.
4. python app.py를 실행합니다.
## PR 시 규칙
* DB 구조는 ```sql_script/db_stu.sql```에 정의합니다
  * DB Browser for SQLite 등으로 확인한 스키마를 넣고, ```CREATE TABLE``` 뒤에 ```IF NOT EXISTS```를 붙여주세요
* DB에 자동 커밋이 설정되어 있으므로 따로 commit 명령어를 넣지 마세요
* 커밋 메시지는 버전 숫자만 넣으세요 (예 : 16)
  * 이때 관련된 Issue의 ID는 버전 뒤에 넣으며, 관련된 Issue가 2개 이상인 경우 Issue ID가 작은 것부터 나열하며, 공백으로 구분합니다 (예 : 16 #1 #2)
* TWE에 포함된 모든 소스(HTML, CSS, JavaScript, Python)에는 webpack-obfuscator, javascript2img 등 난독화 도구를 사용할 수 없습니다.
* Python 3.9.0 ~ Python 최신 버전 사이의 하나 이상의 버전에서 사용 불가한 코드는 사용 금지입니다. (TWE는 현재 Python 3.9까지 공식 지원합니다.)
