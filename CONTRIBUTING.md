## 기본 규칙
 * 익명 기여는 허용되지 않습니다.
  * author.email에는 실제로 연락 가능한 이메일을 적어야 합니다. example@example.com, anonymous@1392year.pythonanywhere.com 등의 익명 이메일, 임시 이메일, 110650515+1392-github@users.noreply.github.com 등의 noreply 이메일을 이용한 커밋은 반려됩니다.
 * DB 구조는 ```sql_script/db_stu.sql```에 정의합니다.
  * DB Browser for SQLite 등으로 확인한 스키마를 넣고, ```CREATE TABLE``` 뒤에 ```IF NOT EXISTS```를 붙여주세요.
 * NewTheSeed에 포함된 모든 소스(HTML, CSS, JavaScript, Python)에는 webpack-obfuscator, javascript2img 등 난독화 도구를 사용할 수 없습니다.
 * Python 3.10 ~ Python 최신 버전 사이의 하나 이상의 버전에서 사용 불가한 코드는 사용 금지입니다. (NewTheSeed는 현재 Python 3.10 이상을 공식 지원합니다.)