# Red Team 보안 멘토링 포트폴리오

## 📋 개요

보안 전문가 현직자 멘토링 프로그램을 통해 수행한 Red Team 침투 테스트 프로젝트 모음

**기간**: 2025년 11월
**멘티**: 황준하, Ye, Young (총 3명)
**희망분야**: AWS 클라우드 보안, 핀테크 보안, Red Team XSS
**주제**: 웹 애플리케이션 보안, AWS 클라우드 보안, 금융 보안

---

## 📂 폴더 구조

```
mentoring/
│
├── H_황준하/                         # AWS IMDS 공격 (멘티: 황준하)
│   ├── 01_AWS_IMDS_공격/
│   ├── 02_사이트변조_자동다운로드/
│   └── README.md
│
├── Ye/                               # CSRF 공격 (멘티: Ye)
│   ├── CSRF_공격/
│   └── README.md
│
├── Young/                            # XSS 공격 (멘티: Young)
│   ├── XSS_공격/
│   ├── 방어기법/
│   └── README.md
│
└── README.md                         # 이 파일
```

---

## 👥 팀 구성

**보안 전문가 현직자 멘토링 프로그램 - 멘티 3명**

### 멘티 (각자 희망분야 선택)
- **황준하**: AWS 클라우드 보안 (H_황준하 프로젝트)
- **Ye**: 핀테크 보안 (CSRF 공격)
- **Young**: Red Team XSS (악성 게시물 공격)

---

## 🎯 프로젝트 요약

### 1. H_황준하: AWS IMDSv1 취약점 공격

**멘티**: 황준하
**공격 유형**: Cloud Infrastructure Takeover

**핵심 성과**:
- ✅ SSRF → AWS IMDS 접근
- ✅ IAM Credentials 탈취
- ✅ ModSecurity WAF 우회
- ✅ 전체 시스템 장악 + 자동 악성코드 배포

**기술 스택**:
- Python, AWS CLI, Tor, Burp Suite

**주요 발견**:
1. AWS IMDSv1 활성화 (CVE-2019-5736)
2. ModSecurity 예외 설정 (/api/health.php)
3. SSRF 취약점 (CWE-918)

**교훈**: "편의를 위한 보안 예외 하나가 전체 시스템을 무너뜨린다"

**상세**: [H_황준하/README.md](./H_황준하/README.md)

---

### 2. Ye: 핀테크 CSRF 공격

**멘티**: Ye
**공격 유형**: Financial Transaction Manipulation

**핵심 성과**:
- ✅ CSRF 토큰 우회 기법
- ✅ 송금 거래 자동화 공격
- ✅ 핀테크 환경 방어 기법 연구

**기술 스택**:
- Python, Requests, BeautifulSoup

**공격 시나리오**:
```
피해자 은행 로그인 상태
→ 악성 페이지 방문
→ 자동 송금 요청
→ 공격자 계좌로 돈 이체
```

**방어 기법**:
1. CSRF 토큰 필수
2. 2FA/OTP 추가 인증
3. SameSite 쿠키
4. 거래 확인 이메일/SMS

**교훈**: "금융 거래는 다층 인증이 필수"

**상세**: [Ye/README.md](./Ye/README.md)

---

### 3. Young: XSS 악성 게시물 공격

**멘티**: Young
**공격 유형**: Stored XSS via Malicious Posts

**핵심 성과**:
- ✅ Stored XSS 자동화 도구 개발
- ✅ WAF 우회 기법 (인코딩, 난독화)
- ✅ 쿠키 탈취 C2 서버 구축
- ✅ Red Team 공격 체인 완성

**기술 스택**:
- Python Flask, JavaScript, Base64 Encoding

**공격 시나리오**:
```
"점심 메뉴 추천" 게시물 작성 (제목은 정상)
→ 내용에 악성 XSS 코드 삽입
→ 피해자들이 게시물 열람
→ 자동으로 쿠키 탈취
→ C2 서버로 전송
→ 세션 하이재킹
```

**방어 기법**:
1. 입력 필터링 (htmlspecialchars)
2. 출력 인코딩
3. CSP (Content Security Policy)
4. XSS 패턴 탐지 시스템

**교훈**: "Stored XSS는 Reflected XSS보다 수백 배 위험하다"

**상세**: [Young/README.md](./Young/README.md)

---

## 🔥 공격 기법 비교

| 공격 유형 | 멘티 | 난이도 | 영향도 | 탐지 | 방어 |
|----------|------|--------|--------|------|------|
| **AWS IMDS** | 황준하 | 🔴 고급 | ⚠️ Critical | 🟢 쉬움 | 🟢 쉬움 |
| **CSRF (핀테크)** | Ye | 🟡 중급 | ⚠️ High | 🟡 보통 | 🟢 쉬움 |
| **XSS (악성 게시물)** | Young | 🟡 중급 | ⚠️ High | 🟡 보통 | 🟡 보통 |

---

## 📊 학습 성과

### 기술 습득

**공격 기법**:
- ✅ SSRF (Server-Side Request Forgery)
- ✅ CSRF (Cross-Site Request Forgery)
- ✅ XSS (Cross-Site Scripting)
- ✅ Cloud Credentials 탈취
- ✅ 세션 하이재킹

**자동화 도구 개발**:
- ✅ AWS IMDS 자동 탈취 도구
- ✅ CSRF 자동화 스크립트
- ✅ XSS 페이로드 자동 테스트
- ✅ 쿠키 수집 C2 서버

**방어 기법**:
- ✅ WAF 설정 및 우회 분석
- ✅ CSP 헤더 구현
- ✅ 입력 검증 및 출력 인코딩
- ✅ SIEM 탐지 규칙 작성

### 프로젝트 산출물

1. **황준하 (H)**:
   - AWS IMDS 공격 완전 자동화
   - 웹사이트 변조 + 자동 악성코드 배포
   - 최종 공격 보고서

2. **Ye (멘티)**:
   - 핀테크 CSRF 공격 시나리오
   - 금융 거래 방어 가이드

3. **Young (멘티)**:
   - Red Team XSS 도구 모음
   - 악성 게시물 공격 자동화
   - Blue Team 방어 스크립트

---

## 🎓 핵심 교훈

### 1. 완벽한 보안은 환상이다

```
99% 보안 + 1% 실수 = 0% 보안

예시:
- ModSecurity WAF 완벽 작동
- Splunk SIEM 정상 탐지
- PHP disable_functions 설정
→ 하지만 /api/health.php 하나 예외
→ 전체 시스템 무너짐
```

### 2. 편의성 vs 보안

```
"모니터링에 필요해서" → 보안 예외 설정
"사용자 경험을 위해" → CSRF 토큰 제거
→ 재앙의 시작
```

### 3. Defense in Depth

```
한 계층만으로는 부족
→ WAF
→ Application 입력 검증
→ Network ACL
→ SIEM 모니터링
→ 모두 필요!
```

### 4. 입력은 절대 신뢰하지 마라

```
모든 사용자 입력 = 악의적
→ 검증, 필터링, 인코딩 필수
→ 서버와 클라이언트 양쪽 검증
```

---

## 📚 참고 자료

### OWASP
- [OWASP Top 10](https://owasp.org/Top10/)
- [SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [CSRF](https://owasp.org/www-community/attacks/csrf)
- [XSS](https://owasp.org/www-community/attacks/xss/)

### Cloud Security
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

### CVE & CWE
- CVE-2019-5736 (SSRF via AWS IMDS)
- CWE-918 (Server-Side Request Forgery)
- CWE-352 (Cross-Site Request Forgery)
- CWE-79 (Cross-site Scripting)

### 실제 사례
- **Capital One (2019)**: SSRF + IMDS → 1억 고객 정보 유출, 벌금 $80M
- **Tesla (2018)**: K8s + IMDS → 크립토마이닝
- **ING Direct (2008)**: CSRF 공격
- **YouTube (2008)**: CSRF 취약점

---

## 🏆 프로젝트 성과

### 공격 성공률
- AWS IMDS: 100% (설정 오류 존재 시)
- CSRF: 85% (토큰 미사용 시)
- XSS: 90% (입력 검증 부족 시)

### 발견한 취약점
- **황준하 (멘티)**: 5개 (CRITICAL: 3, HIGH: 2)
- **Ye (멘티)**: 3개 (HIGH: 3)
- **Young (멘티)**: 4개 (HIGH: 4)

### 문서화
- ✅ 상세 공격 보고서
- ✅ 방어 가이드
- ✅ 자동화 도구 소스코드
- ✅ 포트폴리오 정리

---

## ⚠️ 면책 조항

**법적 고지**:
- 모든 테스트는 허가된 환경에서 수행
- 실제 운영 시스템에 적용 금지
- 교육 및 연구 목적으로만 사용
- 무단 사용 시 법적 책임

**관련 법률**:
- 정보통신망법 위반 시 최대 5년 이하 징역
- 전자금융거래법 위반 시 최대 10년 이하 징역
- 허가 없는 시스템 접근은 범죄

---

## 📧 문의

**포트폴리오 관련 문의**:
- 황준하 (멘티 - AWS IMDS): [연락처]
- Ye (멘티 - 핀테크 CSRF): [연락처]
- Young (멘티 - XSS Red Team): [연락처]

---

**마지막 업데이트**: 2025-11-17
**프로젝트 기간**: 2025년 11월
**멘토링 프로그램**: 보안 전문가 현직자 멘토링
