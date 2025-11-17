# 황준하 - Red Team 침투 테스트 포트폴리오

## 📋 프로젝트 개요

**프로젝트명**: AWS IMDSv1 취약점을 이용한 전체 시스템 장악 시연
**기간**: 2025년 11월
**역할**: Red Team 침투 테스트 수행
**멘티**: 황준하
**희망분야**: AWS 클라우드 보안
**멘토링**: 보안 전문가 현직자 멘토링 프로그램

---

## 🎯 프로젝트 목표

완벽해 보이는 보안 시스템에서 **단 하나의 작은 설정 실수가 전체 시스템 장악으로 이어지는 과정**을 시연하여, Defense in Depth의 중요성과 "모든 계층이 완벽해야 한다"는 보안 원칙을 증명

---

## 🔥 핵심 성과

### 공격 성공 요약
- ✅ ModSecurity WAF 우회 성공
- ✅ Splunk SIEM 탐지 회피 성공
- ✅ AWS IAM Credentials 탈취 성공
- ✅ Root 권한 획득 성공
- ✅ 웹사이트 변조 및 백도어 설치 성공
- ✅ 자동 악성코드 배포 성공

### 발견한 취약점
1. **AWS IMDSv1 활성화** (CVE-2019-5736 관련)
2. **ModSecurity WAF 예외 설정** (/api/health.php)
3. **SSRF 취약점** (CWE-918)
4. **파일 업로드 검증 부족**
5. **PHP 위험 함수 미제한**

---

## 📂 프로젝트 구조

```
H_황준하/
├── 01_AWS_IMDS_공격/              # 핵심 공격 체인
│   ├── 119_setup_aws_vuln.sh     # 취약점 설정
│   ├── 120_aws_imds_exploit.py   # Credentials 탈취
│   ├── 121_aws_privilege_escalation.py # AWS 인프라 열거
│   └── 122_aws_ssm_command.py    # SSM 원격 명령 실행
│
├── 02_사이트변조_자동다운로드/      # 최종 공격
│   ├── TOGGLE_SILENT.sh          # 핵심 토글 스크립트
│   └── SILENT_DOWNLOAD.sh        # 자동 다운로드
│
└── README.md                      # 이 파일
```

---

## 🛡️ 공격 시나리오

### Phase 1: 정찰 (Reconnaissance)
```
포트 스캔 → 디렉터리 브루트포스 → /api/health.php 발견
```

**사용 도구**:
- Nmap
- Gobuster
- Burp Suite

### Phase 2: 초기 침입 (Initial Access)
```
SSRF 취약점 발견 → ModSecurity 우회 확인
```

**핵심 취약점**:
```php
// /api/health.php
if (isset($_GET['url'])) {
    $data = file_get_contents($_GET['url']);  // SSRF!
    echo $data;
}
```

**ModSecurity 예외**:
```apache
<LocationMatch "/api/health\.php">
    SecRuleEngine Off    # 치명적 실수!
</LocationMatch>
```

### Phase 3: Credentials 탈취 (Credential Access)
```
SSRF로 AWS IMDS 접근 → IAM Role Credentials 탈취
```

**공격 코드**:
```python
# AWS IMDS 접근
url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
role = requests.get(health_endpoint, params={'url': url})

# Credentials 탈취
creds_url = f"{url}{role.text}"
credentials = requests.get(health_endpoint, params={'url': creds_url})
```

**탈취한 정보**:
- AccessKeyId: `ASIASO4TYV4OK2MJVZDV`
- SecretAccessKey: `7H1nyRK6iZ80K2Tthpq7...`
- SessionToken: (임시 세션 토큰)

### Phase 4: 권한 상승 (Privilege Escalation)
```
AWS CLI 설정 → EC2 인스턴스 열거 → SSH 접근 → Root 권한 획득
```

### Phase 5: 목표 달성 (Impact)
```
웹사이트 변조 → 자동 악성코드 배포 → 백도어 설치
```

---

## 💻 핵심 기술 스택

### 공격 도구
- **Python 3**: 자동화 스크립트
- **AWS CLI**: AWS 인프라 조작
- **Tor**: IP 추적 방지
- **Burp Suite**: HTTP 인터셉트
- **ModSecurity**: WAF 분석

### 대상 시스템
- **AWS EC2**: t2.micro
- **Apache 2.4.65**: 웹 서버
- **PHP 8.2**: 애플리케이션
- **ModSecurity**: WAF
- **Splunk**: SIEM

---

## 📊 공격 타임라인

| 시간 | 단계 | 활동 | 결과 |
|------|------|------|------|
| T+00:00 | 정찰 | 포트 스캔, 디렉터리 브루트포스 | /api/health.php 발견 |
| T+00:05 | 초기 침입 | SSRF 취약점 테스트 | IMDS 접근 확인 |
| T+00:10 | Credentials | IAM credentials 탈취 | AWS 접근 권한 획득 |
| T+00:15 | 횡적 이동 | AWS 인프라 열거 | EC2, S3, RDS 목록 획득 |
| T+00:20 | 권한 상승 | SSH 접근 시도 | Root 권한 획득 |
| T+00:25 | 목표 달성 | 웹사이트 변조 | 해킹 페이지 게시 |
| T+00:30 | 지속성 | 백도어 설치 | 재접속 경로 확보 |

---

## 🔍 발견한 보안 이슈

### 1. IMDSv1 활성화 (HIGH)

**위험도**: ⚠️ CRITICAL

**설명**:
```bash
# 취약한 설정
aws ec2 modify-instance-metadata-options \
    --http-tokens optional    # IMDSv1 허용
```

**영향**:
- SSRF 공격으로 AWS Credentials 탈취 가능
- 인증 없이 메타데이터 접근 가능

**권장 해결책**:
```bash
# 안전한 설정
aws ec2 modify-instance-metadata-options \
    --http-tokens required    # IMDSv2 강제
```

### 2. ModSecurity 예외 (HIGH)

**위험도**: ⚠️ CRITICAL

**설명**:
"모니터링에 필요"하다는 이유로 `/api/health.php`를 WAF 예외로 설정

**영향**:
- WAF 완전 우회
- 모든 공격이 탐지되지 않음

**권장 해결책**:
```apache
<LocationMatch "/api/health\.php">
    # 특정 규칙만 예외 처리
    SecRuleRemoveById 920350
    # 나머지는 활성화 유지
</LocationMatch>
```

### 3. SSRF 취약점 (HIGH)

**위험도**: ⚠️ CRITICAL

**CWE**: CWE-918

**취약한 코드**:
```php
$url = $_GET['url'];
$data = file_get_contents($url);  // 검증 없음!
```

**권장 해결책**:
```php
// URL 화이트리스트
$allowed_hosts = ['api.example.com'];
$parsed = parse_url($url);

if (!in_array($parsed['host'], $allowed_hosts)) {
    die('Invalid URL');
}

// 내부 IP 차단
if (preg_match('/^(10|127|172\.(1[6-9]|2[0-9]|3[01])|192\.168|169\.254)\./,
    gethostbyname($parsed['host']))) {
    die('Internal IP blocked');
}
```

---

## 📈 영향 평가

### 기술적 영향

| 항목 | 심각도 | 세부 내용 |
|------|--------|-----------|
| **기밀성** | ⚠️ CRITICAL | AWS credentials, 시스템 전체 접근 |
| **무결성** | ⚠️ CRITICAL | 웹사이트 변조, 시스템 파일 수정 |
| **가용성** | ⚠️ HIGH | 서비스 중단, 랜섬웨어 설치 가능 |

### 비즈니스 영향

1. **재정적 손실**:
   - 서비스 중단: 시간당 매출 손실
   - 복구 비용: 보안 전문가 고용
   - 법적 벌금: GDPR, 개인정보보호법

2. **평판 손상**:
   - 언론 보도 → 브랜드 이미지 하락
   - 고객 이탈 → 장기적 매출 감소

---

## 🎓 핵심 교훈

### 1. "완벽한 보안"은 환상이다

```
99% 완벽한 보안 + 1% 작은 틈 = 0% 보안
```

이 프로젝트에서:
- ✅ ModSecurity WAF: 완벽하게 작동
- ✅ Splunk SIEM: 정상 탐지
- ✅ PHP disable_functions: 올바르게 설정
- ❌ 단 하나의 예외 (/api/health.php): **모든 것을 무너뜨림**

### 2. 편의성 vs 보안

"모니터링에 필요해서"라는 이유로:
- ModSecurity 예외 설정 → WAF 무력화
- IMDSv1 유지 → AWS 전체 장악

**교훈**: 편의를 위한 보안 예외는 재앙의 시작

### 3. Defense in Depth의 중요성

한 계층이 뚫려도 다음 계층에서 막아야 하지만,
이 경우 ModSecurity 예외로 모든 계층이 무력화됨

**올바른 방어**:
```
Layer 1: WAF (ModSecurity)
Layer 2: Application (input validation)
Layer 3: Network (IMDS blocking)
Layer 4: Monitoring (SIEM)
  ↓
모두 필요!
```

---

## 🔗 실제 사례

### Capital One (2019)
- **공격**: SSRF + IMDSv1
- **피해**: 1억 고객 정보 유출
- **벌금**: $80 million
- **출처**: [KrebsOnSecurity](https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/)

### Tesla (2018)
- **공격**: K8s 노출 + IMDSv1
- **피해**: AWS credentials 탈취, 크립토마이닝
- **출처**: [RedLock Blog](https://redlock.io/blog/cryptojacking-tesla)

---

## 📚 참고 자료

### CVE
- **CVE-2019-5736**: SSRF via AWS IMDS
- **CWE-918**: Server-Side Request Forgery
- **CWE-269**: Improper Privilege Management

### AWS 문서
- [IMDSv2 Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

### OWASP
- [SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [Top 10 2021](https://owasp.org/Top10/)

---

## 🛠️ 방어 권장 사항

### 즉시 조치 (Immediate)
1. ✅ IMDSv2 강제 활성화
2. ✅ ModSecurity 예외 제거
3. ✅ SSRF 입력 검증 추가
4. ✅ 백도어 제거

### 단기 조치 (Short-term)
1. ✅ Network ACL 강화
2. ✅ WAF 규칙 강화
3. ✅ 로그 모니터링 강화

### 장기 조치 (Long-term)
1. ✅ 최소 권한 원칙 적용
2. ✅ VPC Endpoint 사용
3. ✅ 주기적 취약점 스캔
4. ✅ Zero Trust 아키텍처 전환

---

## 👨‍💻 작성자

**황준하**
멘티 - AWS 클라우드 보안 전문화
보안 전문가 멘토링 프로그램 수료

---

## 📄 라이선스

이 프로젝트는 교육 목적으로만 사용됩니다.
무단 사용 금지.

---

**마지막 메시지**:

> "편의를 위한 보안 예외는 재앙의 시작이다"
>
> 아무리 강력한 보안 시스템도,
> 단 하나의 예외로 모두 무너질 수 있습니다.
>
> 보안은 체인과 같습니다.
> 가장 약한 고리가 전체 강도를 결정합니다.
