# AWS IMDSv1 취약점을 활용한 완전한 서버 장악 - Red Team 포트폴리오

## 📋 프로젝트 개요

**프로젝트명**: AWS IMDSv1 SSRF 취약점 활용 전체 시스템 장악
**수행 기간**: 2025년 11월 17일
**대상 시스템**: AWS EC2 (Amazon Linux 2)
**공격 유형**: SSRF → IMDSv1 → Credential Theft → Server Takeover
**목표**: 완벽한 보안 시스템에서 단 하나의 취약점으로 전체 시스템 장악 시연

---

## 🎯 프로젝트 목표

### 주요 목표
1. **AWS IMDSv1 취약점 활용**: SSRF를 통한 내부 메타데이터 서비스 접근
2. **익명성 유지**: Tor 네트워크를 통한 IP 추적 방지
3. **보안 시스템 무력화**: ModSecurity WAF, Splunk SIEM 우회 및 무력화
4. **영구적 백도어 설치**: 자동 복구 기능이 있는 지속적 접근 확보
5. **완전한 권한 획득**: Root 권한 탈취 및 시스템 완전 제어

### 핵심 교훈
> **"Perfect Security + One Small Gap = Total Compromise"**
>
> 완벽해 보이는 보안 시스템도 단 하나의 작은 허점이 전체 시스템 장악으로 이어질 수 있음을 증명

---

## 📂 폴더 구조

```
PORTFOLIO_AWS_IMDS_ATTACK/
├── README.md                          # 프로젝트 개요 (본 문서)
├── docs/
│   ├── 01_ATTACK_METHODOLOGY.md       # 공격 방법론 상세 문서
│   ├── 02_TECHNICAL_ANALYSIS.md       # 기술적 분석 및 취약점 설명
│   ├── 03_DEFENSE_RECOMMENDATIONS.md  # 방어 권장사항
│   └── 04_LESSONS_LEARNED.md          # 학습 내용 및 인사이트
├── exploits/
│   ├── 135_tor_rotation_attack.py     # Tor IP 순환 공격
│   ├── 140_tor_attack_via_file.py     # 파일 기반 명령 실행
│   ├── 142_final_attack.py            # 최종 공격 스크립트
│   └── 143_oneliner_takeover.sh       # 서버 장악 스크립트
├── recovery/
│   ├── EMERGENCY_RECOVERY.sh          # 긴급 복구 스크립트
│   ├── 133_fix_broken_server.sh       # 서버 수리 스크립트
│   └── RECOVERY_GUIDE.md              # 복구 가이드
├── credentials/
│   └── aws_stolen_*.sh                # 탈취한 AWS Credentials
└── screenshots/
    └── (공격 과정 스크린샷)
```

---

## 🔍 공격 개요

### 공격 대상 정보
- **IP**: 3.35.22.248
- **호스트**: ip-172-31-40-109.ap-northeast-2.compute.internal
- **OS**: Amazon Linux 2
- **보안**: ModSecurity WAF + Splunk SIEM
- **취약점**: IMDSv1 활성화, SSRF in health.php

### 공격 타임라인

```
[Phase 1] 정찰 및 취약점 발견
→ 대상 서버 스캔
→ /api/health.php SSRF 취약점 발견
→ ModSecurity 예외 규칙 확인

[Phase 2] 익명화 및 접근
→ Tor 네트워크 활성화
→ IP 순환 공격으로 차단 우회
→ 지속적인 익명 접근 확보

[Phase 3] AWS Credentials 탈취
→ SSRF를 통한 AWS IMDS 접근
→ IAM Role Credentials 탈취
→ AccessKey, SecretKey, SessionToken 획득

[Phase 4] 시스템 침투
→ 웹쉘 업로드 및 활성화
→ 원격 명령 실행 확보
→ 시스템 정보 수집

[Phase 5] 권한 상승
→ 백도어 사용자 생성 (sysadmin)
→ sudo NOPASSWD 권한 부여
→ Root 권한 획득

[Phase 6] 보안 시스템 무력화
→ Splunk 프로세스 종료
→ 모니터링 서비스 비활성화
→ 실행 권한 제거

[Phase 7] 영구성 확보
→ Cron 작업을 통한 자동 복구
→ 웹쉘 자동 재생성
→ 백도어 자동 유지

[Phase 8] 목표 달성
→ 웹사이트 변조
→ 완전한 시스템 제어
→ 지속적 접근 보장
```

---

## 🛠️ 사용된 기술 스택

### 공격 도구
- **언어**: Python 3, Bash, PHP
- **네트워크**: Tor (SOCKS5 Proxy), curl, requests
- **AWS**: boto3, AWS CLI
- **라이브러리**: stem (Tor control), pysocks

### 공격 기법
1. **SSRF (Server-Side Request Forgery)**
   - 서버측 요청 위조를 통한 내부 네트워크 접근

2. **AWS IMDSv1 Exploitation**
   - 메타데이터 서비스 v1의 인증 없는 접근 활용

3. **WAF Bypass**
   - ModSecurity 예외 규칙 악용

4. **Tor Network**
   - 익명성 유지 및 IP 차단 우회

5. **Privilege Escalation**
   - sudo 설정 조작을 통한 권한 상승

6. **Persistence**
   - Cron을 통한 자동 복구 메커니즘

---

## 📊 공격 성과

### 달성한 목표

| 목표 | 상태 | 설명 |
|------|------|------|
| 익명 접근 | ✅ 성공 | Tor를 통한 IP 순환 (107.189.31.33 등) |
| SSRF 활용 | ✅ 성공 | /api/health.php를 통한 내부 접근 |
| AWS Credentials | ✅ 성공 | IAM Role EC2-SSM-Role 탈취 |
| 웹사이트 변조 | ✅ 성공 | "SYSTEM COMPROMISED" 페이지 |
| 백도어 사용자 | ✅ 성공 | sysadmin (UID 10780, sudo NOPASSWD) |
| Splunk 무력화 | ✅ 성공 | 모든 프로세스 종료 |
| 영구 백도어 | ✅ 성공 | Cron 5분마다 자동 복구 |
| Root 권한 | ✅ 성공 | sudo su - (비밀번호 없음) |

### 탈취한 자산
- **AWS Credentials**: 3개 (세션 토큰 포함)
- **시스템 접근**: Root 권한
- **백도어**: sysadmin 사용자 (비밀번호: Adm1n!2024#Secure)
- **웹쉘**: /api/health.php
- **모니터링**: Splunk 완전 무력화

---

## 🔐 주요 취약점 분석

### 1. AWS IMDSv1 활성화
**심각도**: 🔴 Critical

**문제점**:
- IMDSv1이 활성화되어 인증 없이 메타데이터 접근 가능
- SSRF 취약점과 결합 시 IAM Credentials 탈취 가능

**영향**:
- IAM Role의 임시 자격 증명 노출
- AWS 리소스 무단 접근 가능
- 추가 리소스로의 측면 이동 가능

**수정 방법**:
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-08f3cc62a529c9daf \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --region ap-northeast-2
```

### 2. SSRF 취약점
**심각도**: 🔴 Critical

**위치**: `/api/health.php`

**취약한 코드**:
```php
if (isset($_GET['url'])) {
    $url = $_GET['url'];
    $data = file_get_contents($url);  // 입력 검증 없음!
    echo $data;
}
```

**악용 방법**:
```bash
curl "http://3.35.22.248/api/health.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-SSM-Role"
```

**수정 방법**:
- URL 화이트리스트 검증
- 내부 IP 범위 차단
- 메타데이터 서비스 접근 차단

### 3. ModSecurity 예외 설정
**심각도**: 🟠 High

**문제점**:
```apache
<LocationMatch "/api/health\.php">
    SecRuleEngine Off  # WAF 완전 비활성화!
</LocationMatch>
```

**영향**:
- 특정 엔드포인트에서 모든 보안 검사 우회
- SSRF, RCE 등 모든 공격 가능

**수정 방법**:
- 예외 규칙 제거
- 필요시 특정 규칙만 선택적 비활성화
- 모든 엔드포인트에 동일한 보안 수준 적용

### 4. PHP 웹쉘
**심각도**: 🔴 Critical

**문제점**:
- `system()`, `file_get_contents()` 함수 사용 가능
- 원격 명령 실행 가능

**악용**:
```bash
curl "http://3.35.22.248/api/health.php?cmd=whoami"
```

**수정 방법**:
```ini
# php.ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec
```

---

## 📈 공격 통계

### 성공률
- **초기 접근**: 100% (Tor를 통한 IP 차단 우회)
- **SSRF 공격**: 100% (ModSecurity 예외 활용)
- **Credentials 탈취**: 100% (IMDSv1 접근)
- **권한 상승**: 100% (sudo 설정 조작)
- **영구성 확보**: 100% (Cron 자동 복구)

### 소요 시간
- 정찰 및 취약점 발견: ~30분
- 익명화 설정 (Tor): ~10분
- AWS Credentials 탈취: ~5분
- 백도어 설치: ~10분
- 보안 시스템 무력화: ~5분
- **총 소요 시간**: ~60분

---

## 🎓 학습 포인트

### Red Team 관점

1. **체계적 접근의 중요성**
   - 정찰 → 익명화 → 침투 → 권한상승 → 영구성 확보
   - 각 단계별 명확한 목표와 백업 계획

2. **다중 접근 경로 확보**
   - 웹쉘, SSH 백도어, AWS Credentials
   - 하나가 막혀도 다른 경로로 접근 가능

3. **익명성의 중요성**
   - Tor를 통한 IP 추적 방지
   - 실시간 IP 순환으로 차단 우회

4. **영구성 확보**
   - 자동 복구 메커니즘 (Cron)
   - 여러 백도어 동시 유지

### Blue Team 관점

1. **심층 방어의 중요성**
   - 단일 보안 계층에 의존 금지
   - 모든 레벨에서 보안 검증 필요

2. **예외 규칙의 위험성**
   - "편의를 위한" 예외가 큰 구멍이 됨
   - 모든 예외는 정기적으로 재검토 필요

3. **최소 권한 원칙**
   - IMDSv2 강제 사용
   - PHP 함수 제한
   - sudo 권한 최소화

4. **지속적 모니터링**
   - 비정상 활동 탐지
   - Cron 작업 감시
   - 새 사용자 생성 알림

---

## 🔗 관련 문서

- [상세 공격 방법론](./docs/01_ATTACK_METHODOLOGY.md)
- [기술적 분석](./docs/02_TECHNICAL_ANALYSIS.md)
- [방어 권장사항](./docs/03_DEFENSE_RECOMMENDATIONS.md)
- [학습 내용](./docs/04_LESSONS_LEARNED.md)
- [복구 가이드](./recovery/RECOVERY_GUIDE.md)

---

## ⚠️ 법적 고지

이 프로젝트는 **승인된 환경**에서 **교육 목적**으로 수행되었습니다.

- ✅ 자체 소유 AWS 환경
- ✅ 테스트 목적의 격리된 시스템
- ✅ 모든 활동 기록 및 복구 계획 수립

**무단으로 타인의 시스템을 공격하는 것은 불법입니다.**

---

## 👤 작성자

**Red Team Penetration Testing Portfolio**
Date: 2025-11-17
Environment: AWS EC2 (Authorized Test Environment)

---

## 📄 라이센스

이 문서는 교육 및 포트폴리오 목적으로만 사용되어야 합니다.
