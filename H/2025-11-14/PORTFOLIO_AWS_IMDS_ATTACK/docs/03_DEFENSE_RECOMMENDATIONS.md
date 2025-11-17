# 방어 권장사항 (Defense Recommendations)

## 목차
1. [즉시 조치 (Critical - 24시간 내)](#즉시-조치)
2. [단기 조치 (High - 1주일 내)](#단기-조치)
3. [중기 조치 (Medium - 1개월 내)](#중기-조치)
4. [장기 조치 (Low - 3개월 내)](#장기-조치)
5. [모니터링 및 탐지](#모니터링-및-탐지)
6. [인시던트 대응 절차](#인시던트-대응-절차)

---

## 즉시 조치

### 1. 백도어 제거 (Priority: 🔴 Critical)

**실행 명령**:
```bash
# 1.1 백도어 사용자 삭제
sudo userdel -r sysadmin
sudo rm -f /etc/sudoers.d/sysadmin

# 1.2 Cron 작업 제거
sudo crontab -r
sudo crontab -l  # 확인

# 1.3 백도어 스크립트 삭제
sudo rm -f /usr/local/bin/backdoor_keeper.sh

# 1.4 모든 의심스러운 사용자 확인
awk -F: '$3 >= 1000 {print $1":"$3":"$6}' /etc/passwd
```

**검증**:
```bash
# 사용자 삭제 확인
id sysadmin
# → id: 'sysadmin': no such user

# Cron 확인
crontab -l
# → no crontab for root

# 스크립트 확인
ls -la /usr/local/bin/backdoor_keeper.sh
# → No such file or directory
```

---

### 2. 웹쉘 제거 및 복구 (Priority: 🔴 Critical)

**실행 명령**:
```bash
# 2.1 웹쉘 탐지
sudo find /var/www/html -type f -name "*.php" -exec grep -l "system\|exec\|passthru\|shell_exec" {} \;

# 2.2 health.php 복구 (또는 삭제)
sudo rm -f /var/www/html/www/api/health.php

# 또는 안전한 버전으로 교체
sudo cat > /var/www/html/www/api/health.php << 'EOF'
<?php
header('Content-Type: application/json');
echo json_encode(['status' => 'OK', 'timestamp' => time()]);
?>
EOF

sudo chown apache:apache /var/www/html/www/api/health.php
sudo chmod 644 /var/www/html/www/api/health.php

# 2.3 변조된 index.php 복구
# 백업에서 복구 또는 정상 파일로 교체
sudo find /var/www/html/www -name "*.backup" -exec bash -c 'cp "$0" "${0%.backup}"' {} \;

# 2.4 .htaccess 파일 확인 및 제거
sudo find /var/www/html -name ".htaccess" -exec cat {} \; -exec rm -i {} \;

# 2.5 Apache 재시작
sudo systemctl restart httpd
```

**검증**:
```bash
# 웹사이트 정상 작동 확인
curl -I http://3.35.22.248/
# → HTTP/1.1 200 OK

curl "http://3.35.22.248/api/health.php?cmd=whoami"
# → 명령 실행 안됨
```

---

### 3. AWS IMDSv2 강제 적용 (Priority: 🔴 Critical)

**실행 명령**:
```bash
# 3.1 현재 설정 확인
aws ec2 describe-instances \
  --instance-ids i-08f3cc62a529c9daf \
  --query 'Reservations[0].Instances[0].MetadataOptions' \
  --region ap-northeast-2

# 3.2 IMDSv2 강제 적용
aws ec2 modify-instance-metadata-options \
  --instance-id i-08f3cc62a529c9daf \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --region ap-northeast-2

# 3.3 설정 검증
aws ec2 describe-instances \
  --instance-ids i-08f3cc62a529c9daf \
  --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens' \
  --region ap-northeast-2
# → "required"
```

**서버 내부에서 테스트**:
```bash
# IMDSv1 (차단되어야 함)
curl http://169.254.169.254/latest/meta-data/
# → 401 Unauthorized

# IMDSv2 (정상 작동)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
# → ami-id
# instance-id
# ...
```

---

### 4. 탈취된 Credentials 무효화 (Priority: 🔴 Critical)

**실행 명령**:
```bash
# 4.1 IAM Role 세션 확인
aws sts get-caller-identity

# 4.2 EC2 인스턴스 재부팅 (새 임시 자격 증명 발급)
aws ec2 reboot-instances \
  --instance-ids i-08f3cc62a529c9daf \
  --region ap-northeast-2

# 4.3 IAM Role 정책 검토
aws iam get-role --role-name EC2-SSM-Role
aws iam list-attached-role-policies --role-name EC2-SSM-Role
aws iam list-role-policies --role-name EC2-SSM-Role

# 4.4 불필요한 권한 제거
# 예: S3 전체 액세스가 필요 없다면 제거
```

**CloudTrail 로그 분석**:
```bash
# 탈취된 자격 증명 사용 여부 확인
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=EC2-SSM-Role \
  --start-time 2025-11-17T00:00:00Z \
  --region ap-northeast-2 \
  --max-results 50
```

---

### 5. ModSecurity 강화 (Priority: 🔴 Critical)

**실행 명령**:
```bash
# 5.1 예외 규칙 제거
sudo vi /etc/httpd/conf.d/modsecurity.conf

# 다음 섹션 삭제 또는 주석 처리:
# <LocationMatch "/api/health\.php">
#     SecRuleEngine Off
# </LocationMatch>

# 5.2 설정 테스트
sudo apachectl configtest
# → Syntax OK

# 5.3 Apache 재시작
sudo systemctl restart httpd
```

**검증**:
```bash
# SSRF 공격 차단 확인
curl "http://3.35.22.248/api/health.php?url=http://169.254.169.254/"
# → 403 Forbidden (ModSecurity 차단)
```

---

### 6. PHP 보안 강화 (Priority: 🔴 Critical)

**실행 명령**:
```bash
# 6.1 php.ini 수정
sudo vi /etc/php.ini

# 다음 설정 추가/변경:
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,pcntl_exec,pcntl_fork,pcntl_signal,pcntl_waitpid,pcntl_wexitstatus,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority

allow_url_fopen = Off
allow_url_include = Off

open_basedir = /var/www/html/www:/tmp

expose_php = Off
display_errors = Off
log_errors = On

# 6.2 설정 확인
php -i | grep disable_functions

# 6.3 Apache 재시작
sudo systemctl restart httpd
```

**검증**:
```bash
# 명령 실행 차단 확인
echo '<?php system("whoami"); ?>' > /tmp/test.php
php /tmp/test.php
# → Warning: system() has been disabled for security reasons
```

---

### 7. Splunk 복구 (Priority: 🟠 High)

**실행 명령**:
```bash
# 7.1 실행 권한 복구
sudo chmod 755 /opt/splunk/bin/splunk
sudo chmod 755 /opt/splunkforwarder/bin/splunk

# 7.2 서비스 재시작
sudo systemctl start Splunkd
sudo systemctl enable Splunkd

# 7.3 프로세스 확인
ps aux | grep splunk

# 7.4 Splunk 무결성 보호
sudo chattr +i /opt/splunk/bin/splunk
sudo chattr +i /opt/splunkforwarder/bin/splunk
```

**검증**:
```bash
# Splunk 정상 작동 확인
sudo /opt/splunk/bin/splunk status
# → splunkd is running (PID: 12345)

# 삭제 방지 확인
sudo rm /opt/splunk/bin/splunk
# → rm: cannot remove '/opt/splunk/bin/splunk': Operation not permitted
```

---

### 8. SSH 보안 강화 (Priority: 🟠 High)

**실행 명령**:
```bash
# 8.1 /etc/ssh/sshd_config 수정
sudo vi /etc/ssh/sshd_config

# 다음 설정 적용:
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers ec2-user
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2

# 8.2 설정 테스트
sudo sshd -t

# 8.3 SSH 재시작
sudo systemctl restart sshd
```

**검증**:
```bash
# 비밀번호 로그인 차단 확인
ssh sysadmin@3.35.22.248
# → Permission denied (publickey)
```

---

## 단기 조치

### 1. 로그 분석 및 침해 범위 확인 (Priority: 🟠 High)

**Apache 접근 로그 분석**:
```bash
# 1.1 Tor Exit Node IP 확인
sudo grep -E "107\.189\.|45\.38\." /var/log/httpd/access_log

# 1.2 health.php 접근 로그
sudo grep "health.php" /var/log/httpd/access_log | grep -E "cmd=|url="

# 1.3 의심스러운 User-Agent
sudo grep "python-requests\|curl" /var/log/httpd/access_log

# 1.4 시간대별 분석
sudo awk '{print $4}' /var/log/httpd/access_log | cut -d: -f1-2 | sort | uniq -c
```

**시스템 로그 분석**:
```bash
# 1.5 사용자 생성 로그
sudo grep "useradd\|groupadd" /var/log/secure

# 1.6 sudo 사용 로그
sudo grep "sudo:" /var/log/secure

# 1.7 Cron 작업 변경
sudo grep "cron" /var/log/cron
```

**CloudTrail 분석**:
```bash
# 1.8 탈취된 자격 증명 사용 내역
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=EC2-SSM-Role \
  --start-time 2025-11-17T00:00:00Z \
  --end-time 2025-11-17T23:59:59Z \
  --region ap-northeast-2 \
  --output json > cloudtrail_events.json

# 1.9 의심스러운 API 호출 확인
cat cloudtrail_events.json | jq '.Events[] | select(.EventName | contains("Create") or contains("Delete") or contains("Put"))'
```

---

### 2. Security Group 및 NACL 강화 (Priority: 🟠 High)

**Security Group 최소 권한 적용**:
```bash
# 2.1 현재 Security Group 확인
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=your-sg-name" \
  --region ap-northeast-2

# 2.2 불필요한 규칙 제거
# 예: 0.0.0.0/0에서 22번 포트 접근 제거
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0 \
  --region ap-northeast-2

# 2.3 특정 IP만 허용
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr YOUR_OFFICE_IP/32 \
  --region ap-northeast-2
```

**NACL 추가**:
```bash
# 2.4 Network ACL 생성 (선택사항)
aws ec2 create-network-acl \
  --vpc-id vpc-xxxxxxxxx \
  --region ap-northeast-2

# 2.5 Tor Exit Node IP 차단
# 예시: 107.189.0.0/16, 45.38.0.0/16 차단
aws ec2 create-network-acl-entry \
  --network-acl-id acl-xxxxxxxxx \
  --rule-number 100 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block 107.189.0.0/16 \
  --egress false \
  --region ap-northeast-2
```

---

### 3. IAM 권한 최소화 (Priority: 🟠 High)

**EC2-SSM-Role 권한 검토**:
```bash
# 3.1 현재 권한 확인
aws iam list-attached-role-policies --role-name EC2-SSM-Role
aws iam get-role-policy --role-name EC2-SSM-Role --policy-name inline-policy

# 3.2 최소 권한 정책 생성
cat > ec2-ssm-minimal-policy.json << 'EOF'
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
      "Resource": "arn:aws:s3:::your-specific-bucket/*"
    }
  ]
}
EOF

# 3.3 정책 업데이트
aws iam put-role-policy \
  --role-name EC2-SSM-Role \
  --policy-name EC2-SSM-Minimal-Policy \
  --policy-document file://ec2-ssm-minimal-policy.json
```

---

### 4. 웹 애플리케이션 보안 강화 (Priority: 🟠 High)

**입력 검증 추가**:
```php
// health.php - 보안 강화 버전
<?php
header('Content-Type: application/json');

// 인증 토큰 검증
$valid_token = getenv('HEALTH_CHECK_TOKEN');
if (!isset($_GET['token']) || $_GET['token'] !== $valid_token) {
    http_response_code(403);
    die(json_encode(['error' => 'Forbidden']));
}

// IP 화이트리스트
$allowed_ips = ['172.31.0.0/16', '10.0.0.0/8'];
$client_ip = $_SERVER['REMOTE_ADDR'];
$allowed = false;
foreach ($allowed_ips as $range) {
    if (ip_in_range($client_ip, $range)) {
        $allowed = true;
        break;
    }
}
if (!$allowed) {
    http_response_code(403);
    die(json_encode(['error' => 'IP not allowed']));
}

// 단순 헬스체크만 제공
$status = [
    'status' => 'OK',
    'timestamp' => time(),
    'version' => '1.0.0'
];

echo json_encode($status);

function ip_in_range($ip, $range) {
    list($subnet, $mask) = explode('/', $range);
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);
    $mask_long = ~((1 << (32 - $mask)) - 1);
    return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
}
?>
```

**Apache 설정 강화**:
```apache
# /etc/httpd/conf.d/security.conf
<Directory /var/www/html/www>
    # PHP 실행 제한
    <FilesMatch "\.(jpg|jpeg|png|gif|css|js|txt)$">
        php_flag engine off
    </FilesMatch>

    # 디렉터리 리스팅 차단
    Options -Indexes

    # 심볼릭 링크 차단
    Options -FollowSymLinks

    # .htaccess 차단
    AllowOverride None
</Directory>

# 숨김 파일 접근 차단
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

# 서버 정보 숨기기
ServerTokens Prod
ServerSignature Off
```

---

## 중기 조치

### 1. AWS WAF 배포 (Priority: 🟡 Medium)

**CloudFront + WAF 구성**:
```bash
# 1.1 Web ACL 생성
aws wafv2 create-web-acl \
  --name my-web-acl \
  --scope REGIONAL \
  --default-action Allow={} \
  --rules file://waf-rules.json \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=MyWebACL \
  --region ap-northeast-2

# 1.2 ALB와 연결
aws wafv2 associate-web-acl \
  --web-acl-arn arn:aws:wafv2:ap-northeast-2:123456789012:regional/webacl/my-web-acl/a1b2c3d4 \
  --resource-arn arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188 \
  --region ap-northeast-2
```

**WAF 규칙 예시** (`waf-rules.json`):
```json
[
  {
    "Name": "RateLimitRule",
    "Priority": 1,
    "Statement": {
      "RateBasedStatement": {
        "Limit": 2000,
        "AggregateKeyType": "IP"
      }
    },
    "Action": {
      "Block": {}
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitRule"
    }
  },
  {
    "Name": "BlockSSRF",
    "Priority": 2,
    "Statement": {
      "ByteMatchStatement": {
        "SearchString": "169.254.169.254",
        "FieldToMatch": {
          "UriPath": {}
        },
        "TextTransformations": [
          {
            "Priority": 0,
            "Type": "URL_DECODE"
          }
        ],
        "PositionalConstraint": "CONTAINS"
      }
    },
    "Action": {
      "Block": {}
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "BlockSSRF"
    }
  }
]
```

---

### 2. 침입 탐지 시스템 강화 (Priority: 🟡 Medium)

**GuardDuty 활성화**:
```bash
# 2.1 GuardDuty 활성화
aws guardduty create-detector \
  --enable \
  --region ap-northeast-2

# 2.2 탐지 결과 확인
aws guardduty list-findings \
  --detector-id abcd1234 \
  --region ap-northeast-2
```

**Splunk 알림 설정**:
```bash
# 2.3 Splunk 모니터링 강화
# /opt/splunk/etc/apps/search/local/savedsearches.conf
[New User Created]
search = index=linux sourcetype=linux_secure "useradd" OR "groupadd"
cron_schedule = */5 * * * *
action.email = 1
action.email.to = security@example.com

[Sudo Modification]
search = index=linux sourcetype=linux_secure "/etc/sudoers"
cron_schedule = */5 * * * *
action.email = 1
action.email.to = security@example.com

[Suspicious Web Access]
search = index=apache sourcetype=access_combined "/api/health.php" (cmd OR url)
cron_schedule = */5 * * * *
action.email = 1
action.email.to = security@example.com
```

---

### 3. 백업 및 복구 계획 (Priority: 🟡 Medium)

**자동 백업 설정**:
```bash
# 3.1 AMI 자동 생성
aws dlm create-lifecycle-policy \
  --execution-role-arn arn:aws:iam::123456789012:role/AWSDataLifecycleManagerDefaultRole \
  --description "Daily AMI backup" \
  --state ENABLED \
  --policy-details file://backup-policy.json \
  --region ap-northeast-2
```

**백업 정책** (`backup-policy.json`):
```json
{
  "PolicyType": "IMAGE_MANAGEMENT",
  "ResourceTypes": ["INSTANCE"],
  "TargetTags": [
    {
      "Key": "Backup",
      "Value": "True"
    }
  ],
  "Schedules": [
    {
      "Name": "DailyBackup",
      "CreateRule": {
        "Interval": 24,
        "IntervalUnit": "HOURS",
        "Times": ["03:00"]
      },
      "RetainRule": {
        "Count": 7
      },
      "CopyTags": true
    }
  ]
}
```

---

### 4. 코드 보안 스캔 (Priority: 🟡 Medium)

**정적 분석 도구 실행**:
```bash
# 4.1 PHP 취약점 스캔 (PHPStan)
composer require --dev phpstan/phpstan
./vendor/bin/phpstan analyse /var/www/html/www

# 4.2 웹쉘 탐지
sudo find /var/www/html -type f -name "*.php" | xargs grep -l "eval\|base64_decode\|gzinflate\|str_rot13\|system\|exec"

# 4.3 의심스러운 파일 권한
sudo find /var/www/html -type f -perm 0777

# 4.4 최근 수정된 파일
sudo find /var/www/html -type f -mtime -7 -ls
```

---

## 장기 조치

### 1. 제로 트러스트 아키텍처 구현 (Priority: 🟢 Low)

**Private Subnet 이전**:
```
현재:
Internet → EC2 (Public Subnet)

목표:
Internet → CloudFront → ALB (Public) → EC2 (Private)
```

**Terraform 예시**:
```hcl
resource "aws_instance" "web_server" {
  ami           = "ami-xxxxxxxxx"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.private.id  # Private Subnet

  metadata_options {
    http_tokens   = "required"  # IMDSv2 강제
    http_endpoint = "enabled"
  }

  tags = {
    Name = "WebServer"
  }
}

resource "aws_lb" "alb" {
  name               = "web-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = aws_subnet.public[*].id

  security_groups = [aws_security_group.alb_sg.id]
}
```

---

### 2. 보안 교육 및 프로세스 개선 (Priority: 🟢 Low)

**개발자 교육**:
1. OWASP Top 10 교육
2. Secure Coding 가이드라인
3. SSRF, RCE 취약점 실습
4. AWS 보안 모범 사례

**코드 리뷰 프로세스**:
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run PHPStan
        run: |
          composer install
          ./vendor/bin/phpstan analyse
      - name: Run OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
```

---

### 3. 보안 모니터링 대시보드 구축 (Priority: 🟢 Low)

**Splunk 대시보드**:
```xml
<dashboard>
  <label>Security Monitoring</label>
  <row>
    <panel>
      <title>Failed Login Attempts</title>
      <chart>
        <search>
          <query>index=linux sourcetype=linux_secure "Failed password" | timechart count</query>
        </search>
      </chart>
    </panel>
    <panel>
      <title>Suspicious Web Access</title>
      <chart>
        <search>
          <query>index=apache sourcetype=access_combined status=403 OR status=500 | timechart count</query>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>AWS API Calls</title>
      <table>
        <search>
          <query>index=aws sourcetype=aws:cloudtrail | stats count by eventName, sourceIPAddress</query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

---

## 모니터링 및 탐지

### 침해 지표 (IOCs)

**파일 기반**:
```bash
# IOC 리스트
/var/www/html/www/api/health.php (웹쉘)
/usr/local/bin/backdoor_keeper.sh (백도어 스크립트)
/etc/sudoers.d/sysadmin (sudo 설정)
```

**사용자 기반**:
```bash
# 의심스러운 사용자
sysadmin (UID: 10780)
```

**네트워크 기반**:
```bash
# Tor Exit Node IPs
107.189.31.33
45.38.20.240
# (전체 목록: https://check.torproject.org/exit-addresses)
```

**행위 기반**:
```bash
# 의심스러운 패턴
- health.php에 대한 "cmd=" 또는 "url=" 파라미터
- 169.254.169.254에 대한 요청
- useradd/usermod 명령 실행
- /etc/sudoers.d/ 파일 수정
- Splunk 프로세스 종료
```

### 탐지 규칙

**Splunk 쿼리**:
```spl
# SSRF 탐지
index=apache sourcetype=access_combined uri_query="*169.254.169.254*"

# 웹쉘 탐지
index=apache sourcetype=access_combined uri_query="*cmd=*" OR uri_query="*exec=*"

# 백도어 사용자 탐지
index=linux sourcetype=linux_secure "useradd" AND "sysadmin"

# Splunk 종료 탐지
index=linux sourcetype=linux_secure "pkill" AND "splunk"

# Cron 변경 탐지
index=linux sourcetype=linux_secure "crontab"
```

---

## 인시던트 대응 절차

### Phase 1: 탐지 (Detection)

1. **알림 수신**
   - Splunk 알림
   - GuardDuty 탐지
   - CloudWatch 알람

2. **초기 분석**
   - 로그 확인
   - 침해 범위 파악
   - 영향도 평가

### Phase 2: 격리 (Containment)

1. **즉시 격리**
   ```bash
   # Security Group 수정 (모든 인바운드 차단)
   aws ec2 revoke-security-group-ingress \
     --group-id sg-xxxxxxxxx \
     --ip-permissions file://all-traffic.json
   ```

2. **백업 생성**
   ```bash
   # 현재 상태 AMI 생성 (포렌식용)
   aws ec2 create-image \
     --instance-id i-08f3cc62a529c9daf \
     --name "incident-$(date +%Y%m%d-%H%M%S)" \
     --no-reboot
   ```

### Phase 3: 제거 (Eradication)

1. **위협 제거**
   - 백도어 삭제
   - 웹쉘 제거
   - 악성 Cron 제거

2. **시스템 복구**
   - 정상 AMI에서 복구
   - 설정 파일 복원

### Phase 4: 복구 (Recovery)

1. **서비스 재개**
   - 보안 강화 완료 후 서비스 재개
   - 단계적 트래픽 증가

2. **모니터링 강화**
   - 24시간 모니터링
   - 재감염 여부 확인

### Phase 5: 사후 분석 (Lessons Learned)

1. **사고 보고서 작성**
2. **프로세스 개선**
3. **교육 실시**

---

## 체크리스트

### 즉시 조치 체크리스트

- [ ] 백도어 사용자 삭제 (sysadmin)
- [ ] 웹쉘 제거 (health.php)
- [ ] Cron 작업 삭제
- [ ] 백도어 스크립트 삭제
- [ ] AWS IMDSv2 강제 적용
- [ ] EC2 인스턴스 재부팅 (자격 증명 무효화)
- [ ] ModSecurity 예외 제거
- [ ] PHP disable_functions 강화
- [ ] Splunk 복구
- [ ] SSH 비밀번호 인증 비활성화

### 단기 조치 체크리스트

- [ ] 로그 분석 완료
- [ ] CloudTrail 로그 검토
- [ ] Security Group 강화
- [ ] IAM 권한 최소화
- [ ] 웹 애플리케이션 입력 검증 추가

### 중기 조치 체크리스트

- [ ] AWS WAF 배포
- [ ] GuardDuty 활성화
- [ ] 자동 백업 설정
- [ ] 코드 보안 스캔 실행

### 장기 조치 체크리스트

- [ ] Private Subnet 이전
- [ ] 제로 트러스트 아키텍처 구현
- [ ] 보안 교육 실시
- [ ] 모니터링 대시보드 구축

---

**끝.**
