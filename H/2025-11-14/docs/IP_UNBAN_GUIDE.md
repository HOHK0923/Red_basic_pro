# IP 차단 해제 및 우회 가이드

**상황:** 탐지 시스템이 IP를 차단하여 서버 접근 불가

---

## 문제 확인

현재 증상:
```bash
ping 43.201.154.142
# 100% packet loss

curl http://43.201.154.142
# Connection timeout
```

**원인:**
- 탐지 시스템이 비정상 활동 감지
- IP 주소가 방화벽/WAF에 차단됨
- AWS 보안 그룹에서 차단됨

---

## 해결 방법

### 방법 1: 서버 측에서 차단 해제 (권한 있는 경우)

#### AWS 보안 그룹 확인
```bash
# AWS CLI로 보안 그룹 규칙 확인
aws ec2 describe-security-groups --group-ids sg-xxxxx

# 거부 규칙 제거
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxx \
  --ip-permissions IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges='[{CidrIp=YOUR_BLOCKED_IP/32}]'
```

#### iptables 차단 해제 (서버 접근 가능 시)
```bash
# 차단된 IP 확인
sudo iptables -L -n | grep YOUR_IP

# 차단 해제
sudo iptables -D INPUT -s YOUR_IP -j DROP

# 저장
sudo iptables-save
```

#### fail2ban 차단 해제
```bash
# 차단된 IP 확인
sudo fail2ban-client status
sudo fail2ban-client status sshd

# 차단 해제
sudo fail2ban-client set sshd unbanip YOUR_IP
```

---

### 방법 2: IP 변경 (VPN/Proxy 사용)

#### A. Tor 사용 (무료, 익명)

**macOS 설치:**
```bash
# Homebrew로 설치
brew install tor

# Tor 시작
brew services start tor

# 상태 확인
brew services list | grep tor
# tor started
```

**Linux 설치:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install tor

# 시작
sudo systemctl start tor
sudo systemctl status tor
```

**Tor 설정 확인:**
```bash
# /usr/local/etc/tor/torrc (macOS)
# /etc/tor/torrc (Linux)

# 기본 설정:
# SOCKSPort 9050
```

**Tor로 스크립트 실행:**
```bash
# PySocks 설치 (SOCKS5 지원)
pip3 install PySocks requests[socks]

# 프록시 우회 스크립트 실행
cd /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14/exploits
python3 03_proxy_bypass.py

# 프록시 선택: 1 (Tor)
```

**수동 테스트:**
```bash
# curl로 Tor 통해 접속
curl --socks5-hostname 127.0.0.1:9050 http://43.201.154.142/

# IP 확인 (Tor 통해)
curl --socks5-hostname 127.0.0.1:9050 http://icanhazip.com
```

---

#### B. ProxyChains 사용

**설치:**
```bash
# macOS
brew install proxychains-ng

# Linux
sudo apt install proxychains4
```

**설정:**
```bash
# macOS: /usr/local/etc/proxychains.conf
# Linux: /etc/proxychains4.conf

# 파일 끝에 추가:
[ProxyList]
socks5 127.0.0.1 9050
```

**사용:**
```bash
# Tor 먼저 시작
brew services start tor

# ProxyChains로 스크립트 실행
proxychains4 python3 01_detection_bypass_webshell.py
```

---

#### C. VPN 사용

**무료 VPN 옵션:**

1. **ProtonVPN** (무료 제공)
   ```bash
   # 다운로드: https://protonvpn.com/
   # 설치 후 GUI로 연결
   ```

2. **OpenVPN**
   ```bash
   # 설치
   brew install openvpn

   # 설정 파일로 연결
   sudo openvpn --config vpn_config.ovpn
   ```

---

#### D. 모바일 핫스팟 (간단)

**가장 간단한 방법:**
1. 스마트폰 핫스팟 켜기
2. 컴퓨터를 핫스팟에 연결
3. 새로운 IP로 스크립트 실행

---

#### E. C2 서버/리다이렉터 사용

**C2 인프라가 있는 경우:**

```python
# 스크립트 실행 시 리다이렉터 정보 입력
python3 01_detection_bypass_webshell.py

타겟 IP: 43.201.154.142
C2 서버: YOUR_C2_IP
리다이렉터 서버: YOUR_REDIRECTOR_IP
```

**리다이렉터 서버 설정 예시:**
```bash
# Nginx 리버스 프록시
location / {
    proxy_pass http://43.201.154.142;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

---

### 방법 3: 새로운 타겟 IP 사용

**서버 재시작 후 새 IP 받기 (AWS):**
```bash
# 인스턴스 중지
aws ec2 stop-instances --instance-ids i-xxxxx

# 시작 (새 퍼블릭 IP 할당됨)
aws ec2 start-instances --instance-ids i-xxxxx

# 새 IP 확인
aws ec2 describe-instances --instance-ids i-xxxxx \
  --query 'Reservations[0].Instances[0].PublicIpAddress'
```

**Elastic IP 사용 (고정 IP):**
```bash
# Elastic IP 할당
aws ec2 allocate-address

# 인스턴스에 연결
aws ec2 associate-address --instance-id i-xxxxx --public-ip x.x.x.x
```

---

## 추천 워크플로우

### 1단계: 현재 IP 확인
```bash
curl http://icanhazip.com
# 현재 IP 확인
```

### 2단계: Tor 설치 및 시작
```bash
brew install tor
brew services start tor
```

### 3단계: 연결 테스트
```bash
# Tor IP 확인
curl --socks5-hostname 127.0.0.1:9050 http://icanhazip.com
# Tor 출구 노드 IP (현재 IP와 다름)

# 타겟 서버 접근 테스트
curl --socks5-hostname 127.0.0.1:9050 http://43.201.154.142/
```

### 4단계: 프록시 스크립트 실행
```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14/exploits

# PySocks 설치
pip3 install PySocks

# 프록시 우회 스크립트
python3 03_proxy_bypass.py
# 선택: 1 (Tor)
```

### 5단계: 연결 성공하면 메인 스크립트 실행

**메인 스크립트 수정 (프록시 지원 추가):**

스크립트를 실행하기 전에 환경변수로 프록시 설정:
```bash
export HTTP_PROXY="socks5h://127.0.0.1:9050"
export HTTPS_PROXY="socks5h://127.0.0.1:9050"

python3 01_detection_bypass_webshell.py
```

또는 스크립트 내부에 프록시 설정 추가 (이미 준비됨):
```python
# DetectionBypassAttacker 클래스에 프록시 추가
session.proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}
```

---

## 탐지 시스템이 강력한 경우

### 추가 우회 기법

1. **더 긴 딜레이**
   ```python
   self._human_delay(30, 60)  # 30~60초 대기
   ```

2. **완전히 다른 User-Agent**
   ```python
   # 모바일 브라우저로 위장
   'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15'
   ```

3. **Tor Circuit 변경**
   ```bash
   # Tor 제어 포트 활성화
   # /usr/local/etc/tor/torrc에 추가:
   ControlPort 9051

   # 새 Circuit 요청
   echo -e 'AUTHENTICATE\nSIGNAL NEWNYM\nQUIT' | nc 127.0.0.1 9051
   ```

4. **요청 간격 랜덤화**
   ```python
   # 각 요청마다 Tor Circuit 변경
   # 완전히 다른 IP에서 요청
   ```

---

## 요약

**가장 빠른 해결책:**
1. Tor 설치: `brew install tor && brew services start tor`
2. PySocks 설치: `pip3 install PySocks`
3. 프록시 스크립트 실행: `python3 03_proxy_bypass.py`
4. 연결 성공 확인 후 메인 스크립트 실행

**대안:**
- 모바일 핫스팟 사용
- VPN 사용
- 서버 측 차단 해제 (권한 있는 경우)

---

**작성일:** 2025-11-14
**참고:** Tor 사용 시 속도가 느릴 수 있음 (출구 노드에 따라 다름)
