# 서버 복구 가이드 (Server Recovery Guide)

## 목차
1. [복구 개요](#복구-개요)
2. [백도어 제거](#백도어-제거)
3. [웹사이트 복구](#웹사이트-복구)
4. [보안 설정 강화](#보안-설정-강화)
5. [복구 검증](#복구-검증)

---

## 복구 개요

### 현재 상태
- ❌ 웹사이트 변조됨 (SYSTEM COMPROMISED 페이지)
- ❌ 백도어 사용자 존재 (sysadmin)
- ❌ 웹쉘 설치됨 (health.php)
- ❌ Splunk 무력화됨
- ❌ 자동 복구 Cron 작업 실행 중

### 복구 목표
- ✅ 모든 백도어 제거
- ✅ 웹사이트 정상 복구
- ✅ 보안 시스템 재활성화
- ✅ 보안 설정 강화
- ✅ 정상 서비스 재개

---

## 백도어 제거

### 1단계: 백도어 사용자 삭제

```bash
# 백도어 사용자 삭제
sudo userdel -r sysadmin

# 확인
id sysadmin
# 출력: id: 'sysadmin': no such user

# sudo 설정 파일 삭제
sudo rm -f /etc/sudoers.d/sysadmin

# 확인
ls -la /etc/sudoers.d/
```

### 2단계: Cron 작업 제거

```bash
# 현재 Cron 작업 확인
sudo crontab -l

# 모든 Cron 작업 제거
sudo crontab -r

# 확인
sudo crontab -l
# 출력: no crontab for root
```

### 3단계: 백도어 스크립트 삭제

```bash
# 백도어 유지 스크립트 삭제
sudo rm -f /usr/local/bin/backdoor_keeper.sh

# 확인
ls -la /usr/local/bin/backdoor_keeper.sh
# 출력: No such file or directory
```

### 4단계: 의심스러운 파일 검색 및 제거

```bash
# 최근 7일 내 수정된 파일 검색
sudo find /var/www/html -type f -mtime -7 -ls

# 웹쉘 패턴 검색
sudo find /var/www/html -type f -name "*.php" -exec grep -l "system\|exec\|passthru\|shell_exec" {} \;

# 의심스러운 파일 수동 검토 후 삭제
```

---

## 웹사이트 복구

### 1단계: 현재 상태 백업 (선택사항)

```bash
# 포렌식을 위한 현재 상태 백업
sudo mkdir -p /root/forensics/$(date +%Y%m%d-%H%M%S)
sudo cp -r /var/www/html/www /root/forensics/$(date +%Y%m%d-%H%M%S)/
```

### 2단계: 변조된 파일 제거

```bash
# 변조된 index.php 삭제
sudo rm -f /var/www/html/www/index.php

# .htaccess 파일 삭제 (있다면)
sudo find /var/www/html/www -name ".htaccess" -delete

# 웹쉘 삭제
sudo rm -f /var/www/html/www/api/health.php
```

### 3단계: 백업에서 복구

```bash
# 백업 파일이 있다면 복구
sudo find /var/www/html/www -name "*.backup" -exec bash -c 'cp "$0" "${0%.backup}"' {} \;

# 또는 Git에서 복구
cd /var/www/html/www
sudo git checkout -- index.php
sudo git checkout -- api/health.php
```

### 4단계: 원본 파일 작성 (백업이 없는 경우)

**정상적인 index.php**:
```bash
sudo cat > /var/www/html/www/index.php << 'EOF'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome to Our Website</h1>
    <p>서비스가 정상적으로 복구되었습니다.</p>
    <ul>
        <li><a href="/login.php">로그인</a></li>
        <li><a href="/upload.php">파일 업로드</a></li>
    </ul>
</body>
</html>
EOF
```

**안전한 health.php** (단순 헬스체크만):
```bash
sudo cat > /var/www/html/www/api/health.php << 'EOF'
<?php
header('Content-Type: application/json');
echo json_encode([
    'status' => 'OK',
    'timestamp' => time(),
    'version' => '1.0.0'
]);
?>
EOF
```

### 5단계: 파일 권한 설정

```bash
# 소유자 설정
sudo chown -R apache:apache /var/www/html/www

# 권한 설정
sudo find /var/www/html/www -type f -exec chmod 644 {} \;
sudo find /var/www/html/www -type d -exec chmod 755 {} \;

# 확인
ls -la /var/www/html/www/
```

### 6단계: Apache 재시작

```bash
# 설정 테스트
sudo apachectl configtest

# Apache 재시작
sudo systemctl restart httpd

# 상태 확인
sudo systemctl status httpd
```

---

## 보안 설정 강화

### 1단계: ModSecurity 예외 제거

```bash
# ModSecurity 설정 편집
sudo vi /etc/httpd/conf.d/modsecurity.conf

# 다음 섹션 삭제 또는 주석 처리:
# <LocationMatch "/api/health\.php">
#     SecRuleEngine Off
# </LocationMatch>

# 설정 테스트
sudo apachectl configtest

# Apache 재시작
sudo systemctl restart httpd
```

### 2단계: PHP 보안 강화

```bash
# php.ini 편집
sudo vi /etc/php.ini

# 다음 설정 추가/변경:
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
allow_url_fopen = Off
allow_url_include = Off
open_basedir = /var/www/html/www:/tmp
expose_php = Off
display_errors = Off

# Apache 재시작
sudo systemctl restart httpd

# 확인
php -i | grep disable_functions
```

### 3단계: AWS IMDSv2 강제 적용

```bash
# 로컬에서 실행 (AWS CLI 필요)
aws ec2 modify-instance-metadata-options \
  --instance-id i-08f3cc62a529c9daf \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --region ap-northeast-2

# 서버에서 확인
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
if [ -n "$TOKEN" ]; then
    echo "✅ IMDSv2 활성화됨"
else
    echo "❌ IMDSv2 설정 필요"
fi
```

### 4단계: SSH 보안 강화

```bash
# sshd_config 편집
sudo vi /etc/ssh/sshd_config

# 다음 설정 확인/변경:
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers ec2-user
MaxAuthTries 3

# SSH 재시작
sudo systemctl restart sshd
```

### 5단계: Splunk 복구

```bash
# 실행 권한 복구
sudo chmod 755 /opt/splunk/bin/splunk
sudo chmod 755 /opt/splunkforwarder/bin/splunk

# Splunk 시작
sudo systemctl start Splunkd
sudo systemctl enable Splunkd

# 상태 확인
sudo systemctl status Splunkd
ps aux | grep splunk

# 무결성 보호 (선택사항)
sudo chattr +i /opt/splunk/bin/splunk
sudo chattr +i /opt/splunkforwarder/bin/splunk
```

### 6단계: 방화벽 설정

```bash
# firewalld 활성화
sudo systemctl start firewalld
sudo systemctl enable firewalld

# 필요한 포트만 허용
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=ssh

# 규칙 적용
sudo firewall-cmd --reload

# 확인
sudo firewall-cmd --list-all
```

---

## 복구 검증

### 1단계: 웹사이트 접근 확인

```bash
# 로컬에서 테스트
curl -I http://3.35.22.248/
# 출력: HTTP/1.1 200 OK

curl http://3.35.22.248/
# 출력: 정상 웹페이지 HTML

# health.php 확인
curl http://3.35.22.248/api/health.php
# 출력: {"status":"OK","timestamp":1234567890,"version":"1.0.0"}
```

### 2단계: 백도어 제거 확인

```bash
# 사용자 확인
id sysadmin
# 출력: id: 'sysadmin': no such user

# sudo 설정 확인
sudo ls -la /etc/sudoers.d/
# 출력: sysadmin 파일 없음

# Cron 확인
sudo crontab -l
# 출력: no crontab for root

# 백도어 스크립트 확인
ls /usr/local/bin/backdoor_keeper.sh
# 출력: No such file or directory
```

### 3단계: 웹쉘 제거 확인

```bash
# 명령 실행 테스트
curl "http://3.35.22.248/api/health.php?cmd=whoami"
# 출력: {"status":"OK",...} (명령 실행 안됨)

# SSRF 테스트
curl "http://3.35.22.248/api/health.php?url=http://169.254.169.254/"
# 출력: 403 Forbidden 또는 {"status":"OK",...}
```

### 4단계: ModSecurity 확인

```bash
# SQL Injection 테스트
curl "http://3.35.22.248/?test=' OR '1'='1"
# 출력: 403 Forbidden (ModSecurity 차단)

# XSS 테스트
curl "http://3.35.22.248/?test=<script>alert(1)</script>"
# 출력: 403 Forbidden (ModSecurity 차단)
```

### 5단계: IMDSv2 확인

```bash
# 서버에서 테스트
# IMDSv1 (차단되어야 함)
curl http://169.254.169.254/latest/meta-data/
# 출력: 401 Unauthorized

# IMDSv2 (정상 작동)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
# 출력: ami-id, instance-id, ...
```

### 6단계: Splunk 확인

```bash
# 프로세스 확인
ps aux | grep splunk | grep -v grep
# 출력: splunkd 프로세스 실행 중

# 서비스 상태
sudo systemctl status Splunkd
# 출력: active (running)
```

### 7단계: 로그 분석

```bash
# Apache 접근 로그
sudo tail -f /var/log/httpd/access_log

# Apache 에러 로그
sudo tail -f /var/log/httpd/error_log

# 시스템 보안 로그
sudo tail -f /var/log/secure

# Splunk에서 확인
sudo /opt/splunk/bin/splunk search "index=* | head 10"
```

---

## 복구 체크리스트

### 백도어 제거
- [ ] sysadmin 사용자 삭제됨
- [ ] /etc/sudoers.d/sysadmin 삭제됨
- [ ] Cron 작업 제거됨
- [ ] /usr/local/bin/backdoor_keeper.sh 삭제됨
- [ ] 의심스러운 파일 제거됨

### 웹사이트 복구
- [ ] index.php 복구됨
- [ ] health.php 안전한 버전으로 교체됨
- [ ] .htaccess 파일 제거됨
- [ ] 파일 권한 올바르게 설정됨
- [ ] Apache 정상 작동

### 보안 강화
- [ ] ModSecurity 예외 제거됨
- [ ] PHP disable_functions 설정됨
- [ ] IMDSv2 강제 적용됨
- [ ] SSH 비밀번호 인증 비활성화됨
- [ ] Splunk 복구 및 보호됨

### 검증
- [ ] 웹사이트 정상 접근 가능
- [ ] 백도어로 접근 불가
- [ ] 웹쉘 실행 불가
- [ ] ModSecurity 차단 작동
- [ ] IMDSv2 정상 작동
- [ ] Splunk 정상 작동

---

## 긴급 복구 스크립트

**완전 자동화 복구 스크립트** (`EMERGENCY_RECOVERY.sh`):

```bash
#!/bin/bash

echo "╔═══════════════════════════════════════════════╗"
echo "║   긴급 서버 복구 시작                        ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# 1. 백도어 제거
echo "[1/6] 백도어 제거 중..."
userdel -r sysadmin 2>/dev/null
rm -f /etc/sudoers.d/sysadmin
crontab -r 2>/dev/null
rm -f /usr/local/bin/backdoor_keeper.sh
echo "  ✅ 백도어 제거 완료"
echo ""

# 2. 웹쉘 제거
echo "[2/6] 웹쉘 제거 중..."
rm -f /var/www/html/www/api/health.php
find /var/www/html/www -name ".htaccess" -delete
echo "  ✅ 웹쉘 제거 완료"
echo ""

# 3. 웹사이트 복구
echo "[3/6] 웹사이트 복구 중..."

# 백업에서 복구 시도
if find /var/www/html/www -name "*.backup" | grep -q .; then
    find /var/www/html/www -name "*.backup" -exec bash -c 'cp "$0" "${0%.backup}"' {} \;
    echo "  ✅ 백업에서 복구됨"
else
    # 안전한 파일 생성
    cat > /var/www/html/www/index.php << 'EOF'
<!DOCTYPE html>
<html>
<head><title>서비스 복구됨</title></head>
<body><h1>서비스가 정상적으로 복구되었습니다</h1></body>
</html>
EOF

    cat > /var/www/html/www/api/health.php << 'EOF'
<?php
header('Content-Type: application/json');
echo json_encode(['status' => 'OK', 'timestamp' => time()]);
?>
EOF
    echo "  ✅ 기본 파일 생성됨"
fi

chown -R apache:apache /var/www/html/www
echo ""

# 4. Apache 재시작
echo "[4/6] Apache 재시작 중..."
apachectl configtest && systemctl restart httpd
echo "  ✅ Apache 재시작 완료"
echo ""

# 5. Splunk 복구
echo "[5/6] Splunk 복구 중..."
chmod 755 /opt/splunk/bin/splunk 2>/dev/null
chmod 755 /opt/splunkforwarder/bin/splunk 2>/dev/null
systemctl start Splunkd 2>/dev/null
systemctl enable Splunkd 2>/dev/null
echo "  ✅ Splunk 복구 완료"
echo ""

# 6. 검증
echo "[6/6] 복구 검증 중..."
ERROR=0

# 백도어 확인
if id sysadmin &>/dev/null; then
    echo "  ❌ 백도어 사용자 여전히 존재"
    ERROR=1
else
    echo "  ✅ 백도어 제거 확인"
fi

# 웹사이트 확인
if curl -s http://localhost/ | grep -q "SYSTEM COMPROMISED"; then
    echo "  ❌ 웹사이트 여전히 변조됨"
    ERROR=1
else
    echo "  ✅ 웹사이트 정상"
fi

# Apache 확인
if systemctl is-active --quiet httpd; then
    echo "  ✅ Apache 정상 작동"
else
    echo "  ❌ Apache 작동 안함"
    ERROR=1
fi

echo ""
if [ $ERROR -eq 0 ]; then
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   ✅ 복구 완료!                              ║"
    echo "╚═══════════════════════════════════════════════╝"
else
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   ⚠️  일부 문제 발생 - 수동 확인 필요       ║"
    echo "╚═══════════════════════════════════════════════╝"
fi
```

---

## 복구 후 권장 사항

### 즉시 조치
1. 모든 사용자 비밀번호 변경
2. SSH 키 재발급
3. AWS Credentials 재발급 (IAM Role 재생성)
4. 로그 분석 (침해 범위 확인)

### 단기 조치
1. 보안 감사 실시
2. 취약점 스캔
3. 침투 테스트
4. 보안 정책 재검토

### 장기 조치
1. 보안 아키텍처 재설계
2. 모니터링 강화
3. 자동화된 대응 체계 구축
4. 정기 보안 교육

---

**끝.**
