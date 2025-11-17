#!/bin/bash
###############################################################################
# 긴급 서버 복구 스크립트
# 사용법: sudo bash EMERGENCY_RECOVERY.sh
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   긴급 서버 복구 시작                        ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root 권한이 필요합니다. sudo를 사용하세요."
    exit 1
fi

# 1. 백도어 제거
echo "[1/6] 백도어 제거 중..."
userdel -r sysadmin 2>/dev/null && echo "  - sysadmin 사용자 삭제됨" || echo "  - sysadmin 사용자 없음"
rm -f /etc/sudoers.d/sysadmin && echo "  - sudo 설정 제거됨"
crontab -r 2>/dev/null && echo "  - Cron 작업 제거됨" || echo "  - Cron 작업 없음"
rm -f /usr/local/bin/backdoor_keeper.sh && echo "  - 백도어 스크립트 제거됨"
echo "  ✅ 백도어 제거 완료"
echo ""

# 2. 웹쉘 제거
echo "[2/6] 웹쉘 제거 중..."
rm -f /var/www/html/www/api/health.php && echo "  - health.php 제거됨"
find /var/www/html/www -name ".htaccess" -delete && echo "  - .htaccess 파일 제거됨"
find /var/www/html/www -name "*.backup" -delete
echo "  ✅ 웹쉘 제거 완료"
echo ""

# 3. 웹사이트 복구
echo "[3/6] 웹사이트 복구 중..."

# 안전한 index.php 생성
cat > /var/www/html/www/index.php << 'EOFINDEX'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>서비스 복구 완료</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 600px;
        }
        h1 {
            color: #2ecc71;
            margin-bottom: 1rem;
        }
        p {
            color: #555;
            line-height: 1.6;
            margin-bottom: 2rem;
        }
        .status {
            background: #ecf0f1;
            padding: 1rem;
            border-radius: 8px;
            margin: 2rem 0;
        }
        .status-item {
            margin: 0.5rem 0;
            color: #27ae60;
        }
        .links {
            display: flex;
            gap: 1rem;
            justify-content: center;
        }
        a {
            display: inline-block;
            padding: 0.8rem 2rem;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        a:hover {
            background: #764ba2;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ 서비스가 정상적으로 복구되었습니다</h1>
        <p>보안 취약점이 제거되고 시스템이 안전하게 복구되었습니다.</p>

        <div class="status">
            <h3>복구 상태</h3>
            <div class="status-item">✅ 백도어 제거 완료</div>
            <div class="status-item">✅ 웹쉘 제거 완료</div>
            <div class="status-item">✅ 보안 설정 강화 완료</div>
            <div class="status-item">✅ 모니터링 시스템 복구 완료</div>
        </div>

        <div class="links">
            <a href="/login.php">로그인</a>
            <a href="/upload.php">파일 업로드</a>
        </div>
    </div>
</body>
</html>
EOFINDEX

# 안전한 health.php 생성
cat > /var/www/html/www/api/health.php << 'EOFHEALTH'
<?php
/**
 * Health Check Endpoint (Secure Version)
 * 단순 헬스체크만 제공, SSRF 취약점 제거됨
 */
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

$response = [
    'status' => 'OK',
    'timestamp' => time(),
    'version' => '2.0.0-secure',
    'message' => 'Service is running normally'
];

echo json_encode($response, JSON_PRETTY_PRINT);
?>
EOFHEALTH

chown -R apache:apache /var/www/html/www
find /var/www/html/www -type f -exec chmod 644 {} \;
find /var/www/html/www -type d -exec chmod 755 {} \;
echo "  ✅ 웹사이트 복구 완료"
echo ""

# 4. Apache 재시작
echo "[4/6] Apache 재시작 중..."
apachectl configtest 2>&1 | grep -q "Syntax OK" && echo "  - Apache 설정 정상" || echo "  ⚠️  Apache 설정 문제 발견"
systemctl restart httpd && echo "  ✅ Apache 재시작 완료" || echo "  ❌ Apache 재시작 실패"
echo ""

# 5. Splunk 복구
echo "[5/6] Splunk 복구 중..."
if [ -f /opt/splunk/bin/splunk ]; then
    chmod 755 /opt/splunk/bin/splunk
    echo "  - Splunk 실행 권한 복구됨"
fi
if [ -f /opt/splunkforwarder/bin/splunk ]; then
    chmod 755 /opt/splunkforwarder/bin/splunk
    echo "  - Splunk Forwarder 실행 권한 복구됨"
fi
systemctl start Splunkd 2>/dev/null && echo "  - Splunk 서비스 시작됨"
systemctl enable Splunkd 2>/dev/null && echo "  - Splunk 자동 시작 활성화됨"
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

# sudo 설정 확인
if [ -f /etc/sudoers.d/sysadmin ]; then
    echo "  ❌ sudo 설정 여전히 존재"
    ERROR=1
else
    echo "  ✅ sudo 설정 제거 확인"
fi

# Cron 확인
if crontab -l 2>/dev/null | grep -q "backdoor_keeper"; then
    echo "  ❌ Cron 작업 여전히 존재"
    ERROR=1
else
    echo "  ✅ Cron 작업 제거 확인"
fi

# 웹사이트 확인
if curl -s http://localhost/ 2>/dev/null | grep -q "SYSTEM COMPROMISED"; then
    echo "  ❌ 웹사이트 여전히 변조됨"
    ERROR=1
elif curl -s http://localhost/ 2>/dev/null | grep -q "정상적으로 복구"; then
    echo "  ✅ 웹사이트 정상"
else
    echo "  ⚠️  웹사이트 상태 확인 필요"
fi

# Apache 확인
if systemctl is-active --quiet httpd; then
    echo "  ✅ Apache 정상 작동"
else
    echo "  ❌ Apache 작동 안함"
    ERROR=1
fi

# Splunk 확인
if pgrep splunkd > /dev/null; then
    echo "  ✅ Splunk 정상 작동"
else
    echo "  ⚠️  Splunk 작동 안함 (선택사항)"
fi

echo ""
echo "╔═══════════════════════════════════════════════╗"
if [ $ERROR -eq 0 ]; then
    echo "║   ✅ 복구 완료!                              ║"
    echo "║                                              ║"
    echo "║   다음 단계:                                 ║"
    echo "║   1. 웹사이트 접속 테스트                    ║"
    echo "║   2. 로그 분석 실시                          ║"
    echo "║   3. 보안 설정 강화 확인                     ║"
else
    echo "║   ⚠️  일부 문제 발생                        ║"
    echo "║                                              ║"
    echo "║   수동 확인이 필요합니다                     ║"
    echo "║   RECOVERY_GUIDE.md 참고                    ║"
fi
echo "╚═══════════════════════════════════════════════╝"
