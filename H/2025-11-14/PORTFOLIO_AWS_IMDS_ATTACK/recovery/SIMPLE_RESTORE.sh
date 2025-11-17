#!/bin/bash
###############################################################################
# 간단한 웹사이트 복구 스크립트
# - 백도어는 유지
# - index.php만 원래대로 복구 (다른 페이지들은 그대로)
# - .htaccess 제거
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   웹사이트 접속 복구                         ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root 권한이 필요합니다. sudo를 사용하세요."
    exit 1
fi

# 1. 기존 파일 백업
echo "[1/4] 기존 파일 백업 중..."
if [ -f /var/www/html/www/index.php ]; then
    cp /var/www/html/www/index.php /var/www/html/www/index.php.hacked.backup
    echo "  - index.php 백업됨 (index.php.hacked.backup)"
fi

# 2. .htaccess 제거 (리다이렉트 때문에 다른 페이지 접근 안되는 문제 해결)
echo "[2/4] .htaccess 제거 중..."
find /var/www/html/www -name ".htaccess" -delete 2>/dev/null
echo "  ✅ .htaccess 제거 완료"
echo ""

# 3. index.php를 간단한 메인 페이지로 교체
echo "[3/4] index.php 복구 중..."

# .backup 파일이 있으면 복구
if find /var/www/html/www -name "index.php.backup" | grep -q .; then
    cp /var/www/html/www/index.php.backup /var/www/html/www/index.php
    echo "  ✅ 백업에서 복구됨"
else
    # 없으면 간단한 메인 페이지 생성
    cat > /var/www/html/www/index.php << 'EOFINDEX'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 50px auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
        }
        .nav {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-top: 30px;
        }
        a {
            display: inline-block;
            padding: 15px 30px;
            background: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        a:hover {
            background: #45a049;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>환영합니다</h1>
        <p style="text-align: center; margin: 20px 0;">서비스가 정상적으로 작동하고 있습니다.</p>
        <div class="nav">
            <a href="/login.php">로그인</a>
            <a href="/upload.php">파일 업로드</a>
        </div>
    </div>
</body>
</html>
EOFINDEX
    echo "  ✅ 기본 페이지 생성됨"
fi

chown apache:apache /var/www/html/www/index.php
chmod 644 /var/www/html/www/index.php
echo ""

# 4. Apache 재시작
echo "[4/4] Apache 재시작 중..."
apachectl configtest 2>&1 | grep -q "Syntax OK" && echo "  - Apache 설정 정상"
systemctl restart httpd && echo "  ✅ Apache 재시작 완료"
echo ""

# 상태 확인
echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 복구 완료!                              ║"
echo "║                                              ║"
echo "║   메인 페이지: http://3.35.22.248/           ║"
echo "║   로그인: http://3.35.22.248/login.php       ║"
echo "║   업로드: http://3.35.22.248/upload.php      ║"
echo "║                                              ║"
echo "║   백도어: 유지됨 (sysadmin)                  ║"
echo "║                                              ║"
echo "║   해킹 페이지로 전환:                        ║"
echo "║   sudo bash /tmp/SHOW_HACKED.sh              ║"
echo "╚═══════════════════════════════════════════════╝"
