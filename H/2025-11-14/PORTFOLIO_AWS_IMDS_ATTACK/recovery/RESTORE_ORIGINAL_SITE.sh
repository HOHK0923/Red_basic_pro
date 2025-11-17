#!/bin/bash
###############################################################################
# 원본 SNS 사이트 복구 스크립트
# vulnerable-sns 폴더의 내용을 서버로 복구
# 백도어는 유지됨
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   원본 SNS 사이트 복구                       ║"
echo "║   (백도어 유지)                              ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root 권한이 필요합니다. sudo를 사용하세요."
    exit 1
fi

# 1. 현재 해킹된 파일 백업
echo "[1/5] 현재 해킹된 파일 백업 중..."
mkdir -p /var/www/html/www.hacked.backup
cp -r /var/www/html/www/* /var/www/html/www.hacked.backup/ 2>/dev/null
echo "  ✅ 백업 완료: /var/www/html/www.hacked.backup/"
echo ""

# 2. .htaccess 제거
echo "[2/5] .htaccess 제거 중..."
find /var/www/html/www -name ".htaccess" -delete 2>/dev/null
echo "  ✅ .htaccess 제거 완료"
echo ""

# 3. vulnerable-sns 파일 확인
echo "[3/5] 원본 파일 확인 중..."
ORIGINAL_PATH="/home/ec2-user/vulnerable-sns"

if [ ! -d "$ORIGINAL_PATH" ]; then
    echo "  ⚠️  원본 폴더가 없습니다: $ORIGINAL_PATH"
    echo "  대체 경로를 찾는 중..."

    # 여러 경로 시도
    for path in "/tmp/vulnerable-sns" "/opt/vulnerable-sns" "/var/www/vulnerable-sns"; do
        if [ -d "$path" ]; then
            ORIGINAL_PATH="$path"
            echo "  ✅ 발견: $ORIGINAL_PATH"
            break
        fi
    done
fi

if [ -d "$ORIGINAL_PATH" ]; then
    echo "  ✅ 원본 파일 발견: $ORIGINAL_PATH"

    # 파일 복사
    echo ""
    echo "[4/5] 원본 파일 복구 중..."

    # 주요 파일들 복사
    cp "$ORIGINAL_PATH/index.php" /var/www/html/www/ 2>/dev/null && echo "  - index.php 복구됨"
    cp "$ORIGINAL_PATH/login.php" /var/www/html/www/ 2>/dev/null && echo "  - login.php 복구됨"
    cp "$ORIGINAL_PATH/register.php" /var/www/html/www/ 2>/dev/null && echo "  - register.php 복구됨"
    cp "$ORIGINAL_PATH/upload.php" /var/www/html/www/ 2>/dev/null && echo "  - upload.php 복구됨"
    cp "$ORIGINAL_PATH/profile.php" /var/www/html/www/ 2>/dev/null && echo "  - profile.php 복구됨"
    cp "$ORIGINAL_PATH/logout.php" /var/www/html/www/ 2>/dev/null && echo "  - logout.php 복구됨"
    cp "$ORIGINAL_PATH/new_post.php" /var/www/html/www/ 2>/dev/null && echo "  - new_post.php 복구됨"
    cp "$ORIGINAL_PATH/file.php" /var/www/html/www/ 2>/dev/null && echo "  - file.php 복구됨"
    cp "$ORIGINAL_PATH/download.php" /var/www/html/www/ 2>/dev/null && echo "  - download.php 복구됨"
    cp "$ORIGINAL_PATH/config.php" /var/www/html/www/ 2>/dev/null && echo "  - config.php 복구됨"

    echo "  ✅ 원본 파일 복구 완료"
else
    echo "  ⚠️  원본 폴더를 찾을 수 없습니다"
    echo "  기본 SNS 사이트를 생성합니다..."

    # 간단한 SNS 사이트 생성
    cat > /var/www/html/www/index.php << 'EOFINDEX'
<?php
session_start();
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SNS - Social Network Service</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f0f2f5;
        }
        .header {
            background: #4267B2;
            color: white;
            padding: 15px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header .container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 20px;
        }
        .header h1 {
            font-size: 28px;
        }
        .header nav a {
            color: white;
            text-decoration: none;
            margin-left: 20px;
            padding: 8px 16px;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .header nav a:hover {
            background: rgba(255,255,255,0.2);
        }
        .main {
            max-width: 800px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .welcome {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            margin-bottom: 30px;
        }
        .welcome h2 {
            color: #1c1e21;
            margin-bottom: 15px;
            font-size: 32px;
        }
        .welcome p {
            color: #606770;
            font-size: 18px;
            margin-bottom: 30px;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        .feature {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        .feature:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        .feature-icon {
            font-size: 48px;
            margin-bottom: 15px;
        }
        .feature h3 {
            color: #1c1e21;
            margin-bottom: 10px;
        }
        .feature p {
            color: #606770;
        }
        .cta-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
        }
        .btn {
            display: inline-block;
            padding: 15px 40px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s;
        }
        .btn-primary {
            background: #4267B2;
            color: white;
        }
        .btn-primary:hover {
            background: #365899;
        }
        .btn-secondary {
            background: #42b72a;
            color: white;
        }
        .btn-secondary:hover {
            background: #36a420;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>📱 SNS</h1>
            <nav>
                <a href="/">홈</a>
                <a href="/login.php">로그인</a>
                <a href="/register.php">회원가입</a>
            </nav>
        </div>
    </div>

    <div class="main">
        <div class="welcome">
            <h2>소셜 네트워크에 오신 것을 환영합니다</h2>
            <p>친구들과 연결하고, 소식을 공유하세요</p>
            <div class="cta-buttons">
                <a href="/login.php" class="btn btn-primary">로그인</a>
                <a href="/register.php" class="btn btn-secondary">회원가입</a>
            </div>
        </div>

        <div class="features">
            <div class="feature">
                <div class="feature-icon">👥</div>
                <h3>친구 연결</h3>
                <p>친구들과 쉽게 연결하고 소통하세요</p>
            </div>
            <div class="feature">
                <div class="feature-icon">📸</div>
                <h3>사진 공유</h3>
                <p>소중한 순간을 사진으로 공유하세요</p>
            </div>
            <div class="feature">
                <div class="feature-icon">💬</div>
                <h3>실시간 소통</h3>
                <p>댓글과 좋아요로 소통하세요</p>
            </div>
        </div>
    </div>
</body>
</html>
EOFINDEX

    cat > /var/www/html/www/login.php << 'EOFLOGIN'
<?php
session_start();
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>로그인 - SNS</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            width: 400px;
        }
        h2 {
            text-align: center;
            color: #1c1e21;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #606770;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #dddfe2;
            border-radius: 5px;
            font-size: 14px;
        }
        button {
            width: 100%;
            padding: 15px;
            background: #4267B2;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover {
            background: #365899;
        }
        .register-link {
            text-align: center;
            margin-top: 20px;
            color: #606770;
        }
        .register-link a {
            color: #4267B2;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>로그인</h2>
        <form method="POST" action="">
            <div class="form-group">
                <label>아이디</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>비밀번호</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">로그인</button>
        </form>
        <div class="register-link">
            계정이 없으신가요? <a href="/register.php">회원가입</a>
        </div>
    </div>
</body>
</html>
EOFLOGIN

    cat > /var/www/html/www/upload.php << 'EOFUPLOAD'
<?php
session_start();
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>파일 업로드 - SNS</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f0f2f5;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h2 {
            color: #1c1e21;
            margin-bottom: 30px;
        }
        .upload-area {
            border: 2px dashed #dddfe2;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
        }
        .upload-area:hover {
            border-color: #4267B2;
            background: #f7f9fa;
        }
        .upload-icon {
            font-size: 48px;
            margin-bottom: 15px;
        }
        button {
            margin-top: 20px;
            padding: 15px 40px;
            background: #4267B2;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
        }
        button:hover {
            background: #365899;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>📤 파일 업로드</h2>
        <form method="POST" enctype="multipart/form-data">
            <div class="upload-area">
                <div class="upload-icon">📁</div>
                <p>파일을 선택하거나 드래그하세요</p>
                <input type="file" name="file" required>
            </div>
            <button type="submit">업로드</button>
        </form>
    </div>
</body>
</html>
EOFUPLOAD

    echo "  ✅ 기본 SNS 사이트 생성 완료"
fi

echo ""

# 4. 권한 설정
echo "[5/5] 권한 설정 중..."
chown -R apache:apache /var/www/html/www
find /var/www/html/www -type f -exec chmod 644 {} \;
find /var/www/html/www -type d -exec chmod 755 {} \;
echo "  ✅ 권한 설정 완료"
echo ""

# Apache 재시작
echo "Apache 재시작 중..."
apachectl configtest && systemctl restart httpd
echo ""

echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 원본 SNS 사이트 복구 완료!             ║"
echo "║                                              ║"
echo "║   메인: http://3.35.22.248/                  ║"
echo "║   로그인: http://3.35.22.248/login.php       ║"
echo "║   회원가입: http://3.35.22.248/register.php  ║"
echo "║   업로드: http://3.35.22.248/upload.php      ║"
echo "║                                              ║"
echo "║   백도어: 유지됨 (sysadmin)                  ║"
echo "║                                              ║"
echo "║   해킹 페이지로 전환:                        ║"
echo "║   sudo bash /tmp/SHOW_HACKED_WITH_MALWARE.sh ║"
echo "╚═══════════════════════════════════════════════╝"
