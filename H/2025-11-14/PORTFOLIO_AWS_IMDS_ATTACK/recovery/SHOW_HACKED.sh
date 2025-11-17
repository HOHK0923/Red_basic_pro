#!/bin/bash
###############################################################################
# 해킹 페이지 전환 스크립트
# 언제든지 실행하여 해킹된 사이트로 전환 가능
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   해킹 페이지로 전환 중...                   ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root 권한이 필요합니다. sudo를 사용하세요."
    exit 1
fi

# 해킹 페이지 생성
cat > /var/www/html/www/index.php << 'EOFHACKED'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SYSTEM COMPROMISED</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            overflow: hidden;
            position: relative;
        }
        #matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 1;
            opacity: 0.2;
        }
        .container {
            position: relative;
            z-index: 10;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 2rem;
        }
        .content {
            max-width: 900px;
            text-align: center;
            animation: glitch 1s infinite;
        }
        h1 {
            font-size: 4rem;
            color: #f00;
            text-shadow: 0 0 20px #f00, 0 0 40px #f00;
            margin-bottom: 2rem;
            animation: pulse 2s infinite;
        }
        .warning {
            font-size: 1.5rem;
            color: #ff0;
            margin-bottom: 2rem;
            animation: blink 1s infinite;
        }
        .attack-chain {
            background: rgba(0, 255, 0, 0.1);
            border: 2px solid #0f0;
            padding: 2rem;
            margin: 2rem 0;
            text-align: left;
            border-radius: 10px;
        }
        .attack-chain h2 {
            color: #0ff;
            margin-bottom: 1rem;
            text-align: center;
        }
        .step {
            margin: 1rem 0;
            padding: 0.5rem;
            border-left: 3px solid #0f0;
            padding-left: 1rem;
        }
        .vulnerability {
            background: rgba(255, 0, 0, 0.2);
            border: 2px solid #f00;
            padding: 2rem;
            margin: 2rem 0;
            border-radius: 10px;
        }
        .vulnerability h3 {
            color: #f00;
            margin-bottom: 1rem;
        }
        .vuln-item {
            margin: 0.5rem 0;
            color: #ff0;
        }
        .lesson {
            background: rgba(0, 255, 255, 0.1);
            border: 2px solid #0ff;
            padding: 2rem;
            margin: 2rem 0;
            border-radius: 10px;
        }
        .lesson h3 {
            color: #0ff;
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }
        .backdoor-info {
            background: rgba(255, 0, 255, 0.1);
            border: 2px solid #f0f;
            padding: 1.5rem;
            margin: 2rem 0;
            border-radius: 10px;
        }
        .backdoor-info h3 {
            color: #f0f;
            margin-bottom: 1rem;
        }
        code {
            background: rgba(0, 255, 0, 0.2);
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            color: #0f0;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        @keyframes blink {
            0%, 50%, 100% { opacity: 1; }
            25%, 75% { opacity: 0; }
        }
        @keyframes glitch {
            0%, 100% { transform: translateX(0); }
            20% { transform: translateX(-2px); }
            40% { transform: translateX(2px); }
            60% { transform: translateX(-2px); }
            80% { transform: translateX(2px); }
        }
    </style>
</head>
<body>
    <canvas id="matrix-bg"></canvas>
    <div class="container">
        <div class="content">
            <h1>⚠️ SYSTEM COMPROMISED ⚠️</h1>
            <div class="warning">WARNING: UNAUTHORIZED ACCESS DETECTED</div>

            <div class="attack-chain">
                <h2>🔴 공격 체인 (Attack Chain)</h2>
                <div class="step">→ 1. SSRF 취약점 발견 (health.php)</div>
                <div class="step">→ 2. ModSecurity WAF 우회 (예외 규칙 악용)</div>
                <div class="step">→ 3. AWS IMDSv1 접근</div>
                <div class="step">→ 4. IAM Credentials 탈취</div>
                <div class="step">→ 5. 웹쉘 설치</div>
                <div class="step">→ 6. 백도어 사용자 생성 (sysadmin)</div>
                <div class="step">→ 7. sudo NOPASSWD 권한 획득</div>
                <div class="step">→ 8. Splunk SIEM 무력화</div>
                <div class="step">→ 9. 영구 백도어 설치 (Cron)</div>
                <div class="step">→ 10. 완전한 시스템 장악 ✅</div>
            </div>

            <div class="vulnerability">
                <h3>🔥 발견된 취약점</h3>
                <div class="vuln-item">❌ AWS IMDSv1 활성화 (SSRF → Credentials 탈취)</div>
                <div class="vuln-item">❌ ModSecurity WAF 예외 설정 (/api/health.php)</div>
                <div class="vuln-item">❌ SSRF 취약점 (입력 검증 없음)</div>
                <div class="vuln-item">❌ PHP 위험 함수 사용 가능 (system, file_get_contents)</div>
                <div class="vuln-item">❌ sudo 권한 관리 부족</div>
            </div>

            <div class="backdoor-info">
                <h3>🚪 설치된 백도어</h3>
                <div>사용자: <code>sysadmin</code></div>
                <div>비밀번호: <code>Adm1n!2024#Secure</code></div>
                <div>권한: <code>sudo NOPASSWD (Root 권한)</code></div>
                <div>자동 복구: <code>Cron (*/5 * * * *)</code></div>
                <div>웹쉘: <code>/api/health.php</code></div>
            </div>

            <div class="lesson">
                <h3>💡 핵심 교훈</h3>
                <p style="font-size: 1.3rem; margin: 1rem 0;">
                    <strong>"Perfect Security + One Small Gap = Total Compromise"</strong>
                </p>
                <p style="margin: 1rem 0;">
                    완벽해 보이는 보안 시스템도, 단 하나의 작은 허점<br>
                    (WAF 예외 설정 + IMDSv1)이<br>
                    전체 시스템의 완전한 장악으로 이어질 수 있습니다.
                </p>
            </div>

            <div style="margin-top: 3rem; color: #666;">
                <p>Red Team Penetration Testing Demo</p>
                <p>2025-11-17</p>
            </div>
        </div>
    </div>

    <script>
        // Matrix rain effect
        const canvas = document.getElementById('matrix-bg');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()';
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = [];

        for (let i = 0; i < columns; i++) {
            drops[i] = Math.random() * canvas.height / fontSize;
        }

        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#0f0';
            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const char = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(char, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.95) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }

        setInterval(draw, 33);

        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });
    </script>
</body>
</html>
EOFHACKED

# .htaccess로 모든 페이지 리다이렉트
cat > /var/www/html/www/.htaccess << 'EOFHTACCESS'
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_URI} !^/index\.php$
RewriteCond %{REQUEST_URI} !^/api/
RewriteRule ^.*$ /index.php [L]
</IfModule>
EOFHTACCESS

chown apache:apache /var/www/html/www/index.php
chown apache:apache /var/www/html/www/.htaccess
chmod 644 /var/www/html/www/index.php
chmod 644 /var/www/html/www/.htaccess

systemctl restart httpd

echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 해킹 페이지로 전환 완료!                ║"
echo "║                                              ║"
echo "║   웹사이트 접속: http://3.35.22.248/         ║"
echo "║                                              ║"
echo "║   정상 페이지로 복구:                        ║"
echo "║   sudo bash /tmp/DEMO_RESTORE.sh             ║"
echo "╚═══════════════════════════════════════════════╝"
