#!/bin/bash
###############################################################################
# 모든 페이지 해킹 페이지로 토글
# - 해킹 모드: 모든 페이지 → 해킹 페이지로 리다이렉트
# - 정상 모드: .htaccess 제거 → 원본 페이지 작동
###############################################################################

HTACCESS="/var/www/html/www/.htaccess"
HACKED_PAGE="/var/www/html/www/hacked_display.php"

if [ -f "$HTACCESS" ]; then
    # 정상 모드로
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   ✅ 정상 모드로 전환                        ║"
    echo "╚═══════════════════════════════════════════════╝"

    rm -f "$HTACCESS"
    rm -f "$HACKED_PAGE"

    systemctl restart httpd

    echo "✅ 정상 SNS 사이트"
    echo "http://3.35.22.248/"
    echo "http://3.35.22.248/login.php"
    echo "http://3.35.22.248/upload.php"

else
    # 해킹 모드로
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   🔴 해킹 모드로 전환                        ║"
    echo "╚═══════════════════════════════════════════════╝"

    # 해킹 페이지 생성
    cat > "$HACKED_PAGE" << 'EOFHACKED'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SYSTEM COMPROMISED</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            overflow-x: hidden;
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
        .content { max-width: 900px; text-align: center; }
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
        .attack-chain h2 { color: #0ff; margin-bottom: 1rem; text-align: center; }
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
        .vulnerability h3 { color: #f00; margin-bottom: 1rem; }
        .vuln-item { margin: 0.5rem 0; color: #ff0; }
        .malware {
            background: rgba(255, 0, 0, 0.3);
            border: 2px solid #f00;
            padding: 1.5rem;
            margin: 2rem 0;
            border-radius: 10px;
            animation: pulse-red 2s infinite;
        }
        .malware h3 { color: #f00; margin-bottom: 1rem; }
        code {
            background: rgba(0, 255, 0, 0.2);
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            color: #0f0;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        @keyframes pulse-red { 0%, 100% { box-shadow: 0 0 10px #f00; } 50% { box-shadow: 0 0 30px #f00; } }
        @keyframes blink { 0%, 50%, 100% { opacity: 1; } 25%, 75% { opacity: 0; } }
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
                <div class="step">→ 2. ModSecurity WAF 우회</div>
                <div class="step">→ 3. AWS IMDSv1 접근</div>
                <div class="step">→ 4. IAM Credentials 탈취</div>
                <div class="step">→ 5. 웹쉘 설치</div>
                <div class="step">→ 6. 백도어 사용자 생성 (sysadmin)</div>
                <div class="step">→ 7. Root 권한 획득</div>
                <div class="step">→ 8. Splunk SIEM 무력화</div>
                <div class="step">→ 9. 영구 백도어 설치 (Cron)</div>
                <div class="step">→ 10. 완전한 시스템 장악 ✅</div>
                <div class="step" style="border-left-color: #f00;">→ 11. 악성코드 배포 🦠</div>
            </div>

            <div class="malware">
                <h3>🦠 악성코드 배포 중...</h3>
                <div>⚠️ 파일이 자동 다운로드됨</div>
                <div>📁 파일명: <code>system_update.exe</code></div>
                <div>📂 저장 위치: 다운로드 폴더</div>
            </div>

            <div class="vulnerability">
                <h3>🔥 발견된 취약점</h3>
                <div class="vuln-item">❌ AWS IMDSv1 활성화</div>
                <div class="vuln-item">❌ ModSecurity WAF 예외</div>
                <div class="vuln-item">❌ SSRF 취약점</div>
                <div class="vuln-item">❌ PHP 위험 함수 사용</div>
                <div class="vuln-item">❌ sudo 권한 관리 부족</div>
            </div>

            <div style="margin-top: 3rem; color: #666;">
                <p>Red Team Penetration Testing Demo</p>
                <p>2025-11-17</p>
            </div>
        </div>
    </div>

    <script>
        const canvas = document.getElementById('matrix-bg');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()';
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = [];
        for (let i = 0; i < columns; i++) drops[i] = Math.random() * canvas.height / fontSize;
        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#0f0';
            ctx.font = fontSize + 'px monospace';
            for (let i = 0; i < drops.length; i++) {
                const char = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(char, i * fontSize, drops[i] * fontSize);
                if (drops[i] * fontSize > canvas.height && Math.random() > 0.95) drops[i] = 0;
                drops[i]++;
            }
        }
        setInterval(draw, 33);

        // 자동 악성 파일 다운로드
        setTimeout(() => {
            const content = '@echo off\necho [+] C2 Server: attacker.onion\necho [+] Ransomware Activated!\npause';
            const blob = new Blob([content], { type: 'application/octet-stream' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = 'system_update.exe';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }, 3000);
    </script>
</body>
</html>
EOFHACKED

    # .htaccess로 모든 페이지를 해킹 페이지로 리다이렉트
    cat > "$HTACCESS" << 'EOFHTACCESS'
<IfModule mod_rewrite.c>
RewriteEngine On

# 해킹 페이지 자체는 리다이렉트 안함
RewriteCond %{REQUEST_URI} !^/hacked_display\.php$

# 이미지, CSS, JS 파일은 제외
RewriteCond %{REQUEST_URI} !^/uploads/
RewriteCond %{REQUEST_URI} !\.(jpg|jpeg|png|gif|css|js|ico)$

# 모든 페이지를 해킹 페이지로
RewriteRule ^.*$ /hacked_display.php [L]
</IfModule>
EOFHTACCESS

    chown apache:apache "$HACKED_PAGE"
    chown apache:apache "$HTACCESS"
    chmod 644 "$HACKED_PAGE"
    chmod 644 "$HTACCESS"

    systemctl restart httpd

    echo "🔴 해킹 모드 활성화!"
    echo "모든 페이지가 해킹 페이지로 리다이렉트됨:"
    echo "http://3.35.22.248/          → 해킹 페이지"
    echo "http://3.35.22.248/login.php → 해킹 페이지"
    echo "http://3.35.22.248/upload.php → 해킹 페이지"
fi
