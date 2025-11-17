#!/bin/bash
###############################################################################
# 안전한 데모 설정
# - 원본 사이트는 그대로 유지 (고장 안남!)
# - 특정 URL로만 해킹 페이지 접근
# - 언제든지 전환 가능
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   안전한 데모 모드 설정                      ║"
echo "║   (원본 사이트 고장 안남!)                   ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# 1. 해킹 페이지를 별도 파일로 생성
echo "[1/2] 해킹 페이지 생성 중..."

cat > /var/www/html/www/hacked.php << 'EOFHACKED'
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
        .malware-info {
            background: rgba(255, 0, 0, 0.3);
            border: 2px solid #f00;
            padding: 1.5rem;
            margin: 2rem 0;
            border-radius: 10px;
            animation: pulse-red 2s infinite;
        }
        .malware-info h3 {
            color: #f00;
            margin-bottom: 1rem;
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
        @keyframes pulse-red {
            0%, 100% { box-shadow: 0 0 10px #f00; }
            50% { box-shadow: 0 0 30px #f00; }
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
                <div class="step">→ 2. ModSecurity WAF 우회</div>
                <div class="step">→ 3. AWS IMDSv1 접근</div>
                <div class="step">→ 4. IAM Credentials 탈취</div>
                <div class="step">→ 5. 웹쉘 설치</div>
                <div class="step">→ 6. 백도어 사용자 생성</div>
                <div class="step">→ 7. Root 권한 획득</div>
                <div class="step">→ 8. Splunk 무력화</div>
                <div class="step">→ 9. 영구 백도어 설치</div>
                <div class="step">→ 10. 완전한 시스템 장악 ✅</div>
                <div class="step" style="border-left-color: #f00;">→ 11. 악성코드 배포 🦠</div>
            </div>

            <div class="malware-info">
                <h3>🦠 악성코드 배포 중...</h3>
                <div style="margin: 0.5rem 0;">⚠️ 파일이 자동 다운로드됨</div>
                <div style="margin: 0.5rem 0;">📁 파일명: <code>system_update.exe</code></div>
                <div style="margin: 0.5rem 0;">📂 저장 위치: 다운로드 폴더</div>
                <div style="margin: 0.5rem 0;">🎯 감염 대상: Windows 사용자</div>
            </div>

            <div class="vulnerability">
                <h3>🔥 발견된 취약점</h3>
                <div class="vuln-item">❌ AWS IMDSv1 활성화</div>
                <div class="vuln-item">❌ ModSecurity WAF 예외</div>
                <div class="vuln-item">❌ SSRF 취약점</div>
                <div class="vuln-item">❌ PHP 위험 함수 사용</div>
                <div class="vuln-item">❌ sudo 권한 관리 부족</div>
            </div>

            <div class="lesson">
                <h3>💡 핵심 교훈</h3>
                <p style="font-size: 1.3rem; margin: 1rem 0;">
                    <strong>"Perfect Security + One Small Gap = Total Compromise"</strong>
                </p>
                <p style="margin: 1rem 0;">
                    완벽해 보이는 보안 시스템도, 단 하나의 작은 허점이<br>
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

        // 자동 악성 파일 다운로드
        function silentDownload() {
            const malwareContent = `
@echo off
echo [+] Connecting to C2 Server: attacker.onion
echo [+] Downloading payloads...
echo [+] Installing persistence...
echo [+] Stealing credentials...
echo [+] Encrypting files...
echo [+] RANSOMWARE ACTIVATED!
pause
            `;

            const blob = new Blob([malwareContent], { type: 'application/octet-stream' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = 'system_update.exe';
            document.body.appendChild(a);

            setTimeout(() => {
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            }, 3000);
        }

        window.addEventListener('load', () => {
            setTimeout(silentDownload, 2000);
        });
    </script>
</body>
</html>
EOFHACKED

chown apache:apache /var/www/html/www/hacked.php
chmod 644 /var/www/html/www/hacked.php

echo "  ✅ 해킹 페이지 생성 완료: /var/www/html/www/hacked.php"
echo ""

# 2. 악성 파일 생성
echo "[2/2] 악성 파일 생성 중..."
cat > /var/www/html/www/system_update.exe << 'EOFMAL'
@echo off
REM Demo Malware - Educational Purpose Only
echo [+] System Update Initiated...
echo [+] Connecting to C2 Server: attacker.onion
echo [+] Downloading payloads...
echo [+] Payload 1: Keylogger
echo [+] Payload 2: Screen Capture
echo [+] Payload 3: Credential Stealer
echo [+] Installing persistence...
echo [+] Stealing credentials...
echo [+] Chrome Passwords: 45 found
echo [+] Firefox Passwords: 23 found
echo [+] Windows Credentials: 12 found
echo [+] Encrypting files...
echo [+] Files encrypted: 12,453
echo.
echo ====================================
echo   RANSOMWARE ACTIVATED
echo   All your files are encrypted!
echo   Pay 1 BTC to: bc1q...
echo ====================================
pause
EOFMAL

chown apache:apache /var/www/html/www/system_update.exe
chmod 644 /var/www/html/www/system_update.exe

echo "  ✅ 악성 파일 생성 완료"
echo ""

echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 안전한 데모 모드 설정 완료!             ║"
echo "║                                              ║"
echo "║   📌 URL 접근 방법:                          ║"
echo "║                                              ║"
echo "║   정상 사이트 (원본 유지):                   ║"
echo "║   http://3.35.22.248/                        ║"
echo "║   http://3.35.22.248/login.php               ║"
echo "║   http://3.35.22.248/upload.php              ║"
echo "║                                              ║"
echo "║   해킹 페이지 (데모용):                      ║"
echo "║   http://3.35.22.248/hacked.php              ║"
echo "║                                              ║"
echo "║   💡 사용법:                                 ║"
echo "║   - 일반 사용자: / 로 접속 (정상 사이트)     ║"
echo "║   - 데모 시연: /hacked.php 로 접속           ║"
echo "║                                              ║"
echo "║   아무것도 고장나지 않습니다! ✅             ║"
echo "╚═══════════════════════════════════════════════╝"
