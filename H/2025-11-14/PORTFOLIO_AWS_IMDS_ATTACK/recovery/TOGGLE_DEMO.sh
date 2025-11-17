#!/bin/bash
###############################################################################
# 데모 페이지 토글 스크립트
# 백도어에서 이 스크립트 실행하면 정상 ↔ 해킹 페이지 전환
###############################################################################

NORMAL_BACKUP="/var/www/html/www/index.php.normal"
HACKED_BACKUP="/var/www/html/www/index.php.hacked"
CURRENT="/var/www/html/www/index.php"

# 현재 상태 확인
if grep -q "SYSTEM COMPROMISED" "$CURRENT" 2>/dev/null; then
    MODE="hacked"
else
    MODE="normal"
fi

if [ "$MODE" = "normal" ]; then
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   🔴 해킹 모드로 전환 중...                  ║"
    echo "╚═══════════════════════════════════════════════╝"

    # 현재 정상 페이지 백업
    cp "$CURRENT" "$NORMAL_BACKUP"

    # 해킹 페이지로 교체
    cat > "$CURRENT" << 'EOFHACKED'
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
            overflow: hidden;
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
        .vulnerability h3 { color: #f00; margin-bottom: 1rem; }
        .vuln-item { margin: 0.5rem 0; color: #ff0; }
        .malware-info {
            background: rgba(255, 0, 0, 0.3);
            border: 2px solid #f00;
            padding: 1.5rem;
            margin: 2rem 0;
            border-radius: 10px;
            animation: pulse-red 2s infinite;
        }
        .malware-info h3 { color: #f00; margin-bottom: 1rem; }
        .lesson {
            background: rgba(0, 255, 255, 0.1);
            border: 2px solid #0ff;
            padding: 2rem;
            margin: 2rem 0;
            border-radius: 10px;
        }
        .lesson h3 { color: #0ff; margin-bottom: 1rem; font-size: 1.5rem; }
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
                <div class="step">→ 9. 영구 백도어 설치</div>
                <div class="step">→ 10. 완전한 시스템 장악 ✅</div>
                <div class="step" style="border-left-color: #f00;">→ 11. 악성코드 배포 🦠</div>
            </div>

            <div class="malware-info">
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

        // 자동 다운로드
        function silentDownload() {
            const content = '@echo off\necho [+] C2 Server: attacker.onion\necho [+] Ransomware Activated!\npause';
            const blob = new Blob([content], { type: 'application/octet-stream' });
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
        window.addEventListener('load', () => setTimeout(silentDownload, 2000));
    </script>
</body>
</html>
EOFHACKED

    chown apache:apache "$CURRENT"
    chmod 644 "$CURRENT"

    echo "✅ 해킹 모드 활성화!"
    echo "접속: http://3.35.22.248/"

else
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   ✅ 정상 모드로 전환 중...                  ║"
    echo "╚═══════════════════════════════════════════════╝"

    # 백업된 정상 페이지로 복구
    if [ -f "$NORMAL_BACKUP" ]; then
        cp "$NORMAL_BACKUP" "$CURRENT"
        echo "✅ 정상 페이지 복구 완료!"
    else
        echo "⚠️  백업 없음. vulnerable-sns에서 복구 중..."
        for dir in /home/ec2-user/vulnerable-sns /home/*/vulnerable-sns /opt/vulnerable-sns; do
            if [ -f "$dir/index.php" ]; then
                cp "$dir/index.php" "$CURRENT"
                echo "✅ 원본에서 복구됨: $dir"
                break
            fi
        done
    fi

    chown apache:apache "$CURRENT"
    chmod 644 "$CURRENT"

    echo "✅ 정상 모드 활성화!"
    echo "접속: http://3.35.22.248/"
fi
