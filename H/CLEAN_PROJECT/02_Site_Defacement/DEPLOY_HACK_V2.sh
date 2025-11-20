#!/bin/bash
###############################################################################
# 해킹 사이트 배포 V2 - PDF로 위장
###############################################################################

WWW="/var/www/html/www"
BACKUP="/tmp/index_REAL.php"

echo "╔═══════════════════════════════════════════════╗"
echo "║   해킹 사이트 배포 V2 (PDF 위장)             ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# 서버 IP 자동 감지
echo "[*] 서버 IP 자동 감지 중..."
TARGET_SERVER=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)
if [ -z "$TARGET_SERVER" ]; then
    TARGET_SERVER=$(hostname -I | awk '{print $1}')
fi
if [ -z "$TARGET_SERVER" ]; then
    TARGET_SERVER="localhost"
fi

echo "✅ 대상 서버: $TARGET_SERVER"
echo ""

# 원본 백업
[ ! -f "$BACKUP" ] && [ -f "$WWW/index.php" ] && cp "$WWW/index.php" "$BACKUP" && echo "✅ 원본 백업"

# 악성코드 생성
mkdir -p $WWW/downloads
cat > $WWW/downloads/payload.bin << 'EOF'
@echo off
title RANSOMWARE ATTACK
color 0C
cls
echo.
echo ============================================
echo    ALL YOUR FILES ARE ENCRYPTED!
echo ============================================
echo.
echo [!] Payment Required: 5 Bitcoin
echo [+] C2 Server: CONNECTED
echo [+] Keylogger: RUNNING
echo [+] Data Exfil: IN PROGRESS
echo.
pause
EOF

chmod 644 $WWW/downloads/payload.bin
chown apache:apache $WWW/downloads/payload.bin 2>/dev/null || chown www-data:www-data $WWW/downloads/payload.bin 2>/dev/null
echo "✅ 악성코드 생성: payload.bin"

# PHP 다운로드 (PDF로 위장)
cat > $WWW/dl.php << 'EOFPHP'
<?php
$file = __DIR__ . '/downloads/payload.bin';

if (file_exists($file)) {
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: Sat, 26 Jul 1997 05:00:00 GMT');

    // PDF로 위장! (브라우저 경고 없음)
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="Security_Report_2025.pdf"');
    header('Content-Length: ' . filesize($file));

    ob_clean();
    flush();
    readfile($file);
    exit;
} else {
    http_response_code(404);
    echo 'File not found';
}
?>
EOFPHP

chmod 644 $WWW/dl.php
chown apache:apache $WWW/dl.php 2>/dev/null || chown www-data:www-data $WWW/dl.php 2>/dev/null
echo "✅ 다운로드 PHP 생성 (PDF 위장)"

# 해킹 페이지
cat > $WWW/index.php << 'EOFHTML'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your files have been encrypted</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
            color: #e0e0e0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
            padding: 2rem;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { text-align: center; padding: 3rem 0; border-bottom: 1px solid #2a2a2a; }
        .logo { font-size: 2.5rem; font-weight: 700; color: #ff3b3b; letter-spacing: 2px; margin-bottom: 1rem; }
        .subtitle { color: #888; font-size: 0.95rem; font-weight: 500; }
        .alert-box { background: linear-gradient(135deg, #2a0000 0%, #1a0000 100%); border: 1px solid #ff3b3b; border-radius: 12px; padding: 2rem; margin: 2rem 0; }
        .alert-title { font-size: 1.5rem; font-weight: 600; color: #ff3b3b; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
        .alert-content { color: #ccc; line-height: 1.6; font-size: 0.95rem; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin: 2rem 0; }
        .info-card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 8px; padding: 1.5rem; transition: border-color 0.3s; }
        .info-card:hover { border-color: #3a3a3a; }
        .info-card-title { font-size: 0.85rem; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.75rem; font-weight: 600; }
        .info-card-value { font-size: 1.1rem; color: #fff; font-weight: 500; word-break: break-all; }
        .countdown-box { background: #1a1a1a; border: 1px solid #ff3b3b; border-radius: 8px; padding: 2rem; text-align: center; margin: 2rem 0; }
        .countdown-title { color: #ff3b3b; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 1rem; font-weight: 600; }
        .countdown-timer { font-size: 3rem; font-weight: 700; color: #ff3b3b; font-variant-numeric: tabular-nums; }
        .attack-details { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 8px; padding: 2rem; margin: 2rem 0; }
        .attack-details h3 { font-size: 1.2rem; color: #fff; margin-bottom: 1.5rem; font-weight: 600; }
        .attack-chain { list-style: none; }
        .attack-chain li { padding: 0.75rem 0; border-bottom: 1px solid #2a2a2a; color: #aaa; font-size: 0.9rem; display: flex; align-items: center; gap: 1rem; }
        .attack-chain li:last-child { border-bottom: none; }
        .attack-chain li::before { content: "→"; color: #ff3b3b; font-weight: 700; flex-shrink: 0; }
        .attack-chain li.critical { color: #ff3b3b; font-weight: 500; }
        .malware-status { background: rgba(255, 59, 59, 0.1); border: 1px solid #ff3b3b; border-radius: 8px; padding: 1.5rem; margin: 2rem 0; }
        .status-item { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid rgba(255, 59, 59, 0.2); }
        .status-item:last-child { border-bottom: none; }
        .status-label { color: #ccc; font-size: 0.9rem; }
        .status-value { color: #ff3b3b; font-weight: 600; font-size: 0.9rem; }
        .status-value.success { color: #4caf50; }
        code { background: #0a0a0a; padding: 0.2rem 0.5rem; border-radius: 4px; color: #ff3b3b; font-family: 'Courier New', monospace; font-size: 0.85rem; }
        .footer { text-align: center; padding: 2rem 0; border-top: 1px solid #2a2a2a; margin-top: 3rem; color: #555; font-size: 0.85rem; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
        .pulse { animation: pulse 2s ease-in-out infinite; }
        @media (max-width: 768px) {
            body { padding: 1rem; }
            .header { padding: 2rem 0; }
            .logo { font-size: 2rem; }
            .countdown-timer { font-size: 2rem; }
            .info-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">BLACKLOCK RANSOMWARE</div>
            <div class="subtitle">Advanced Persistent Threat Detection</div>
        </div>

        <div class="alert-box">
            <div class="alert-title">
                <span>⚠</span> YOUR NETWORK HAS BEEN COMPROMISED
            </div>
            <div class="alert-content">
                All your files, databases, and backups have been encrypted with military-grade AES-256 encryption.
                Attempts to decrypt or restore files without our software will result in permanent data loss.
            </div>
        </div>

        <div class="countdown-box">
            <div class="countdown-title">Time until price doubles</div>
            <div class="countdown-timer" id="timer">47:23:15</div>
        </div>

        <div class="info-grid">
            <div class="info-card">
                <div class="info-card-title">Payment Required</div>
                <div class="info-card-value">5.2 BTC (~$185,000)</div>
            </div>
            <div class="info-card">
                <div class="info-card-title">Bitcoin Wallet</div>
                <div class="info-card-value" style="font-size:0.85rem;">bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh</div>
            </div>
            <div class="info-card">
                <div class="info-card-title">Files Encrypted</div>
                <div class="info-card-value">127,483 files</div>
            </div>
            <div class="info-card">
                <div class="info-card-title">Infection ID</div>
                <div class="info-card-value" style="font-size:0.85rem;"><?php echo strtoupper(md5(gethostname())); ?></div>
            </div>
        </div>

        <div class="malware-status">
            <div class="status-item">
                <span class="status-label">Encryption Status</span>
                <span class="status-value success">COMPLETE</span>
            </div>
            <div class="status-item">
                <span class="status-label">Payload Delivery</span>
                <span class="status-value success" id="download-status">IN PROGRESS</span>
            </div>
            <div class="status-item">
                <span class="status-label">Data Exfiltration</span>
                <span class="status-value success">ACTIVE</span>
            </div>
            <div class="status-item">
                <span class="status-label">C2 Connection</span>
                <span class="status-value success pulse">ESTABLISHED</span>
            </div>
        </div>

        <div class="attack-details">
            <h3>Attack Vector Analysis</h3>
            <ul class="attack-chain">
                <li>Initial reconnaissance: ModSecurity WAF + Splunk SIEM detected</li>
                <li>Vulnerability discovered: <code>/api/health.php</code> endpoint bypass</li>
                <li>SSRF exploitation successful</li>
                <li>AWS IMDSv1 metadata accessed</li>
                <li>IAM credentials harvested</li>
                <li>AWS Systems Manager session established</li>
                <li>Privilege escalation to root</li>
                <li class="critical">Full system compromise achieved</li>
                <li class="critical">Malware deployed: <code>Security_Report_2025.pdf</code></li>
            </ul>
        </div>

        <div class="footer">
            <p>Compromised: <?php echo date('Y-m-d H:i:s'); ?> UTC | Server: <?php echo gethostname(); ?></p>
            <p style="margin-top:0.5rem;">Perfect Security + One Configuration Error = Total Compromise</p>
        </div>
    </div>

    <iframe id="dl" style="display:none;"></iframe>

    <script>
        let timeLeft = 47 * 3600 + 23 * 60 + 15;

        function updateTimer() {
            const hours = Math.floor(timeLeft / 3600);
            const minutes = Math.floor((timeLeft % 3600) / 60);
            const seconds = timeLeft % 60;
            document.getElementById('timer').textContent =
                `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
            if (timeLeft > 0) timeLeft--;
        }

        setInterval(updateTimer, 1000);
        updateTimer();

        setTimeout(() => {
            try {
                const iframe = document.getElementById('dl');
                iframe.src = '/dl.php';
                setTimeout(() => {
                    document.getElementById('download-status').textContent = 'COMPLETE';
                }, 3000);
            } catch(e) {}
        }, 2000);
    </script>
</body>
</html>
EOFHTML

chmod 644 $WWW/index.php
chown apache:apache $WWW/index.php 2>/dev/null || chown www-data:www-data $WWW/index.php 2>/dev/null

systemctl restart httpd 2>/dev/null || systemctl restart apache2 2>/dev/null

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 완료!                                    ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo "접속: http://$TARGET_SERVER"
echo "→ 2초 후 자동 다운로드"
echo "→ 파일명: Security_Report_2025.pdf"
echo "→ 브라우저 경고 없음! (PDF로 위장)"
echo ""
echo "복구: sudo bash TOGGLE_SITE.sh"
echo ""
