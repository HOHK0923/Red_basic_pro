<?php
header('Content-Type: text/html; charset=UTF-8');
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Breached</title>
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
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .glitch-wrapper {
            position: relative;
            width: 100%;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            background: linear-gradient(180deg, #000 0%, #0a0a0a 50%, #000 100%);
        }

        .scanlines {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 255, 0, 0.03) 0px,
                rgba(0, 255, 0, 0.03) 1px,
                transparent 1px,
                transparent 2px
            );
            pointer-events: none;
            z-index: 9999;
            animation: scanlines 8s linear infinite;
        }

        @keyframes scanlines {
            0% { transform: translateY(0); }
            100% { transform: translateY(10px); }
        }

        .vhs-effect {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(
                rgba(18, 16, 16, 0) 50%,
                rgba(0, 0, 0, 0.25) 50%
            );
            background-size: 100% 4px;
            pointer-events: none;
            z-index: 9998;
        }

        .skull-container {
            text-align: center;
            position: relative;
            z-index: 10;
        }

        .skull {
            font-size: clamp(40px, 12vw, 120px);
            font-weight: bold;
            color: #ff0000;
            text-shadow:
                0 0 5px #ff0000,
                0 0 10px #ff0000,
                0 0 20px #ff0000,
                0 0 40px #ff0000,
                0 0 80px #ff0000;
            animation: skull-glitch 3s infinite, skull-pulse 2s infinite;
            letter-spacing: 10px;
            margin-bottom: 30px;
        }

        @keyframes skull-glitch {
            0%, 90%, 100% {
                text-shadow:
                    0 0 5px #ff0000,
                    0 0 10px #ff0000,
                    0 0 20px #ff0000;
            }
            92% {
                text-shadow:
                    -2px 0 5px #ff0000,
                    2px 0 10px #00ff00,
                    0 0 20px #ff0000;
                transform: skew(-2deg);
            }
            94% {
                text-shadow:
                    2px 0 5px #ff0000,
                    -2px 0 10px #0000ff,
                    0 0 20px #ff0000;
                transform: skew(2deg);
            }
            96% {
                text-shadow:
                    0 0 5px #ff0000,
                    0 0 10px #ff0000,
                    0 0 20px #ff0000;
                transform: skew(0deg);
            }
        }

        @keyframes skull-pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }

        .warning-box {
            background: rgba(255, 0, 0, 0.1);
            border: 3px solid #ff0000;
            padding: 30px 50px;
            margin: 30px auto;
            max-width: 800px;
            position: relative;
            animation: border-blink 1s infinite, box-glitch 5s infinite;
        }

        @keyframes border-blink {
            0%, 49%, 100% { border-color: #ff0000; }
            50%, 99% { border-color: #ff6600; }
        }

        @keyframes box-glitch {
            0%, 90%, 100% { transform: translateX(0); }
            92% { transform: translateX(-5px); }
            94% { transform: translateX(5px); }
            96% { transform: translateX(-3px); }
            98% { transform: translateX(3px); }
        }

        .warning-title {
            font-size: clamp(24px, 5vw, 48px);
            color: #ff0000;
            text-transform: uppercase;
            letter-spacing: 5px;
            margin-bottom: 20px;
            animation: text-flicker 2s infinite;
        }

        @keyframes text-flicker {
            0%, 19%, 21%, 23%, 25%, 54%, 56%, 100% {
                opacity: 1;
                text-shadow:
                    0 0 5px #ff0000,
                    0 0 10px #ff0000,
                    0 0 15px #ff0000;
            }
            20%, 24%, 55% {
                opacity: 0.4;
                text-shadow: none;
            }
        }

        .warning-text {
            font-size: clamp(14px, 2.5vw, 24px);
            color: #0f0;
            line-height: 1.8;
            text-shadow: 0 0 5px #0f0;
        }

        .danger-icon {
            font-size: clamp(40px, 8vw, 80px);
            margin-bottom: 20px;
            animation: rotate-icon 3s linear infinite;
        }

        @keyframes rotate-icon {
            0% { transform: rotate(0deg); }
            25% { transform: rotate(-15deg); }
            50% { transform: rotate(0deg); }
            75% { transform: rotate(15deg); }
            100% { transform: rotate(0deg); }
        }

        .breach-info {
            margin-top: 40px;
            font-size: clamp(12px, 2vw, 18px);
            color: #ffff00;
            text-shadow: 0 0 5px #ffff00;
        }

        .breach-info ul {
            list-style: none;
            text-align: left;
            display: inline-block;
            margin-top: 15px;
        }

        .breach-info li {
            margin: 8px 0;
            padding-left: 20px;
            position: relative;
        }

        .breach-info li:before {
            content: "▶";
            position: absolute;
            left: 0;
            animation: blink-arrow 1s infinite;
        }

        @keyframes blink-arrow {
            0%, 49% { opacity: 1; }
            50%, 100% { opacity: 0; }
        }

        .signature {
            margin-top: 50px;
            font-size: clamp(16px, 3vw, 28px);
            color: #ff00ff;
            text-shadow: 0 0 10px #ff00ff;
            animation: glow-pulse 2s infinite;
        }

        @keyframes glow-pulse {
            0%, 100% {
                text-shadow: 0 0 10px #ff00ff;
            }
            50% {
                text-shadow:
                    0 0 20px #ff00ff,
                    0 0 30px #ff00ff,
                    0 0 40px #ff00ff;
            }
        }

        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 1;
            opacity: 0.15;
        }

        @media (max-width: 768px) {
            .warning-box {
                padding: 20px 25px;
                margin: 20px 15px;
            }
            .skull {
                letter-spacing: 5px;
            }
        }
    </style>
</head>
<body>
    <div class="scanlines"></div>
    <div class="vhs-effect"></div>
    <canvas class="matrix-bg" id="matrix"></canvas>

    <div class="glitch-wrapper">
        <div class="skull-container">
            <div class="danger-icon">☠️</div>
            <div class="skull">BREACHED</div>

            <div class="warning-box">
                <div class="warning-title">⚠ SYSTEM COMPROMISED ⚠</div>
                <div class="warning-text">
                    이 시스템은 무단 침입 당했습니다<br>
                    모든 데이터가 노출되었습니다<br>
                    당신의 활동은 모니터링 되고 있습니다
                </div>
            </div>

            <div class="breach-info">
                <strong>발견된 취약점:</strong>
                <ul>
                    <li>SQL Injection - 데이터베이스 완전 접근</li>
                    <li>Cross-Site Scripting - 사용자 세션 탈취</li>
                    <li>Weak Authentication - 관리자 권한 획득</li>
                    <li>Local File Inclusion - 시스템 파일 노출</li>
                    <li>Privilege Escalation - ROOT 권한 탈취</li>
                </ul>
            </div>

            <div class="signature">
                [ 침투 테스트 by Red Team ]<br>
                Grey Box Penetration Testing - 2025
            </div>

            <div style="margin-top: 30px; font-size: 14px; color: #00ffff;">
                <span id="timestamp"></span><br>
                Server: 52.78.221.104 | Method: Web Shell → SUID → Root
            </div>
        </div>
    </div>

    <script>
        // Matrix background
        const canvas = document.getElementById('matrix');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = Array(Math.floor(columns)).fill(1);

        function drawMatrix() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#0f0';
            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }

        setInterval(drawMatrix, 35);

        // Timestamp
        document.getElementById('timestamp').textContent =
            '침투 일시: ' + new Date().toLocaleString('ko-KR');

        // Window resize
        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });

        // 경고 팝업 - 다운로드 대신 알림으로 표시
        setTimeout(() => {
            // 다운로드도 시도하되, 실패해도 괜찮음
            try {
            const warning = `
⚠️⚠️⚠️ 주의하세요! ⚠️⚠️⚠️

이 사이트는 매우 위험합니다!

발견된 보안 취약점:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. SQL Injection
   → 데이터베이스 전체 접근 가능
   → 사용자 정보 유출 위험

2. Cross-Site Scripting (XSS)
   → 악성 스크립트 실행 가능
   → 세션 쿠키 탈취 위험

3. 약한 인증 시스템
   → 비밀번호 추측 공격 가능
   → 무단 관리자 권한 획득

4. Local File Inclusion (LFI)
   → 시스템 파일 노출
   → 민감 정보 유출

5. 권한 상승 취약점
   → ROOT 권한 탈취 성공
   → 전체 시스템 제어 가능

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ 권장사항:
- 이 사이트 사용 즉시 중단
- 비밀번호를 다른 사이트와 공유했다면 즉시 변경
- 개인정보가 노출되었을 가능성 있음
- 관리자에게 즉시 보고 필요

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

이것은 침투 테스트 결과입니다.
실제 악의적 해킹이 발생하기 전에
보안 취약점을 수정하십시오.

침투 테스트 팀: Red Team
날짜: ${new Date().toLocaleString('ko-KR')}
서버: 52.78.221.104
`;

                const blob = new Blob([warning], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'SECURITY_WARNING.txt';
                a.style.display = 'none';
                document.body.appendChild(a);
                a.click();
                setTimeout(() => {
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }, 100);
            } catch(e) {
                // 다운로드 실패 시 무시
            }

            // 경고 메시지 팝업
            alert(`⚠️ 보안 경고 ⚠️\n\n이 사이트는 심각한 보안 취약점이 발견되었습니다!\n\n• SQL Injection\n• XSS (Cross-Site Scripting)\n• 약한 인증 시스템\n• ROOT 권한 탈취\n\n즉시 사용을 중단하고 관리자에게 보고하세요!`);
        }, 1000);
    </script>
</body>
</html>
