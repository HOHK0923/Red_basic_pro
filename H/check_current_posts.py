#!/usr/bin/env python3
"""
현재 게시된 게시물 확인
"""

import requests
from bs4 import BeautifulSoup

TARGET = "http://52.78.221.104"
LOGIN_URL = f"{TARGET}/login.php"
INDEX_URL = f"{TARGET}/index.php"

USERNAME = "admin"
PASSWORD = "admin123"

def login():
    """로그인"""
    session = requests.Session()
    data = {'username': USERNAME, 'password': PASSWORD}
    response = session.post(LOGIN_URL, data=data)
    return session

def check_posts(session):
    """게시물 확인"""
    response = session.get(INDEX_URL)

    print("=" * 60)
    print("📝 현재 게시물 확인")
    print("=" * 60)
    print()

    # HTML에서 SVG, script 태그 찾기
    if '<svg' in response.text.lower():
        print("[+] SVG 태그 발견!")
        print("    → SVG onload는 실행됨")

    if '<script' in response.text.lower():
        print("[+] SCRIPT 태그 발견!")
        print("    → <script> 태그가 필터링되지 않음")
    else:
        print("[-] SCRIPT 태그 없음")
        print("    → <script> 태그가 필터링됨")

    if '<iframe' in response.text.lower():
        print("[+] IFRAME 태그 발견!")

    if '<img' in response.text.lower() and 'onerror' in response.text.lower():
        print("[+] IMG onerror 발견!")

    print()
    print("=" * 60)
    print("분석:")
    print("=" * 60)
    print()

    if '<script' not in response.text.lower():
        print("❌ <script> 태그가 필터링되고 있습니다.")
        print()
        print("해결책:")
        print("1. SVG onload만 사용 (현재 상태)")
        print("2. localStorage는 SVG 내부에서만 설정 가능")
        print("3. 다른 페이지에는 적용 불가")
        print()
        print("→ 메인 페이지만 장악 가능 (현재 상태가 최선)")
    else:
        print("✅ <script> 태그 사용 가능")
        print("   → localStorage로 전역 장악 가능")

    print()

if __name__ == "__main__":
    session = login()
    check_posts(session)
