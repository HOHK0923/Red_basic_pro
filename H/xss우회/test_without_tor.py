#!/usr/bin/env python3
"""
Tor 없이 테스트 - 403이 Tor 때문인지 확인
"""

import requests
import sys

BASE_URL = "http://3.34.90.201"
USERNAME = "alice"
PASSWORD = "alice2024"

session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
})

print("[*] Tor 없이 로그인 테스트...")

# 로그인
login_data = {'username': USERNAME, 'password': PASSWORD}
response = session.post(f"{BASE_URL}/login.php", data=login_data, allow_redirects=True, timeout=10)

if 'index.php' in response.url or response.status_code == 200:
    print(f"✓ 로그인 성공! (상태: {response.status_code})\n")
else:
    print(f"✗ 로그인 실패 (상태: {response.status_code})\n")
    sys.exit(1)

# 댓글 작성 테스트
print("[*] 댓글 작성 테스트...")
comment_data = {
    'post_id': 1,
    'content': 'Hello world test comment'
}
response = session.post(f"{BASE_URL}/add_comment.php", data=comment_data, allow_redirects=True, timeout=10)

print(f"상태 코드: {response.status_code}")
print(f"리다이렉트: {response.url}")

if response.status_code == 403:
    print("\n✗ 403 Forbidden - Tor 없이도 차단됨!")
    print("→ IP 차단이 아닌 다른 문제일 수 있음 (CSRF 토큰, Referer 등)")
elif response.status_code == 200 or 'index.php' in response.url:
    print("\n✓ Tor 없이는 성공!")
    print("→ 서버가 Tor exit node를 차단하고 있음")
else:
    print(f"\n? 예상치 못한 응답: {response.status_code}")

print(f"\n응답 본문 (처음 500자):\n{response.text[:500]}")
