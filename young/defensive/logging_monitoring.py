# 실시간 공격 탐지 스크립트
import re
from collections import defaultdict
from datetime import datetime, timedelta

class SecurityMonitor:
    def __init__(self):
        self.failed_logins = defaultdict(list)
        self.suspicious_patterns = {
            'sql': re.compile(r"(union|select|from|where|or|and|--|/\*)", re.I),
            'xss': re.compile(r"(<script|javascript:|onerror=)", re.I),
            'lfi': re.compile(r"(\.\./|/etc/|/proc/)")
        }
    
    def analyze_request(self, ip, path, params, headers):
        alerts = []
        
        # SQL Injection 탐지
        for param, value in params.items():
            if self.suspicious_patterns['sql'].search(str(value)):
                alerts.append({
                    'type': 'SQL_INJECTION_ATTEMPT',
                    'ip': ip,
                    'param': param,
                    'value': value,
                    'timestamp': datetime.now()
                })
        
        # 실패한 로그인 추적
        if path == '/login.php' and 'failed' in str(params):
            self.failed_logins[ip].append(datetime.now())
            recent_failures = [t for t in self.failed_logins[ip] 
                             if t > datetime.now() - timedelta(minutes=5)]
            if len(recent_failures) > 5:
                alerts.append({
                    'type': 'BRUTE_FORCE_ATTEMPT',
                    'ip': ip,
                    'attempts': len(recent_failures)
                })
        
        return alerts