import requests
from bs4 import BeautifulSoup
from urllib.parse import quote
import time
import json
import re
from datetime import datetime

# WAF 규칙 예시
waf_rules = {
    'sql_injection': [
        r"(\"|')\s*(or|and)\s*(\"|')?(\d+|[a-z]+)(\"|')?\s*=\s*(\"|')?(\d+|[a-z]+)",
        r"--\s*$",
        r"\/\*.*\*\/"
    ],
    'xss': [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+\s*="
    ],
    'lfi': [
        r"\.\./",
        r"/etc/passwd",
        r"/proc/self"
    ]
}

# Rate limiting
RATE_LIMIT = {
    'login': {'requests': 5, 'window': 60},  # 분당 5회
    'upload': {'requests': 3, 'window': 60}
}