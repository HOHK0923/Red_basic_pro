from flask import Flask, render_template, request, jsonify
from datetime import datetime
import json
import os

app = Flask(__name__)

# 데이터 저장용
attack_data = {
    'total_points': 0,
    'victims': 0,
    'total_attempts': 0,
    'logs': [],
    'victim_list': []
}

# 로그 파일들
LOG_FILE = 'csrf_attacks.json'
VICTIMS_FILE = 'victims.json'


def load_data():
    """저장된 데이터 불러오기"""
    global attack_data

    # 로그 불러오기
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            attack_data['logs'] = json.load(f)

    # 피해자 목록 불러오기
    if os.path.exists(VICTIMS_FILE):
        with open(VICTIMS_FILE, 'r', encoding='utf-8') as f:
            attack_data['victim_list'] = json.load(f)

    # 통계 계산
    attack_data['total_points'] = sum(v.get('points', 0) for v in attack_data['victim_list'])
    attack_data['victims'] = len(attack_data['victim_list'])
    attack_data['total_attempts'] = len(
        [log for log in attack_data['logs'] if log.get('type') in ['attempt', 'success']])


def save_logs():
    """로그 저장하기"""
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(attack_data['logs'][-100:], f, ensure_ascii=False, indent=2)


def save_victims():
    """피해자 목록 저장하기"""
    with open(VICTIMS_FILE, 'w', encoding='utf-8') as f:
        json.dump(attack_data['victim_list'], f, ensure_ascii=False, indent=2)


@app.route('/')
def dashboard():
    load_data()
    from flask import make_response
    response = make_response(render_template('dashboard.html'))
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response


@app.route('/api/stats')
def get_stats():
    """통계 데이터 API"""
    load_data()
    return jsonify({
        'total_points': attack_data['total_points'],
        'victims': attack_data['victims'],
        'total_attempts': attack_data['total_attempts']
    })


@app.route('/api/logs')
def get_logs():
    """로그 데이터 API"""
    load_data()
    return jsonify(attack_data['logs'][-20:])  # 최근 20개


@app.route('/api/victims')
def get_victims():
    """피해자 목록 API"""
    load_data()
    # 최신순으로 정렬
    sorted_victims = sorted(attack_data['victim_list'],
                            key=lambda x: x.get('last_attack', ''),
                            reverse=True)
    return jsonify(sorted_victims)


@app.route('/api/attack_log', methods=['POST'])
def log_attack():
    """실제 공격 로그 기록 (블루팀 서버 연동용)"""
    data = request.json

    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'type': data.get('type', 'attempt'),  # attempt, success, victim, info
        'status': data.get('status', ''),
        'ip': data.get('ip', 'unknown'),
        'details': data.get('details', ''),
        'user_agent': data.get('user_agent', ''),
        'points': data.get('points', 0)
    }

    attack_data['logs'].append(log_entry)
    save_logs()

    # 성공한 공격인 경우 피해자 목록 업데이트
    if data.get('type') == 'success' and data.get('points', 0) > 0:
        ip = data.get('ip', 'unknown')
        user_agent = data.get('user_agent', 'unknown')
        points = data.get('points', 0)

        # 기존 피해자 찾기
        victim = None
        for v in attack_data['victim_list']:
            if v['ip'] == ip:
                victim = v
                break

        if victim:
            # 기존 피해자 업데이트
            victim['points'] += points
            victim['last_attack'] = log_entry['timestamp']
        else:
            # 새 피해자 추가
            new_victim = {
                'ip': ip,
                'user_agent': user_agent,
                'points': points,
                'last_attack': log_entry['timestamp']
            }
            attack_data['victim_list'].append(new_victim)

        save_victims()

    print(f"[LOG] {log_entry['type'].upper()}: {log_entry['status']} from {log_entry['ip']}")
    return jsonify({'status': 'logged', 'message': 'Attack logged successfully'})


@app.route('/api/reset', methods=['POST'])
def reset_data():
    """데이터 초기화 (선택사항)"""
    global attack_data

    # 파일들 삭제
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    if os.path.exists(VICTIMS_FILE):
        os.remove(VICTIMS_FILE)

    # 메모리 데이터 초기화
    attack_data = {
        'total_points': 0,
        'victims': 0,
        'total_attempts': 0,
        'logs': [],
        'victim_list': []
    }

    print("[RESET] All attack data has been reset!")
    return jsonify({'status': 'reset', 'message': 'All data cleared'})


# 테스트 라우트
@app.route('/test')
def test():
    from flask import make_response
    response = make_response(render_template('test.html'))
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response


if __name__ == '__main__':
    print("🚀 CSRF Attack Dashboard starting...")
    print("📊 Dashboard: http://localhost:8080")
    print("🔄 API Endpoint: http://localhost:8080/api/attack_log")
    print("💾 Data will be saved to: csrf_attacks.json, victims.json")
    print("🔥 Ready for real attacks!")

    app.run(host='0.0.0.0', port=8080, debug=True)