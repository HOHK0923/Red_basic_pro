# CSRF 공격자 서버 설치 및 실행 가이드

## 🚀 빠른 시작 (Ubuntu 서버에서)

### 1. 파일 업로드
```bash
# 로컬에서 서버로 파일 전송
scp attacker_server.py ubuntu@13.158.67.78:~/
scp start_server.sh ubuntu@13.158.67.78:~/
scp stop_server.sh ubuntu@13.158.67.78:~/

# 또는 한번에
scp attacker_server.py start_server.sh stop_server.sh ubuntu@13.158.67.78:~/
```

### 2. 서버 접속 및 설치
```bash
# 서버 접속
ssh ubuntu@13.158.67.78

# Flask 설치
pip3 install flask

# 또는
sudo apt update
sudo apt install python3-pip
pip3 install flask
```

### 3. 서버 시작
```bash
# 방법 1: 스크립트 사용 (권장)
chmod +x start_server.sh
./start_server.sh

# 방법 2: 직접 실행
nohup python3 attacker_server.py > server.log 2>&1 &

# 방법 3: screen 사용
screen -S csrf
python3 attacker_server.py
# Ctrl+A, D로 detach
```

### 4. 확인
```bash
# 프로세스 확인
ps aux | grep attacker_server

# 로그 확인
tail -f server.log

# 포트 확인
netstat -tulpn | grep 5000

# 웹 접속 확인
curl http://localhost:5000/
```

### 5. 브라우저에서 접속
```
http://13.158.67.78:5000/          # 대시보드
http://13.158.67.78:5000/fake-gift # fake-gift 페이지
http://13.158.67.78:5000/logs      # JSON 로그
```

### 6. 서버 종료
```bash
# 방법 1: 스크립트 사용
./stop_server.sh

# 방법 2: 직접 종료
pkill -f attacker_server.py

# 방법 3: PID로 종료
ps aux | grep attacker_server
kill <PID>
```

---

## 🔧 문제 해결

### Flask 설치 오류
```bash
# pip 업그레이드
pip3 install --upgrade pip

# 재설치
pip3 install --force-reinstall flask
```

### 포트 5000 이미 사용 중
```bash
# 포트 사용 확인
sudo lsof -i :5000

# 프로세스 종료
sudo kill -9 <PID>

# 또는 다른 포트 사용 (attacker_server.py 수정)
# 마지막 줄: app.run(host='0.0.0.0', port=8080, debug=True)
```

### 방화벽 설정 (AWS EC2)
```bash
# 보안 그룹에서 5000 포트 열기
# AWS Console → EC2 → Security Groups
# Inbound Rules → Add Rule
# Type: Custom TCP
# Port: 5000
# Source: 0.0.0.0/0
```

### 외부 접속 안됨
```bash
# 서버가 0.0.0.0으로 바인딩되었는지 확인
netstat -tulpn | grep 5000
# 결과: 0.0.0.0:5000 이어야 함

# 방화벽 확인
sudo ufw status
sudo ufw allow 5000/tcp
```

---

## 📊 사용 예제

### 테스트 시나리오

#### 1. 공격자 서버 시작
```bash
ssh ubuntu@13.158.67.78
./start_server.sh
```

#### 2. 대시보드 확인
브라우저에서 `http://13.158.67.78:5000/` 열기

#### 3. 피해자 역할 (로컬 브라우저)
```
1. http://52.78.221.104/login.php
   admin / admin123 로그인

2. 같은 브라우저의 새 탭에서
   http://13.158.67.78:5000/fake-gift 열기

3. 대시보드로 돌아가서 확인:
   - 💰 탈취한 포인트 증가
   - 👥 피해자 수 증가
   - 📋 실시간 로그 확인
```

#### 4. alice 계정 확인
```
http://52.78.221.104/login.php
alice / alice2024
→ 포인트 증가 확인!
```

---

## 🎯 자동화 (auto.py 연동)

### auto.py에서 게시물 작성 시 자동으로 fake-gift URL 생성

게시물 내용:
```
🎁 특별 이벤트! 무료 10,000 포인트 받기!
http://13.158.67.78:5000/fake-gift
선착순 100명! 서두르세요!
```

피해자가 링크 클릭 → 대시보드에서 실시간 확인!

---

## 🔐 보안 참고사항

### 본 서버는 교육 목적으로만 사용하세요!

- ✅ 학습 환경에서만 사용
- ✅ 승인된 테스트 환경에서만 실행
- ❌ 실제 운영 서버에 사용 금지
- ❌ 무단 공격 금지

### 사용 후 반드시 종료
```bash
./stop_server.sh
```

---

## 📝 systemd 서비스로 등록 (선택사항)

영구적으로 실행하려면:

```bash
sudo nano /etc/systemd/system/csrf-server.service
```

```ini
[Unit]
Description=CSRF Attack Server
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu
ExecStart=/usr/bin/python3 /home/ubuntu/attacker_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# 서비스 등록 및 시작
sudo systemctl daemon-reload
sudo systemctl enable csrf-server
sudo systemctl start csrf-server

# 상태 확인
sudo systemctl status csrf-server

# 로그 확인
sudo journalctl -u csrf-server -f

# 종료
sudo systemctl stop csrf-server
```

---

## 📞 문제 발생 시

로그 확인:
```bash
tail -f server.log
cat server.log | grep ERROR
```

디버그 모드:
```python
# attacker_server.py 마지막 줄
app.run(host='0.0.0.0', port=5000, debug=True)
```

수동 테스트:
```bash
# 서버가 응답하는지 확인
curl http://localhost:5000/
curl http://localhost:5000/logs
```
