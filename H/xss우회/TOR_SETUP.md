# Tor Control Port 설정 (macOS)

## 문제
```
⚠ Tor 제어 실패: [Errno 54] Connection reset by peer
```

## 해결 방법

### 1. Tor 설정 파일 찾기
```bash
# Homebrew로 설치한 경우
ls /usr/local/etc/tor/torrc

# 또는
ls /opt/homebrew/etc/tor/torrc
```

### 2. Tor 설정 파일 편집
```bash
# Homebrew 경로 (Intel Mac)
sudo nano /usr/local/etc/tor/torrc

# 또는 (M1/M2 Mac)
sudo nano /opt/homebrew/etc/tor/torrc
```

### 3. 다음 내용 추가
```
ControlPort 9051
CookieAuthentication 0
```

**설명:**
- `ControlPort 9051`: Control Port 활성화
- `CookieAuthentication 0`: 비밀번호 없이 로컬 접속 허용

### 4. Tor 재시작
```bash
# Homebrew 서비스로 실행 중인 경우
brew services restart tor

# 또는 수동 실행
killall tor
tor
```

### 5. Control Port 테스트
```bash
nc 127.0.0.1 9051
# 연결되면 입력:
AUTHENTICATE
# 응답: 250 OK
SIGNAL NEWNYM
# 응답: 250 OK
QUIT
```

---

## 해결 방법 2: IP 변경 없이 Tor만 사용

Control Port 설정이 번거로우면 IP 변경 기능을 비활성화하고 Tor 프록시만 사용:

```bash
python3 stealthy_xss_attack.py --delay 10 --no-ip-rotation
```

(스크립트 수정 필요)
