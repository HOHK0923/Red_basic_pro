# 공격 흔적 제거 가이드

## 📋 목차
1. [데이터베이스 정리](#데이터베이스-정리)
2. [파일 시스템 정리](#파일-시스템-정리)
3. [로그 정리](#로그-정리)
4. [완전 초기화](#완전-초기화)

---

## 데이터베이스 정리

### 리버스 쉘에서 MySQL 접속
```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns
```

### 1. 게시물(posts) 삭제

#### 모든 게시물 확인
```sql
SELECT id, user_id, LEFT(content, 50) as preview, created_at
FROM posts
ORDER BY id DESC;
```

#### 특정 게시물 삭제 (ID로)
```sql
DELETE FROM posts WHERE id = 123;
```

#### XSS/CSRF 악성 게시물 삭제
```sql
-- script 태그 포함 게시물
DELETE FROM posts WHERE content LIKE '%<script%';

-- iframe 포함 게시물
DELETE FROM posts WHERE content LIKE '%<iframe%';

-- svg 포함 게시물
DELETE FROM posts WHERE content LIKE '%<svg%';

-- img onerror 포함
DELETE FROM posts WHERE content LIKE '%onerror%';

-- 특정 문자열 포함 (예: fake-gift)
DELETE FROM posts WHERE content LIKE '%fake-gift%';
DELETE FROM posts WHERE content LIKE '%🎁%';
```

#### admin이 작성한 모든 게시물 삭제
```sql
DELETE FROM posts WHERE user_id = 1;
```

#### 특정 날짜 이후 게시물 삭제
```sql
DELETE FROM posts WHERE created_at >= '2025-11-10 00:00:00';
```

#### 모든 게시물 삭제 (위험!)
```sql
TRUNCATE TABLE posts;
```

### 2. 댓글(comments) 삭제

#### 모든 댓글 확인
```sql
SELECT id, post_id, user_id, LEFT(content, 50) as preview
FROM comments
ORDER BY id DESC;
```

#### 악성 댓글 삭제
```sql
DELETE FROM comments WHERE content LIKE '%<script%';
DELETE FROM comments WHERE content LIKE '%onerror%';
```

#### 모든 댓글 삭제
```sql
TRUNCATE TABLE comments;
```

### 3. 선물 기록(gifts) 삭제

#### 선물 내역 확인
```sql
SELECT id, sender_id, receiver_id, gift_type, points, created_at
FROM gifts
ORDER BY id DESC
LIMIT 20;
```

#### receiver_id=999 (유령 계정) 선물 삭제
```sql
DELETE FROM gifts WHERE receiver_id = 999;
```

#### 특정 날짜 이후 선물 삭제
```sql
DELETE FROM gifts WHERE created_at >= '2025-11-10 00:00:00';
```

#### 모든 선물 기록 삭제
```sql
TRUNCATE TABLE gifts;
```

### 4. 포인트 복구

#### 현재 포인트 확인
```sql
SELECT id, username, points FROM users;
```

#### admin 포인트 복구
```sql
UPDATE users SET points = 1000000 WHERE username = 'admin';
```

#### alice 포인트 복구
```sql
UPDATE users SET points = 500 WHERE username = 'alice';
```

#### bob 포인트 복구
```sql
UPDATE users SET points = 300 WHERE username = 'bob';
```

#### 모든 사용자 포인트 초기화
```sql
UPDATE users SET points = 1000;
```

### 5. 세션 무효화

#### 활성 세션 확인 (PHP 세션 파일)
```bash
ls -la /var/lib/php/sessions/
```

#### 모든 세션 삭제
```bash
rm -f /var/lib/php/sessions/sess_*
```

---

## 파일 시스템 정리

### 1. 업로드된 파일 확인

```bash
# 업로드 디렉토리 확인
ls -la /var/www/html/uploads/

# 파일 타입별 확인
file /var/www/html/uploads/*

# 최근 업로드된 파일 (24시간 이내)
find /var/www/html/uploads/ -type f -mtime -1
```

### 2. 웹쉘 삭제

```bash
# shell.jpg 찾기
find /var/www/html -name "shell.jpg" -type f

# 웹쉘 삭제
rm -f /var/www/html/uploads/shell.jpg
rm -f /var/www/html/file.php

# PHP 파일 전체 검색 (의심스러운 파일)
find /var/www/html -name "*.php" -type f | grep -v "index\|login\|profile\|new_post"

# 최근 수정된 PHP 파일
find /var/www/html -name "*.php" -type f -mtime -1
```

### 3. 악성 파일 패턴 검색

```bash
# eval, system, exec 포함 파일
grep -r "eval(" /var/www/html/ 2>/dev/null
grep -r "system(" /var/www/html/ 2>/dev/null
grep -r "exec(" /var/www/html/ 2>/dev/null
grep -r "shell_exec" /var/www/html/ 2>/dev/null
grep -r "passthru" /var/www/html/ 2>/dev/null

# base64_decode 사용 파일 (난독화된 웹쉘)
grep -r "base64_decode" /var/www/html/ 2>/dev/null
```

### 4. 업로드 디렉토리 완전 정리

```bash
# 모든 업로드 파일 삭제 (주의!)
rm -rf /var/www/html/uploads/*

# jpg, png 외 모든 파일 삭제
find /var/www/html/uploads/ -type f ! -name "*.jpg" ! -name "*.png" -delete
```

### 5. 임시 파일 정리

```bash
# /tmp에 생성한 파일들
rm -f /tmp/fake-gift.html
rm -f /tmp/*.php
rm -f /tmp/*.sh

# /var/tmp 정리
rm -f /var/tmp/*.php
```

---

## 로그 정리

### 1. 웹 서버 로그

#### Apache 로그 확인
```bash
# 접근 로그
tail -100 /var/log/apache2/access.log

# 에러 로그
tail -100 /var/log/apache2/error.log

# 특정 IP 필터링
grep "공격자IP" /var/log/apache2/access.log
```

#### 로그에서 웹쉘 접근 제거
```bash
# file.php 접근 기록 제거
sed -i '/file\.php/d' /var/log/apache2/access.log

# shell.jpg 접근 기록 제거
sed -i '/shell\.jpg/d' /var/log/apache2/access.log

# 특정 IP 제거
sed -i '/공격자IP/d' /var/log/apache2/access.log
```

#### 로그 완전 삭제 (위험!)
```bash
> /var/log/apache2/access.log
> /var/log/apache2/error.log
```

### 2. 시스템 로그

#### auth.log (SSH 접속 기록)
```bash
# SSH 접속 확인
grep "Accepted" /var/log/auth.log

# 특정 사용자 접속 기록 제거
sed -i '/ubuntu/d' /var/log/auth.log
```

#### syslog
```bash
# 최근 로그 확인
tail -100 /var/log/syslog

# 로그 정리
> /var/log/syslog
```

### 3. MySQL 로그

```bash
# 쿼리 로그 확인
tail -100 /var/log/mysql/mysql.log

# 로그 정리
> /var/log/mysql/mysql.log
```

### 4. Bash 히스토리

```bash
# 현재 세션 히스토리 확인
history

# 히스토리 삭제
history -c

# .bash_history 파일 삭제
rm -f ~/.bash_history

# 현재 세션 종료 시 히스토리 저장 안 함
unset HISTFILE
```

---

## 완전 초기화

### 원스텝 정리 스크립트

리버스 쉘에서 실행:

```bash
#!/bin/bash
echo "[*] 공격 흔적 제거 시작..."

# 1. 데이터베이스 정리
echo "[*] 데이터베이스 정리..."
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << EOF
DELETE FROM posts WHERE content LIKE '%<script%';
DELETE FROM posts WHERE content LIKE '%<iframe%';
DELETE FROM posts WHERE content LIKE '%<svg%';
DELETE FROM posts WHERE content LIKE '%onerror%';
DELETE FROM posts WHERE content LIKE '%🎁%';
DELETE FROM gifts WHERE receiver_id = 999;
DELETE FROM gifts WHERE created_at >= '2025-11-10 00:00:00';
UPDATE users SET points = 1000000 WHERE username = 'admin';
UPDATE users SET points = 500 WHERE username = 'alice';
UPDATE users SET points = 300 WHERE username = 'bob';
EOF

# 2. 웹쉘 삭제
echo "[*] 웹쉘 삭제..."
rm -f /var/www/html/uploads/shell.jpg
rm -f /var/www/html/file.php
rm -f /var/www/html/uploads/fake-gift.*

# 3. 임시 파일 삭제
echo "[*] 임시 파일 삭제..."
rm -f /tmp/*.php
rm -f /tmp/*.html
rm -f /tmp/*.sh

# 4. 세션 삭제
echo "[*] 세션 삭제..."
rm -f /var/lib/php/sessions/sess_*

# 5. 로그 정리
echo "[*] 로그 정리..."
sed -i '/shell\.jpg/d' /var/log/apache2/access.log 2>/dev/null
sed -i '/file\.php/d' /var/log/apache2/access.log 2>/dev/null

# 6. Bash 히스토리 삭제
echo "[*] Bash 히스토리 삭제..."
history -c
rm -f ~/.bash_history

echo "[+] 완료!"
```

### 데이터베이스만 빠르게 정리

```bash
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'EOF'
-- 악성 게시물 삭제
DELETE FROM posts WHERE content LIKE '%<script%' OR content LIKE '%<iframe%' OR content LIKE '%<svg%' OR content LIKE '%onerror%' OR content LIKE '%🎁%';

-- 유령 계정 선물 삭제
DELETE FROM gifts WHERE receiver_id = 999;

-- 포인트 복구
UPDATE users SET points = 1000000 WHERE username = 'admin';
UPDATE users SET points = 500 WHERE username = 'alice';
UPDATE users SET points = 300 WHERE username = 'bob';

-- 확인
SELECT username, points FROM users;
SELECT COUNT(*) as post_count FROM posts;
SELECT COUNT(*) as gift_count FROM gifts WHERE receiver_id = 999;
EOF
```

---

## 빠른 참조

### 가장 많이 사용하는 명령어

```bash
# 1. 데이터베이스 악성 게시물 삭제
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "DELETE FROM posts WHERE content LIKE '%<script%' OR content LIKE '%🎁%';"

# 2. 웹쉘 삭제
rm -f /var/www/html/uploads/shell.jpg /var/www/html/file.php

# 3. 포인트 복구
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "UPDATE users SET points = 1000000 WHERE username = 'admin';"

# 4. 유령 계정 선물 삭제
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e "DELETE FROM gifts WHERE receiver_id = 999;"

# 5. 히스토리 삭제
history -c && rm -f ~/.bash_history

# 6. 세션 삭제
rm -f /var/lib/php/sessions/sess_*
```

---

## 주의사항

⚠️ **경고**:
- `TRUNCATE TABLE` 명령은 모든 데이터를 삭제합니다
- 로그 삭제는 의심을 불러일으킬 수 있습니다
- 백업 없이 삭제하면 복구 불가능합니다

✅ **권장사항**:
- 삭제 전 항상 데이터 확인
- 중요 데이터는 백업 후 삭제
- 선택적 삭제가 완전 삭제보다 안전
- 로그는 특정 항목만 제거

---

## 테스트 환경 완전 초기화

모든 것을 처음 상태로 되돌리기:

```bash
# 데이터베이스 초기화
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'EOF'
TRUNCATE TABLE posts;
TRUNCATE TABLE comments;
TRUNCATE TABLE gifts;
UPDATE users SET points = 1000 WHERE id > 1;
UPDATE users SET points = 1000000 WHERE id = 1;
DELETE FROM users WHERE id > 3;
EOF

# 업로드 파일 전체 삭제
rm -rf /var/www/html/uploads/*

# 로그 초기화
> /var/log/apache2/access.log
> /var/log/apache2/error.log

# 세션 삭제
rm -f /var/lib/php/sessions/sess_*

# 히스토리 삭제
history -c
rm -f ~/.bash_history
```
