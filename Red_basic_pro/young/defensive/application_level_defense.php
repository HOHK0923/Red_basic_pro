<?php

// CSRF 토큰 구현
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// SQL Injection 방어 - Prepared Statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, hash('sha256', $password)]);

// File Upload 방어
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$file_ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($file_ext, $allowed_extensions)) {
    die("Invalid file type");
}

// LFI 방어
$filename = basename($_GET['name']); // 디렉토리 트래버설 방지
$allowed_files = ['profile.jpg', 'banner.png'];
if (!in_array($filename, $allowed_files)) {
    die("File not found");
}

?>