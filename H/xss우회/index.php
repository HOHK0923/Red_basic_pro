<?php
// index.php - 메인 피드 (XSS 취약)
include 'config.php';
requireLogin();

$user = getCurrentUser();
$db = getConnection();

// 게시물 조회
$posts_query = "SELECT p.*, u.username, u.full_name, u.profile_image
                FROM posts p
                JOIN users u ON p.user_id = u.id
                ORDER BY p.created_at DESC
                LIMIT 50";
$posts_stmt = $db->query($posts_query);
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>홈 - Vulnerable SNS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Crimson+Pro:wght@200;300;400;600;700;900&family=IBM+Plex+Mono:wght@300;400;500;600;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --dark-bg: #0a0e27;
            --dark-card: #111632;
            --dark-border: #1e293b;
            --dark-hover: #1a1f3a;

            --purple-500: #a855f7;
            --purple-600: #9333ea;
            --purple-700: #7e22ce;

            --emerald-500: #10b981;
            --emerald-600: #059669;

            --slate-50: #f8fafc;
            --slate-100: #f1f5f9;
            --slate-200: #e2e8f0;
            --slate-300: #cbd5e1;
            --slate-400: #94a3b8;
            --slate-500: #64748b;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Space Grotesk', sans-serif;
            background: var(--dark-bg);
            color: var(--slate-200);
            min-height: 100vh;
        }

        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background:
                radial-gradient(circle at 15% 20%, rgba(168, 85, 247, 0.08), transparent 40%),
                radial-gradient(circle at 85% 80%, rgba(16, 185, 129, 0.06), transparent 40%),
                repeating-linear-gradient(90deg, transparent 0, transparent 79px, rgba(30, 41, 59, 0.3) 79px, rgba(30, 41, 59, 0.3) 81px),
                repeating-linear-gradient(0deg, transparent 0, transparent 79px, rgba(30, 41, 59, 0.3) 79px, rgba(30, 41, 59, 0.3) 81px);
            opacity: 0.6;
            z-index: 0;
            pointer-events: none;
        }

        .navbar {
            position: sticky;
            top: 0;
            z-index: 100;
            background: rgba(17, 22, 50, 0.9);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--dark-border);
            padding: 16px 0;
        }

        .nav-content {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .nav-brand {
            display: flex;
            align-items: center;
            gap: 16px;
            text-decoration: none;
        }

        .nav-brand i {
            font-size: 28px;
            color: var(--purple-500);
        }

        .nav-brand h1 {
            font-family: 'Crimson Pro', serif;
            font-size: 28px;
            font-weight: 900;
            color: var(--slate-100);
        }

        .nav-links {
            display: flex;
            gap: 20px;
            align-items: center;
            font-size: 14px;
        }

        .nav-links a {
            color: var(--slate-300);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .nav-links a:hover {
            color: var(--purple-500);
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .user-info span {
            font-weight: 600;
            color: var(--slate-100);
            font-size: 14px;
        }

        .points-badge {
            background: linear-gradient(135deg, var(--purple-500), var(--purple-600));
            color: white;
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 700;
        }

        .stories-container {
            position: relative;
            z-index: 1;
            max-width: 800px;
            margin: 24px auto 0;
            padding: 0 32px;
        }

        .stories-wrapper {
            background: var(--dark-card);
            border: 1px solid var(--dark-border);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 24px;
            overflow-x: auto;
            backdrop-filter: blur(10px);
        }

        .stories-wrapper::-webkit-scrollbar {
            height: 6px;
        }

        .stories-wrapper::-webkit-scrollbar-track {
            background: var(--slate-900);
            border-radius: 3px;
        }

        .stories-wrapper::-webkit-scrollbar-thumb {
            background: var(--slate-700);
            border-radius: 3px;
        }

        .stories {
            display: flex;
            gap: 20px;
        }

        .story {
            flex-shrink: 0;
            text-align: center;
            cursor: pointer;
        }

        .story-avatar {
            width: 70px;
            height: 70px;
            border-radius: 50%;
            padding: 3px;
            background: linear-gradient(135deg, var(--purple-500), var(--purple-600));
            margin-bottom: 8px;
            transition: transform 0.2s;
        }

        .story:hover .story-avatar {
            transform: scale(1.05);
        }

        .story-avatar-inner {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: var(--dark-card);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--purple-500);
            font-weight: 700;
            font-size: 24px;
            border: 3px solid var(--dark-bg);
        }

        .story-username {
            font-size: 12px;
            color: var(--slate-300);
            max-width: 70px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .container {
            position: relative;
            z-index: 1;
            max-width: 800px;
            margin: 0 auto 40px;
            padding: 0 32px;
        }

        .post-card {
            background: var(--dark-card);
            border: 1px solid var(--dark-border);
            border-radius: 20px;
            margin-bottom: 24px;
            backdrop-filter: blur(10px);
            transition: all 0.3s;
        }

        .post-card:hover {
            border-color: var(--purple-500);
            transform: translateY(-2px);
        }

        .post-header {
            padding: 20px 24px;
            display: flex;
            align-items: center;
            gap: 14px;
            border-bottom: 1px solid var(--dark-border);
        }

        .post-avatar {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            padding: 2px;
            background: linear-gradient(135deg, var(--purple-500), var(--purple-600));
        }

        .post-avatar-inner {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: var(--dark-bg);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--purple-500);
            font-weight: 700;
            font-size: 18px;
            border: 2px solid var(--dark-card);
        }

        .post-info {
            flex: 1;
        }

        .post-author {
            font-weight: 600;
            color: var(--slate-100);
            font-size: 15px;
            margin-bottom: 2px;
        }

        .post-time {
            font-size: 13px;
            color: var(--slate-400);
            font-family: 'IBM Plex Mono', monospace;
        }

        .post-content {
            padding: 20px 24px;
            color: var(--slate-200);
            line-height: 1.7;
            font-size: 15px;
        }

        .post-image {
            width: 100%;
            max-height: 500px;
            object-fit: cover;
            display: block;
        }

        .post-actions {
            padding: 16px 24px;
            display: flex;
            gap: 20px;
            align-items: center;
            border-top: 1px solid var(--dark-border);
        }

        .post-actions button {
            background: none;
            border: none;
            color: var(--slate-300);
            font-size: 22px;
            cursor: pointer;
            transition: all 0.2s;
            padding: 8px;
        }

        .post-actions button:hover {
            color: var(--purple-500);
            transform: scale(1.1);
        }

        .post-actions button.liked {
            color: #ef4444;
            animation: likeAnimation 0.4s ease;
        }

        @keyframes likeAnimation {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.3); }
        }

        .post-likes {
            padding: 0 24px 16px;
            font-weight: 600;
            color: var(--slate-300);
            font-size: 14px;
        }

        .post-likes i {
            color: #ef4444;
            margin-right: 6px;
        }

        .post-comments {
            padding: 16px 24px;
            border-top: 1px solid var(--dark-border);
        }

        .comment {
            margin-bottom: 12px;
            font-size: 14px;
            line-height: 1.6;
        }

        .comment-author {
            font-weight: 600;
            color: var(--purple-500);
            margin-right: 8px;
        }

        .comment-content {
            color: var(--slate-300);
        }

        .comment-form {
            display: flex;
            gap: 12px;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid var(--dark-border);
        }

        .comment-form input {
            flex: 1;
            background: var(--dark-bg);
            border: 1px solid var(--dark-border);
            border-radius: 10px;
            padding: 12px 16px;
            color: var(--slate-100);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 14px;
        }

        .comment-form input:focus {
            outline: none;
            border-color: var(--purple-500);
        }

        .comment-form input::placeholder {
            color: var(--slate-500);
        }

        .comment-form button {
            background: linear-gradient(135deg, var(--purple-500), var(--purple-600));
            color: white;
            border: none;
            border-radius: 10px;
            padding: 12px 20px;
            font-weight: 700;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
        }

        .comment-form button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(168, 85, 247, 0.4);
        }

        .new-post-btn {
            position: fixed;
            bottom: 32px;
            right: 32px;
            width: 64px;
            height: 64px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--purple-500), var(--purple-600));
            color: white;
            border: none;
            font-size: 26px;
            cursor: pointer;
            box-shadow: 0 8px 24px rgba(168, 85, 247, 0.4);
            transition: all 0.3s;
            z-index: 999;
        }

        .new-post-btn:hover {
            transform: scale(1.1) rotate(90deg);
            box-shadow: 0 12px 32px rgba(168, 85, 247, 0.5);
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .post-card {
            animation: fadeIn 0.4s ease;
        }
    </style>
</head>
<body>
    <!--
        TODO: 프로덕션 배포 전에 제거할 것:
        - /debug.php (RCE 위험!)
        - /admin.php (SQL Injection 취약)
        - /logs.php (LFI 가능)
        - /api_docs.php (API 문서 노출)

        개발 서버 접속: dev.vulnerable-sns.local
        관리자 패널: /admin.php?debug=1
        API 엔드포인트: /api.php
    -->
    <nav class="navbar">
        <div class="nav-content">
            <a href="index.php" class="nav-brand">
                <i class="fas fa-shield-alt"></i>
                <h1>VulnerableSNS</h1>
            </a>
            <div class="nav-links">
                <a href="index.php"><i class="fas fa-home"></i> Feed</a>
                <a href="profile.php"><i class="fas fa-user"></i> Profile</a>
                <a href="upload.php"><i class="fas fa-cloud-upload-alt"></i> Upload</a>
                <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </div>
            <div class="user-info">
                <span><?php echo htmlspecialchars($user['username']); ?></span>
                <span class="points-badge"><?php echo $user['points']; ?> P</span>
            </div>
        </div>
    </nav>

    <!-- Stories Section -->
    <div class="stories-container">
        <div class="stories-wrapper">
            <div class="stories">
                <?php
                $stories_query = "SELECT DISTINCT u.id, u.username
                                 FROM users u
                                 JOIN posts p ON u.id = p.user_id
                                 ORDER BY RANDOM()
                                 LIMIT 10";
                $stories_stmt = $db->query($stories_query);
                while ($story_user = $stories_stmt->fetch(PDO::FETCH_ASSOC)):
                ?>
                <div class="story">
                    <div class="story-avatar">
                        <div class="story-avatar-inner">
                            <?php echo strtoupper(substr($story_user['username'], 0, 1)); ?>
                        </div>
                    </div>
                    <div class="story-username"><?php echo htmlspecialchars($story_user['username']); ?></div>
                </div>
                <?php endwhile; ?>
            </div>
        </div>
    </div>

    <div class="container">
        <?php while ($post = $posts_stmt->fetch(PDO::FETCH_ASSOC)): ?>
        <div class="post-card">
            <div class="post-header">
                <div class="post-avatar">
                    <div class="post-avatar-inner">
                        <?php echo strtoupper(substr($post['username'], 0, 1)); ?>
                    </div>
                </div>
                <div class="post-info">
                    <div class="post-author"><?php echo htmlspecialchars($post['username']); ?></div>
                    <div class="post-time"><?php echo date('Y-m-d H:i', strtotime($post['created_at'])); ?></div>
                </div>
            </div>

            <?php if ($post['image']): ?>
            <img src="<?php echo htmlspecialchars($post['image']); ?>" class="post-image" alt="Post image">
            <?php endif; ?>

            <div class="post-content">
                <!-- 취약점: XSS - htmlspecialchars 미사용 -->
                <?php echo $post['content']; ?>
            </div>

            <div class="post-likes">
                <i class="fas fa-heart" style="color: #ed4956;"></i>
                <?php echo $post['likes']; ?>명이 좋아합니다
            </div>

            <div class="post-actions">
                <button onclick="likePost(<?php echo $post['id']; ?>)">
                    <i class="far fa-heart"></i>
                </button>
                <button onclick="toggleComments(<?php echo $post['id']; ?>)">
                    <i class="far fa-comment"></i>
                </button>
                <a href="profile.php?gift_to=<?php echo $post['user_id']; ?>" style="text-decoration: none;">
                    <button>
                        <i class="fas fa-gift"></i>
                    </button>
                </a>
            </div>

            <div class="post-comments" id="comments-<?php echo $post['id']; ?>" style="display: none;">
                <?php
                $post_id = $post['id'];
                $comments_query = "SELECT c.*, u.username FROM comments c
                                   JOIN users u ON c.user_id = u.id
                                   WHERE c.post_id = ?
                                   ORDER BY c.created_at ASC";
                $comments_stmt = $db->prepare($comments_query);
                $comments_stmt->execute([$post_id]);

                while ($comment = $comments_stmt->fetch(PDO::FETCH_ASSOC)):
                ?>
                <div class="comment">
                    <span class="comment-author"><?php echo htmlspecialchars($comment['username']); ?></span>
                    <!-- 취약점: XSS - 댓글에도 필터링 없음 -->
                    <span class="comment-content"><?php echo $comment['content']; ?></span>
                </div>
                <?php endwhile; ?>

                <form method="POST" action="add_comment.php" class="comment-form">
                    <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                    <input type="text" name="content" placeholder="댓글 달기..." required>
                    <button type="submit">게시</button>
                </form>
            </div>
        </div>
        <?php endwhile; ?>
    </div>

    <a href="new_post.php">
        <button class="new-post-btn">
            <i class="fas fa-plus"></i>
        </button>
    </a>

    <script>
        function likePost(postId) {
            fetch('like_post.php?id=' + postId)
                .then(() => location.reload());
        }

        function toggleComments(postId) {
            const comments = document.getElementById('comments-' + postId);
            comments.style.display = comments.style.display === 'none' ? 'block' : 'none';
        }
    </script>
</body>
</html>
