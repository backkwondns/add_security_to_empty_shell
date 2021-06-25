# add_security_to_empty_shell
2020/12

github에 존재하는 아무기능이 없는 lsh을 가져와서 작업함.

1. lsh를 실행하면 ip 화이트 리스트 기반으로 1차로 차단
2. 이미 접속된 lsh 프로세스가 설정된 수 만큼 있으면(이미 여러명이 접속) 2차로 차단
   #define MAX_LOGIN 1 <= 최대 접속가능한 프로세스 1개(1명)
3. 마지막으로 ID, PW 인증을 통한 로그인

1, 2, 3 과정에서 접속 실패가 되면 failed_log에 저장

모든 과정을 거쳐 최종 로그인이 될 경우 login_log에 저장

