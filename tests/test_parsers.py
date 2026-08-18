from app.parsers.registry import parse_raw_message


def test_auth_log_failed_password():
    line = "Jul 10 10:00:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
    event = parse_raw_message(line, source_type="AUTH_LOG")
    assert event is not None
    assert event.event_type == "AUTH_FAILURE"
    assert event.src_ip == "203.0.113.5"
    assert event.username == "admin"


def test_auth_log_accepted_password():
    line = "Jul 10 10:00:07 web01 sshd[1238]: Accepted password for root from 203.0.113.5 port 51521 ssh2"
    event = parse_raw_message(line, source_type="AUTH_LOG")
    assert event.event_type == "AUTH_SUCCESS"
    assert event.username == "root"


def test_auth_log_sudo_is_privilege_change():
    line = "Jul 10 10:00:10 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/su"
    event = parse_raw_message(line, source_type="AUTH_LOG")
    assert event.event_type == "PRIVILEGE_CHANGE"
    assert event.username == "alice"


def test_auth_log_useradd_is_account_created():
    line = "Jul 10 10:01:00 web01 useradd[1250]: new user: name=bob, UID=1002, GID=1002, home=/home/bob, shell=/bin/bash"
    event = parse_raw_message(line, source_type="AUTH_LOG")
    assert event.event_type == "ACCOUNT_CREATED"
    assert event.username == "bob"


def test_auth_log_malformed_returns_none():
    assert parse_raw_message("not a log line at all", source_type="AUTH_LOG") is None


def test_syslog_rfc3164_auto_detect():
    line = "<34>Oct 11 22:14:15 mymachine sshd: Failed password for invalid user oracle from 198.51.100.23 port 4321 ssh2"
    event = parse_raw_message(line)
    assert event.event_type == "AUTH_FAILURE"
    assert event.hostname == "mymachine"
    assert event.src_ip == "198.51.100.23"


def test_syslog_rfc3164_service_stop():
    line = "<29>Oct 11 22:16:00 mymachine systemd: rsyslog.service: Stopped System Logging Service."
    event = parse_raw_message(line)
    assert event.event_type == "SERVICE_STOP"


def test_syslog_rfc5424_auto_detect():
    line = (
        '<165>1 2023-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 '
        '[exampleSDID@32473 iut="3"] Failed password attempt'
    )
    event = parse_raw_message(line)
    assert event.event_type == "AUTH_FAILURE"
    assert event.hostname == "mymachine.example.com"


def test_nginx_access_ok_request():
    line = '198.51.100.7 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "Mozilla/5.0"'
    event = parse_raw_message(line, source_type="NGINX_ACCESS")
    assert event.event_type == "WEB_REQUEST"
    assert event.http_status == 200
    assert event.src_ip == "198.51.100.7"


def test_nginx_access_error_request():
    line = '198.51.100.7 - - [10/Oct/2023:13:55:39 +0000] "POST /login HTTP/1.1" 401 0 "-" "curl/8.0"'
    event = parse_raw_message(line, source_type="NGINX_ACCESS")
    assert event.event_type == "WEB_ERROR"
    assert event.http_status == 401


def test_nginx_access_traversal_path_preserved_for_rule_matching():
    line = '198.51.100.7 - - [10/Oct/2023:13:55:37 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "curl/8.0"'
    event = parse_raw_message(line, source_type="NGINX_ACCESS")
    assert "../" in event.http_path


def test_apache_access_uses_same_combined_format():
    line = '192.0.2.44 - - [10/Oct/2023:14:10:02 +0000] "GET /wp-login.php HTTP/1.1" 200 4523 "-" "Mozilla/5.0"'
    event = parse_raw_message(line, source_type="APACHE_ACCESS")
    assert event.event_type == "WEB_REQUEST"
    assert event.http_path == "/wp-login.php"


def test_json_generic_parses_direct_fields():
    line = '{"timestamp": "2023-10-11T22:20:00Z", "event_type": "AUTH_FAILURE", "src_ip": "203.0.113.44", "message": "bad creds"}'
    event = parse_raw_message(line, source_type="JSON_GENERIC")
    assert event.event_type == "AUTH_FAILURE"
    assert event.src_ip == "203.0.113.44"


def test_json_generic_unknown_event_type_falls_back_to_other():
    line = '{"event_type": "NOT_A_REAL_TYPE", "message": "hi"}'
    event = parse_raw_message(line, source_type="JSON_GENERIC")
    assert event.event_type == "OTHER"


def test_json_generic_malformed_returns_none():
    assert parse_raw_message("{not valid json", source_type="JSON_GENERIC") is None


def test_windows_json_auth_failure():
    line = '{"EventID": 4625, "TimeCreated": "2023-10-11T22:25:00Z", "IpAddress": "198.51.100.90", "TargetUserName": "administrator", "Computer": "WIN-DC01"}'
    event = parse_raw_message(line, source_type="WINDOWS_JSON")
    assert event.event_type == "AUTH_FAILURE"
    assert event.username == "administrator"
    assert event.hostname == "WIN-DC01"


def test_windows_json_account_created():
    line = '{"EventID": 4720, "TimeCreated": "2023-10-11T22:26:00Z", "TargetUserName": "temp_user", "Computer": "WIN-DC01"}'
    event = parse_raw_message(line, source_type="WINDOWS_JSON")
    assert event.event_type == "ACCOUNT_CREATED"


def test_windows_json_unknown_event_id_is_other():
    line = '{"EventID": 9999, "TimeCreated": "2023-10-11T22:26:00Z", "Computer": "WIN-DC01"}'
    event = parse_raw_message(line, source_type="WINDOWS_JSON")
    assert event.event_type == "OTHER"


def test_registry_returns_none_for_total_garbage():
    assert parse_raw_message("\x00\x01\x02 completely unparseable {{{") is None


def test_registry_returns_none_for_empty_string():
    assert parse_raw_message("") is None
