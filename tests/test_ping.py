from unittest.mock import patch, MagicMock
from modules.ping import check_ping


def test_ping_ok_status_and_time():
    mock_sock = MagicMock()
    with patch('socket.socket', return_value=mock_sock):
        result = check_ping('example.com')
    assert result['status'] == 'ok'
    assert isinstance(result['time_ms'], float)


def test_ping_error_on_connection_failure():
    with patch('socket.socket', side_effect=OSError('Connection refused')):
        result = check_ping('unreachable.invalid')
    assert result['status'] == 'error'
    assert result['time_ms'] is None
    assert 'error' in result


def test_ping_required_keys_present():
    mock_sock = MagicMock()
    with patch('socket.socket', return_value=mock_sock):
        result = check_ping('example.com')
    assert 'status' in result
    assert 'time_ms' in result
