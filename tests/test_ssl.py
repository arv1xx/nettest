from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from modules.ssl_check import check_ssl


def _mock_ssl_ctx(days_ahead=90):
    future = datetime.utcnow() + timedelta(days=days_ahead)
    mock_sock = MagicMock()
    mock_sock.getpeercert.return_value = {
        'notAfter': future.strftime('%b %d %H:%M:%S %Y GMT')
    }
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_sock
    return mock_ctx


def test_ssl_ok_returns_correct_structure():
    mock_ctx = _mock_ssl_ctx(days_ahead=90)
    with patch('ssl.create_default_context', return_value=mock_ctx), \
         patch('socket.socket'):
        result = check_ssl('example.com')
    assert result['status'] == 'ok'
    assert 'days_left' in result
    assert 'expires' in result


def test_ssl_days_left_is_positive_int():
    mock_ctx = _mock_ssl_ctx(days_ahead=60)
    with patch('ssl.create_default_context', return_value=mock_ctx), \
         patch('socket.socket'):
        result = check_ssl('example.com')
    assert isinstance(result['days_left'], int)
    assert result['days_left'] > 0


def test_ssl_error_on_connection_failure():
    with patch('ssl.create_default_context', side_effect=Exception('SSL handshake failed')):
        result = check_ssl('invalid.host')
    assert result['status'] == 'error'
    assert 'error' in result
