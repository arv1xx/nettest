from unittest.mock import patch, MagicMock
from modules.http_check import check_http

ALL_SECURITY_HEADERS = {
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'",
    'Strict-Transport-Security': 'max-age=31536000',
}


def test_http_ok_with_all_security_headers():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = ALL_SECURITY_HEADERS
    with patch('requests.get', return_value=mock_resp):
        result = check_http('example.com')
    assert result['status'] == 'ok'
    assert result['missing_headers'] == []
    assert result['status_code'] == 200


def test_http_reports_missing_security_headers():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {'Content-Type': 'text/html'}
    with patch('requests.get', return_value=mock_resp):
        result = check_http('example.com')
    assert 'X-Frame-Options' in result['missing_headers']
    assert 'Content-Security-Policy' in result['missing_headers']
    assert 'Strict-Transport-Security' in result['missing_headers']


def test_http_error_on_request_failure():
    with patch('requests.get', side_effect=Exception('Connection refused')):
        result = check_http('unreachable.invalid')
    assert result['status'] == 'error'
    assert 'error' in result
