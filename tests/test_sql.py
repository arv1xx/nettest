from unittest.mock import patch, MagicMock
from modules.sql_check import check_sql, PAYLOADS


def test_sql_returns_entry_per_payload():
    mock_resp = MagicMock()
    mock_resp.text = '<html>No results found</html>'
    with patch('requests.get', return_value=mock_resp):
        result = check_sql('example.com')
    assert isinstance(result, list)
    assert len(result) == len(PAYLOADS)


def test_sql_clean_response_gives_ok_status():
    mock_resp = MagicMock()
    mock_resp.text = '<html>No results found</html>'
    with patch('requests.get', return_value=mock_resp):
        result = check_sql('example.com')
    assert all(r['status'] == 'ok' for r in result)
    assert all({'payload', 'status', 'note'} <= r.keys() for r in result)


def test_sql_vulnerable_when_sql_error_in_body():
    mock_resp = MagicMock()
    mock_resp.text = "You have an error in your SQL syntax near ''"
    with patch('requests.get', return_value=mock_resp):
        result = check_sql('example.com')
    assert all(r['status'] == 'vulnerable' for r in result)
    assert all(r['note'] == 'SQL ошибка в ответе' for r in result)
