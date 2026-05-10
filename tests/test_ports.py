from unittest.mock import patch, MagicMock
from modules.ports import check_ports


def test_ports_returns_five_entries():
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    with patch('socket.socket', return_value=mock_sock):
        result = check_ports('example.com')
    assert isinstance(result, list)
    assert len(result) == 5


def test_ports_open_when_connect_succeeds():
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    with patch('socket.socket', return_value=mock_sock):
        result = check_ports('example.com')
    assert all(p['status'] == 'open' for p in result)


def test_ports_closed_when_connect_fails():
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 111
    with patch('socket.socket', return_value=mock_sock):
        result = check_ports('example.com')
    assert all(p['status'] == 'closed' for p in result)
    assert all({'port', 'name', 'status'} <= p.keys() for p in result)
