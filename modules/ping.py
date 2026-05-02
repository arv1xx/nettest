import socket
import time

def check_ping(host):
    try:
        start = time.time()
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, 80))
        elapsed = round((time.time() - start) * 1000, 2)
        return {'status': 'ok', 'time_ms': elapsed}
    except Exception as e:
        return {'status': 'error', 'time_ms': None, 'error': str(e)}