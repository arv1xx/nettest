import ssl, socket
from datetime import datetime

def check_ssl(host):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(3)
            s.connect((host, 443))
            cert = s.getpeercert()
        expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expires - datetime.utcnow()).days
        return {'status': 'ok', 'expires': str(expires.date()), 'days_left': days_left}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}