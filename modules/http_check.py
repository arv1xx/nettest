import requests

SECURITY_HEADERS = ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']

def check_http(host):
    try:
        r = requests.get(f'https://{host}', timeout=5)
        headers = dict(r.headers)
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        return {
            'status_code': r.status_code,
            'status': 'ok' if r.status_code == 200 else 'warn',
            'missing_headers': missing
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}