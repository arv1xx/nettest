import requests
import threading
import time

def check_ddos(host):
    results = []
    errors = 0
    times = []

    def send_request():
        try:
            start = time.time()
            r = requests.get(f'http://{host}', timeout=5)
            elapsed = round((time.time() - start) * 1000, 2)
            times.append(elapsed)
            results.append(r.status_code)
        except Exception:
            errors += 1

    threads = []
    for _ in range(20):
        t = threading.Thread(target=send_request)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    avg_time = round(sum(times) / len(times), 2) if times else None
    status = 'ok' if avg_time and avg_time < 1000 else 'warn'

    return {
        'status': status,
        'requests_sent': 20,
        'avg_response_ms': avg_time,
        'errors': errors
    }