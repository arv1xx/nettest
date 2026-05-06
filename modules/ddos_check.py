import requests
import threading
import time

def check_ddos(host):
    times = []
    errors = [0]
    successful = [0]
    lock = threading.Lock()

    def send_request():
        try:
            start = time.time()
            r = requests.get(f'http://{host}', timeout=5)
            elapsed = round((time.time() - start) * 1000, 2)
            with lock:
                times.append(elapsed)
                successful[0] += 1
        except Exception:
            with lock:
                errors[0] += 1

    threads = [threading.Thread(target=send_request) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    avg_time = round(sum(times) / len(times), 2) if times else None
    status = 'ok' if avg_time and avg_time < 1000 else 'warn'

    return {
        'status': status,
        'requests_sent': 20,
        'successful': successful[0],
        'avg_response_ms': avg_time,
        'errors': errors[0]
    }