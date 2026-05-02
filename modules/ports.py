import socket

PORTS = {80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 8080: 'HTTP-alt'}

def check_ports(host):
    results = []
    for port, name in PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            results.append({
                'port': port,
                'name': name,
                'status': 'open' if result == 0 else 'closed'
            })
        except Exception as e:
            results.append({'port': port, 'name': name, 'status': 'error'})
    return results