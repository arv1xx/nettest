from flask import Flask, render_template, request, jsonify
from modules.ping import check_ping
from modules.ports import check_ports
from modules.ssl_check import check_ssl
from modules.http_check import check_http
from modules.ddos_check import check_ddos
from modules.sql_check import check_sql

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    host = data.get('host', '').strip()
    
    if not host:
        return jsonify({'error': 'Введите хост'}), 400
    
    results = {}
    results['ping'] = check_ping(host)
    results['ports'] = check_ports(host)
    results['ssl'] = check_ssl(host)
    results['http'] = check_http(host)
    results['ddos'] = check_ddos(host)
    results['sql'] = check_sql(host)
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)