from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from modules.ping import check_ping
from modules.ports import check_ports
from modules.ssl_check import check_ssl
from modules.http_check import check_http
from modules.ddos_check import check_ddos
from modules.sql_check import check_sql
from datetime import datetime
import json
import os
import re

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback_dev_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'history.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour", "10 per minute"]
)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(253), nullable=False)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'host': self.host,
            'scanned_at': self.scanned_at.isoformat(),
            'results': json.loads(self.results)
        }

with app.app_context():
    db.create_all()

def validate_host(host):
    blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '192.168.', '10.', '172.']
    if any(b in host for b in blocked):
        return False
    pattern = r'^[a-zA-Z0-9.-]{1,253}$'
    return bool(re.match(pattern, host))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@limiter.limit("5 per minute")
def scan():
    data = request.get_json()
    host = data.get('host', '').strip()
    modules = data.get('modules', {})

    if not host:
        return jsonify({'error': 'Введите хост'}), 400

    if not validate_host(host):
        return jsonify({'error': 'Недопустимый хост'}), 400

    results = {}

    if modules.get('ping', True):
        results['ping'] = check_ping(host)
    else:
        results['ping'] = {'status': 'skip'}

    if modules.get('ports', True):
        results['ports'] = check_ports(host)
    else:
        results['ports'] = []

    if modules.get('ssl', True):
        results['ssl'] = check_ssl(host)
    else:
        results['ssl'] = {'status': 'skip'}

    if modules.get('http', True):
        results['http'] = check_http(host)
    else:
        results['http'] = {'status': 'skip', 'status_code': '-', 'missing_headers': []}

    if modules.get('ddos', True):
        results['ddos'] = check_ddos(host)
    else:
        results['ddos'] = {'status': 'skip', 'avg_response_ms': '-', 'errors': 0, 'requests_sent': 0, 'successful': 0}

    if modules.get('sql', True):
        results['sql'] = check_sql(host)
    else:
        results['sql'] = []

    entry = ScanHistory(host=host, results=json.dumps(results))
    db.session.add(entry)
    db.session.commit()

    return jsonify(results)

@app.route('/history')
def history():
    limit = request.args.get('limit', 20, type=int)
    entries = ScanHistory.query.order_by(ScanHistory.scanned_at.desc()).limit(limit).all()
    return jsonify([e.to_dict() for e in entries])

if __name__ == '__main__':
    app.run(debug=True)