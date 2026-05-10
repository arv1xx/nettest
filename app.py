from flask import Flask, render_template, request, jsonify, send_file
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
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

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

# ── PDF helpers ────────────────────────────────────────────────────────────────

def _register_pdf_fonts():
    candidates = [
        ('C:/Windows/Fonts/arial.ttf',   'C:/Windows/Fonts/arialbd.ttf'),
        ('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
         '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'),
        ('/Library/Fonts/Arial.ttf',     '/Library/Fonts/Arial Bold.ttf'),
    ]
    for reg, bold in candidates:
        if os.path.exists(reg):
            try:
                pdfmetrics.registerFont(TTFont('PDF', reg))
                if os.path.exists(bold):
                    pdfmetrics.registerFont(TTFont('PDF-Bold', bold))
                    return 'PDF', 'PDF-Bold'
                return 'PDF', 'PDF'
            except Exception:
                pass
    return 'Helvetica', 'Helvetica-Bold'

_PDF_FONT, _PDF_BOLD = _register_pdf_fonts()


def _pdf_score(results):
    earned, possible = 0, 0
    ssl = results.get('ssl', {})
    if ssl.get('status') not in ('skip', None):
        possible += 25
        if ssl.get('status') == 'ok':
            earned += 25
    for num, pts in ((21, 10), (22, 10)):
        p = next((x for x in results.get('ports', []) if x['port'] == num), None)
        if p:
            possible += pts
            if p['status'] != 'open':
                earned += pts
    http = results.get('http', {})
    if http.get('status') not in ('skip', 'error', None):
        possible += 20
        missing = [h['header'] if isinstance(h, dict) else h
                   for h in (http.get('missing_headers') or [])]
        if 'Strict-Transport-Security' not in missing:
            earned += 10
        if 'Content-Security-Policy' not in missing:
            earned += 10
    sql = results.get('sql', [])
    if sql:
        possible += 20
        if not any(s.get('status') == 'vulnerable' for s in sql):
            earned += 20
    ddos = results.get('ddos', {})
    if ddos.get('status') not in ('skip', None):
        possible += 15
        if ddos.get('status') == 'ok':
            earned += 15
        elif ddos.get('status') == 'warn':
            earned += 7
    return round(earned / possible * 100) if possible else None


def build_pdf(host, scanned_at, results):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)

    DARK  = colors.HexColor('#111827')
    GRAY  = colors.HexColor('#6b7280')
    ACCENT = colors.HexColor('#2563eb')

    def S(name, **kw):
        kw.setdefault('fontName', _PDF_FONT)
        kw.setdefault('fontSize', 10)
        kw.setdefault('textColor', DARK)
        return ParagraphStyle(name, **kw)

    story = []

    # 1. Заголовок
    story.append(Paragraph(
        'NetTest — отчёт',
        S('t', fontName=_PDF_BOLD, fontSize=22, textColor=ACCENT, spaceAfter=6),
    ))
    story.append(Spacer(1, 8))

    # 2. Хост
    story.append(Paragraph(
        f'Хост: {host}',
        S('h', fontSize=10, textColor=GRAY, spaceAfter=2),
    ))
    story.append(Spacer(1, 4))

    # 3. Дата
    try:
        dt = datetime.fromisoformat(scanned_at)
        date_str = dt.strftime('%d.%m.%Y, %H:%M')
    except Exception:
        date_str = str(scanned_at)
    story.append(Paragraph(
        f'Дата сканирования: {date_str}',
        S('d', fontSize=10, textColor=GRAY),
    ))
    story.append(Spacer(1, 16))

    # 4–6. Security Score
    score = _pdf_score(results)
    if score is not None:
        sc = (colors.HexColor('#16a34a') if score >= 80
              else colors.HexColor('#d97706') if score >= 60
              else colors.HexColor('#dc2626'))
        lbl = ('Хорошая защита' if score >= 80
               else 'Средняя защита' if score >= 60
               else 'Слабая защита')

        # 5. Подпись
        story.append(Paragraph(
            lbl,
            S('sl', fontSize=10, textColor=GRAY),
        ))
        story.append(Spacer(1, 8))

        # 4. Цифры оценки
        story.append(Paragraph(
            f'{score} / 100',
            S('sv', fontName=_PDF_BOLD, fontSize=28, textColor=sc),
        ))
        story.append(Spacer(1, 20))

        # 6. Прогресс-бар
        fw = max(2, min(480, round(482 * score / 100)))
        bar = Table([['', '']], colWidths=[fw, 482 - fw], rowHeights=[10])
        bar.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(0,0), sc),
            ('BACKGROUND',    (1,0),(1,0), colors.HexColor('#e5e7eb')),
            ('TOPPADDING',    (0,0),(-1,-1), 0),
            ('BOTTOMPADDING', (0,0),(-1,-1), 0),
            ('LEFTPADDING',   (0,0),(-1,-1), 0),
            ('RIGHTPADDING',  (0,0),(-1,-1), 0),
        ]))
        story.append(bar)
        story.append(Spacer(1, 14))

    # Results table
    story.append(Paragraph('Результаты проверки',
                            S('rh', fontName=_PDF_BOLD, fontSize=11, spaceAfter=6)))

    rows, ts = [], [
        ('FONTNAME',     (0,0),(-1,-1), _PDF_FONT),
        ('FONTSIZE',     (0,0),(-1,-1), 9),
        ('TEXTCOLOR',    (0,0),(-1,-1), DARK),
        ('VALIGN',       (0,0),(-1,-1), 'MIDDLE'),
        ('TOPPADDING',   (0,0),(-1,-1), 5),
        ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        ('LEFTPADDING',  (0,0),(-1,-1), 10),
        ('RIGHTPADDING', (0,0),(-1,-1), 10),
        ('LINEBELOW',    (0,0),(-1,-1), 0.5, colors.HexColor('#e5e7eb')),
    ]

    def sec(title):
        i = len(rows)
        rows.append([title, ''])
        ts.extend([
            ('SPAN',       (0,i),(1,i)),
            ('BACKGROUND', (0,i),(1,i), colors.HexColor('#f3f4f6')),
            ('FONTNAME',   (0,i),(0,i), _PDF_BOLD),
            ('FONTSIZE',   (0,i),(0,i), 8),
            ('TEXTCOLOR',  (0,i),(0,i), GRAY),
        ])

    STATUS_BG = {
        'ok':         colors.HexColor('#f0faf4'),
        'warn':       colors.HexColor('#fffbeb'),
        'slow':       colors.HexColor('#fffbeb'),
        'vulnerable': colors.HexColor('#fef2f2'),
        'error':      colors.HexColor('#fef2f2'),
        'err':        colors.HexColor('#fef2f2'),
    }
    STATUS_FG = {
        'ok':         colors.HexColor('#16a34a'),
        'warn':       colors.HexColor('#d97706'),
        'slow':       colors.HexColor('#d97706'),
        'vulnerable': colors.HexColor('#dc2626'),
        'error':      colors.HexColor('#dc2626'),
        'err':        colors.HexColor('#dc2626'),
    }

    def row(label, value, status):
        i = len(rows)
        rows.append([str(label), str(value)])
        ts.extend([
            ('BACKGROUND', (0,i),(1,i), STATUS_BG.get(status, colors.white)),
            ('TEXTCOLOR',  (1,i),(1,i), STATUS_FG.get(status, DARK)),
            ('FONTNAME',   (1,i),(1,i), _PDF_BOLD),
        ])

    ping  = results.get('ping', {})
    ports = results.get('ports', [])
    if ping.get('status') != 'skip' or ports:
        sec('Сеть')
        if ping.get('status') != 'skip':
            if ping.get('status') == 'ok':
                row('Пинг', f"{ping.get('time_ms', '-')} ms", 'ok')
            else:
                row('Пинг', 'Хост недоступен', 'error')
        for p in ports:
            row(f"Порт {p['port']} ({p['name']})",
                'открыт' if p['status'] == 'open' else 'закрыт',
                'ok' if p['status'] == 'open' else 'warn')

    ssl  = results.get('ssl', {})
    http = results.get('http', {})
    if ssl.get('status') != 'skip' or http.get('status') != 'skip':
        sec('SSL и HTTP-заголовки')
        if ssl.get('status') != 'skip':
            if ssl.get('status') == 'ok':
                row('SSL сертификат',
                    f"Действителен, истекает через {ssl.get('days_left','?')} дн.", 'ok')
            else:
                row('SSL сертификат',
                    'Ошибка сертификата', 'error')
        if http.get('status') != 'skip':
            row('HTTP статус',
                str(http.get('status_code', 'ошибка')),
                http.get('status', 'error'))
            for h in (http.get('missing_headers') or []):
                name = h['header'] if isinstance(h, dict) else h
                row(name, 'отсутствует', 'warn')

    ddos = results.get('ddos', {})
    if ddos.get('status') != 'skip':
        sec('DDoS-устойчивость')
        row('Среднее время под нагрузкой',
            f"{ddos.get('avg_response_ms', '-')} ms",
            ddos.get('status', 'warn'))
        row('Успешных запросов',
            f"{ddos.get('successful', 0)} / {ddos.get('requests_sent', 20)}",
            'ok' if (ddos.get('errors') or 0) <= 5 else 'warn')

    sql_r = results.get('sql', [])
    if sql_r:
        sec('SQL-инъекции')
        for s in sql_r:
            row(s.get('payload', ''), s.get('note', ''), s.get('status', 'ok'))

    if rows:
        tbl = Table(rows, colWidths=[305, 177])
        tbl.setStyle(TableStyle(ts))
        story.append(tbl)

    # Footer
    story.append(Spacer(1, 18))
    story.append(HRFlowable(width='100%', thickness=0.5,
                             color=colors.HexColor('#e5e7eb')))
    story.append(Paragraph(
        f'Сгенерировано NetTest · {datetime.now().strftime("%d.%m.%Y")}',
        S('f', fontSize=8, textColor=GRAY, alignment=TA_CENTER, spaceBefore=6)
    ))

    doc.build(story)
    buf.seek(0)
    return buf

# ── end PDF helpers ────────────────────────────────────────────────────────────

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

@app.route('/export-pdf', methods=['POST'])
def export_pdf():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    host       = data.get('host', 'unknown')
    scanned_at = data.get('scanned_at', datetime.utcnow().isoformat())
    results    = data.get('results', {})
    buf = build_pdf(host, scanned_at, results)
    safe_host = re.sub(r'[^a-zA-Z0-9._-]', '_', host)
    filename  = f"nettest_{safe_host}_{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(buf, mimetype='application/pdf',
                     as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True)