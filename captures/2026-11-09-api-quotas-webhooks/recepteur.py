"""Récepteur de webhooks de test (port 9104) : journalise chaque envoi et vérifie la signature HMAC-SHA256.

python3 -I recepteur.py <fichier trace> [secret]
- Le secret peut aussi être déposé dans <fichier trace>.secret (relu à chaque requête).
- POST /vendora → 200 ; POST /panne → 503 (pour montrer les nouvelles tentatives).
"""
import hashlib
import hmac
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

TRACE = sys.argv[1]
SECRET = sys.argv[2] if len(sys.argv) > 2 else None


def secret():
    try:
        return open(TRACE + '.secret').read().strip()
    except OSError:
        return SECRET


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if self.path == '/secret':  # dépôt du secret par le scénario de capture (jamais journalisé)
            with open(TRACE + '.secret', 'w') as f:
                f.write(body.decode().strip())
            self.send_response(204)
            self.end_headers()
            return
        header = self.headers.get('X-Vendora-Signature', '')
        parts = dict(p.split('=', 1) for p in header.split(',') if '=' in p)
        key = secret()
        valid = None
        if key and 't' in parts:
            expected = hmac.new(key.encode(), f"{parts['t']}.".encode() + body, hashlib.sha256).hexdigest()
            valid = hmac.compare_digest(expected, parts.get('v1', '')) and abs(time.time() - int(parts['t'])) < 300
        status = 503 if self.path.startswith('/panne') else 200
        entry = {
            'recuLe': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            'chemin': self.path,
            'reponse': status,
            'signatureValide': valid,
            'entetes': {k: v for k, v in self.headers.items() if k.lower().startswith('x-vendora') or k.lower() in ('content-type', 'user-agent')},
            'corps': json.loads(body or b'null'),
        }
        with open(TRACE, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False, indent=2) + '\n')
        payload = b'ok' if status == 200 else b'panne simulee'
        self.send_response(status)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


HTTPServer(('127.0.0.1', 9104), Handler).serve_forever()
