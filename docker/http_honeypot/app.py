"""
HTTP Honeypot - Flask-based web decoy.
Accepts all requests, logs everything, returns convincing fake responses.
Part of HPThreat: https://github.com/rod-trent/HPThreat
"""

import json
import logging
import os
from datetime import datetime, timezone

from flask import Flask, Response, request

app = Flask(__name__)
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)  # Suppress Flask access log; we do our own

LOG_DIR = "/app/logs"
LOG_FILE = os.path.join(LOG_DIR, "http_honeypot.json")
HONEYPOT_NAME = os.getenv("HONEYPOT_NAME", "http-honeypot")

os.makedirs(LOG_DIR, exist_ok=True)

_FAKE_HEADERS = {
    "Server": "Apache/2.4.54 (Ubuntu)",
    "X-Powered-By": "PHP/8.1.12",
    "X-Frame-Options": "SAMEORIGIN",
}

_FAKE_HTML = """<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>"""

_FAKE_404 = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>"""

_FAKE_401 = """<!DOCTYPE html>
<html><head><title>401 Authorization Required</title></head>
<body><h1>Authorization Required</h1>
<p>This server could not verify that you are authorized to access the document requested.</p>
</body></html>"""


def _log_request(resp_code: int):
    try:
        body_bytes = request.get_data(cache=True)
        body = body_bytes[:4096].decode("utf-8", errors="replace") if body_bytes else ""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": request.remote_addr,
            "method": request.method,
            "path": request.path,
            "query_string": request.query_string.decode("utf-8", errors="replace"),
            "user_agent": request.headers.get("User-Agent", ""),
            "content_type": request.headers.get("Content-Type", ""),
            "content_length": request.content_length or 0,
            "body": body,
            "headers": dict(request.headers),
            "response_code": resp_code,
            "sensor": HONEYPOT_NAME,
        }
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _make_response(body: str, status: int, content_type: str = "text/html") -> Response:
    resp = Response(body, status=status, content_type=f"{content_type}; charset=utf-8")
    for k, v in _FAKE_HEADERS.items():
        resp.headers[k] = v
    return resp


@app.route("/", methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE"])
def root():
    _log_request(200)
    return _make_response(_FAKE_HTML, 200)


@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/wp-admin/", methods=["GET", "POST"])
@app.route("/wp-admin/<path:path>", methods=["GET", "POST"])
def wp_admin(path=""):
    _log_request(401)
    return _make_response(_FAKE_401, 401)


@app.route("/.env", methods=["GET"])
@app.route("/.git/config", methods=["GET"])
@app.route("/.aws/credentials", methods=["GET"])
def fake_sensitive():
    # Return convincing fake content to keep attacker engaged
    _log_request(200)
    fake_content = "# Fake configuration file\nDB_PASSWORD=REDACTED\nSECRET_KEY=\n"
    return _make_response(fake_content, 200, "text/plain")


@app.route("/<path:path>", methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
def catch_all(path=""):
    # Return 404 for unknown paths but log everything
    _log_request(404)
    return _make_response(_FAKE_404, 404)


@app.errorhandler(Exception)
def handle_error(e):
    _log_request(500)
    return _make_response("Internal Server Error", 500)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
