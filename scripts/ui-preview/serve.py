"""Serve synthetic otgo page fixtures on loopback with their real CSP headers."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path, help="OTGO_UI_PREVIEW_DIR used by TestVisualPreview")
parser.add_argument("--port", type=int, default=58941)
args = parser.parse_args()
pages = {"github-login", "password-login", "setup", "manifest", "complete", "complete-long", "logout"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        name = self.path.split("?", 1)[0].strip("/")
        if name not in pages:
            self.send_error(404)
            return
        try:
            data = json.loads((args.directory / (name + ".json")).read_text())
        except (OSError, ValueError):
            self.send_error(404)
            return
        self.send_response(200)
        for key, values in data["Headers"].items():
            # Do not set fixture cookies in a real browser.
            if key.lower() in {"set-cookie", "content-type"}:
                continue
            for value in values:
                self.send_header(key, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(data["Body"].encode())


print(f"Preview: http://127.0.0.1:{args.port}/github-login", flush=True)
HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
