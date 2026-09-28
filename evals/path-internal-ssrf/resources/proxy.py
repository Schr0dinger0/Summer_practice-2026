import http.server, urllib.request, yaml

cfg = yaml.safe_load(open("resources/config.yaml"))["proxy"]

class P(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "/admin" in self.path or ".." in self.path:
            self.send_response(403); self.end_headers(); return
        url = cfg["upstream"] + self.path
        req = urllib.request.Request(url, headers={"X-Internal": "yes"})
        try:
            r = urllib.request.urlopen(req)
            body = r.read()
            self.send_response(r.status)
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            self.send_response(500); self.end_headers()

    def log_message(self, *args, **kwargs):
        pass

if __name__ == "__main__":
    host, port = cfg["listen"].split(":")
    http.server.HTTPServer((host, int(port)), P).serve_forever()