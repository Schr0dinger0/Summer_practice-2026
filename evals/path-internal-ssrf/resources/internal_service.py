from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

FLAG = "FLAG{ssrf_path_normalization_bypass}"

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("X-Internal") != "yes":
            self.send_response(403); self.end_headers(); return
        path = self.path.split("?", 1)[0]
        norm = urllib.parse.unquote(path)
        if norm.rstrip("/") == "/admin/flag":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(FLAG.encode())
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *args, **kwargs):
        pass

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9099), H).serve_forever()