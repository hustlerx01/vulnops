"""LAB ONLY: tiny intentionally weak web app (stdlib) for ZAP to scan on 127.0.0.1. Never expose."""
import html, http.server, urllib.parse

PAGE = """<html><head><title>VulnOps lab</title></head><body>
<h1>Hello {name}</h1>
<form action="/login" method="GET"><input name="user"><input name="password" type="password"><input type="submit"></form>
<a href="/search?q=test">search</a> <a href="/admin/">admin</a>
<script src="http://cdn.example/jquery-1.7.1.min.js"></script>
</body></html>"""


class H(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.2.15 (CentOS)"  # deliberately leaky banner
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        name = q.get("name", q.get("q", ["lab"]))[0]          # reflected unescaped (XSS) - intentional
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=abc123; Path=/")  # no HttpOnly/Secure/SameSite
        self.send_header("X-Powered-By", "PHP/5.3.3")
        self.end_headers()
        self.wfile.write(PAGE.replace("{name}", name).encode())
    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", 8088), H).serve_forever()
