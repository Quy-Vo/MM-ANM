"""
https_server.py — Web Server HTTPS dùng chứng thư do CA nội bộ cấp.

Chỉ phục vụ thư mục www/ (không phục vụ thư mục làm việc nên không lộ khóa riêng), tắt liệt kê thư mục.
Chạy: python https_server.py [--port 4443] [--cert certs/server.crt] [--key certs/server.key] [--www www]
"""
import argparse
import functools
import http.server
import os
import ssl

from ca import CA_CN, OU_TEXT


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def list_directory(self, path):          # không cho liệt kê thư mục
        self.send_error(404, "Not found")
        return None

    def log_message(self, fmt, *args):
        pass


class QuietServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):   # lỗi bắt tay TLS của client bị từ chối là bình thường
        pass


def ensure_index(www: str) -> None:
    os.makedirs(www, exist_ok=True)
    index = os.path.join(www, "index.html")
    if not os.path.exists(index):
        with open(index, "w", encoding="utf-8") as f:
            f.write(f"<!doctype html><meta charset='utf-8'><title>HTTPS nội bộ</title>"
                    f"<h1>HTTPS nội bộ</h1><p>Chứng thư do <b>{CA_CN}</b> cấp.</p>"
                    f"<p>{OU_TEXT}</p><p><a href='ca.crt'>ca.crt</a> · <a href='ca.crl'>ca.crl</a></p>")


def make_server(port: int, cert: str, key: str, www: str = "www", host: str = "localhost") -> QuietServer:
    ensure_index(www)
    handler = functools.partial(QuietHandler, directory=www)
    httpd = QuietServer((host, port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    return httpd


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4443)
    ap.add_argument("--cert", default="certs/server.crt")
    ap.add_argument("--key", default="certs/server.key")
    ap.add_argument("--www", default="www")
    a = ap.parse_args()
    httpd = make_server(a.port, a.cert, a.key, a.www)
    print(f"Đang chạy HTTPS Server tại https://localhost:{a.port} (phục vụ thư mục {a.www}/)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
