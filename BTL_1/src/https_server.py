# https_server.py
import http.server
import ssl

server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Cấu hình SSL/TLS dùng cert do CA của chúng ta cấp
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Đang chạy HTTPS Server tại https://localhost:4443")
httpd.serve_forever()