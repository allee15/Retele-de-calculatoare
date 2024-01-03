from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
from urllib.parse import urlparse

# DNS server configuration
DNS_SERVER_HOST = '127.0.0.1'  # DNS server address
DNS_SERVER_PORT = 53  # DNS server port

# Crearea unei clase custom - Handler pentru request-urile de tip http care mosteneste clasa BaseHTTPRequestHandler
class ProxyHandler(BaseHTTPRequestHandler):
    # handler pt GET request
    def do_GET(self):
        self.redirect_to_dns_server()

    # handler pentru POST request
    def do_POST(self):
        self.redirect_to_dns_server()

    def redirect_to_dns_server(self):
        # Preiau domain-ul din request-ul de http facut in browser
        parsed_url = urlparse(self.path)
        domain = parsed_url.netloc

        # imi creez comanda pe care o voi apela si cu care voi face un request in DNS server pentru domain-ul dorit
        cmd = ['nslookup', '-port=' + str(DNS_SERVER_PORT), domain, DNS_SERVER_HOST]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)

        # trimite inapoi un raspuns cu codul 200
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

if __name__ == '__main__':
    try:
        # Create the proxy server
        server = HTTPServer(('127.0.0.1', 5000), ProxyHandler)

        print('Starting proxy server at {}:{}'.format('127.0.0.1', 5000))
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()