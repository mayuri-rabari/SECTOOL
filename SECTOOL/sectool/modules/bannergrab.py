import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

def pretty(title):
    print("\n" + "─" * 50)
    print(f"   {title}")
    print("─" * 50)

def grab_banner(url):
    print("")

    # Extract hostname + port with smart logic
    if "://" in url:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    else:
        if ":" in url:
            host, port = url.split(":")
            port = int(port)
        else:
            host, port = url, 80

    print(f"[+] Connecting to {host}:{port}")

    # If HTTPS
    if port == 443:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    pretty("🔐 TLS Certificate Information")

                    subject = dict(x[0] for x in cert["subject"])
                    issuer = dict(x[0] for x in cert["issuer"])
                    valid_from = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                    valid_to = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

                    print(f" Subject     : {subject.get('commonName', '')}")
                    print(f" Issuer      : {issuer.get('organizationName', '')} ({issuer.get('commonName', '')})")
                    print(f" Valid From  : {valid_from}")
                    print(f" Valid Until : {valid_to}")
                    print(f" Protocol    : {ssock.version()}")
                    print(f" Cipher      : {ssock.cipher()[0]}")
        except Exception as e:
            print(f"[!] TLS handshake failed: {e}")

        # HTTP banner after TLS
        try:
            pretty("🌐 HTTP Banner (over TLS)")
            header_socket = ssl.wrap_socket(socket.socket())
            header_socket.settimeout(3)
            header_socket.connect((host, port))
            header_socket.send(b"GET / HTTP/1.0\r\n\r\n")

            data = header_socket.recv(4096).decode("latin-1", errors="ignore")
            print(data.strip() if data.strip() else "[!] No HTTP banner returned.")

        except Exception as e:
            print(f"[!] No HTTP header returned: {e}")

        return

    # If HTTP or TCP
    try:
        pretty("🌐 HTTP Banner")
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((host, port))
        sock.send(b"GET / HTTP/1.0\r\n\r\n")

        data = sock.recv(4096).decode("latin-1", errors="ignore")
        print(data.strip() if data.strip() else "[!] No banner returned.")

        sock.close()

    except Exception as e:
        print(f"[!] Error: {e}")
