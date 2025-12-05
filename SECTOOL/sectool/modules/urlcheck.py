import requests
import ssl
import socket
from urllib.parse import urlparse
import whois

def check_url(url):
    print()

    print("[+] Checking URL:", url)
    print()

    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    # -----------------------------------------------------
    # SECTION 1: HTTP REQUEST CHECK
    # -----------------------------------------------------
    print("────────────────────────────────────────────────────────────")
    print("   🌐 HTTP Status Check")
    print("────────────────────────────────────────────────────────────")

    try:
        r = requests.get(url, timeout=5)
        print(f"[+] Status: {r.status_code}")
        server = r.headers.get("Server", "Unknown")
        print("[+] Server:", server)
    except Exception:
        print("[!] URL unreachable.")

    # -----------------------------------------------------
    # SECTION 2: SSL CERTIFICATE DETAILS
    # -----------------------------------------------------
    print("\n────────────────────────────────────────────────────────────")
    print("   🔐 SSL Certificate Details")
    print("────────────────────────────────────────────────────────────")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(4)
            s.connect((domain, 443))
            cert = s.getpeercert()

        print("Subject:", cert.get("subject", "N/A"))
        print("Issuer:", cert.get("issuer", "N/A"))
        print("Valid From:", cert.get("notBefore", "N/A"))
        print("Valid To:", cert.get("notAfter", "N/A"))

        # TLS version and cipher
        # For Python 3.10+, we can fetch these after handshake
        try:
            tls_version = s.version()
            cipher = s.cipher()
            print("TLS Protocol:", tls_version)
            print("Cipher:", cipher)
        except:
            pass

    except Exception:
        print("[!] Could not fetch SSL certificate info.")

    # -----------------------------------------------------
    # SECTION 3: WHOIS LOOKUP
    # -----------------------------------------------------
    print("\n────────────────────────────────────────────────────────────")
    print("   📄 WHOIS Information")
    print("────────────────────────────────────────────────────────────")

    try:
        w = whois.whois(domain)
        print("Registrar:", w.registrar)
        print("Country:", w.country)
        print("Created:", w.creation_date)
        print("Expiry:", w.expiration_date)
    except Exception:
        print("[!] WHOIS lookup failed.")

    print("\n✓ URL check complete.\n")
