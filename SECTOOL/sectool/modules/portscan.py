import socket
import concurrent.futures
from urllib.parse import urlparse

def parse_target(target):
    # Handle URLs like https://google.com or http://example.com:8080
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port
        return host, port
    return target, None


def parse_ports(port_string):
    if port_string == "all":
        return range(1, 65536)

    ports = set()
    for part in port_string.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    return sorted(ports)


def scan_port(host, port, timeout=1):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        return port, True
    except:
        return port, False


def run_portscan(target, ports):
    host, url_port = parse_target(target)

    print(f"\n[+] Resolving host: {host}")
    try:
        resolved_ip = socket.gethostbyname(host)
    except:
        print("[!] Failed to resolve domain.")
        return

    print(f"[+] Target IP: {resolved_ip}")

    port_list = parse_ports(ports)
    print(f"[+] Scanning {len(port_list)} ports...")

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(scan_port, resolved_ip, p) for p in port_list]

        for f in concurrent.futures.as_completed(futures):
            port, is_open = f.result()
            if is_open:
                print(f"    [+] PORT OPEN: {port}")
                open_ports.append(port)

    print("\n[+] Scan complete.")
    if not open_ports:
        print("[!] No open ports found.")
    else:
        print("[+] Open Ports:", open_ports)
