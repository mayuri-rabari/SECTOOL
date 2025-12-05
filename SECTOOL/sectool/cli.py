import argparse

# Import modules
from .modules.portscan import run_portscan
from .modules.bannergrab import grab_banner
from .modules.urlcheck import check_url
from .modules.hashdb import crack_hash
from .modules.processmon import monitor_processes, list_processes, list_suspicious


def main():
    parser = argparse.ArgumentParser(
        description="Mayuri's Cybersecurity CLI Swiss-Army Knife"
    )

    sub = parser.add_subparsers(dest="command")

    # -------------------------------
    # Port Scanner
    # -------------------------------
    ps = sub.add_parser("portscan", help="Scan open ports")
    ps.add_argument("--host", required=True)
    ps.add_argument("--ports", required=True)
    ps.add_argument("--fast", action="store_true")
    ps.add_argument("--banner", action="store_true")

    # -------------------------------
    # Banner Grabber
    # -------------------------------
    bg = sub.add_parser("bannergrab", help="Grab a service banner")
    bg.add_argument("--url", required=True)

    # -------------------------------
    # URL Checker
    # -------------------------------
    uc = sub.add_parser("urlcheck", help="Analyze a URL")
    uc.add_argument("--url", required=True)

    # -------------------------------
    # Hash Lookup
    # -------------------------------
    hd = sub.add_parser("hashdb", help="Crack or lookup hash")
    hd.add_argument("--hash", required=True)

    # -------------------------------
    # Process Monitor
    # -------------------------------
    pm = sub.add_parser("processmon", help="Monitor running processes")
    pm.add_argument("--list", action="store_true", help="Show snapshot of all processes")
    pm.add_argument("--live", action="store_true", help="Real-time live monitor")
    pm.add_argument("--suspicious", action="store_true", help="List only suspicious processes")

    # -------------------------------
    # Parse commands
    # -------------------------------
    args = parser.parse_args()

    if args.command == "portscan":
        run_portscan(args.host, args.ports)

    elif args.command == "bannergrab":
        grab_banner(args.url)

    elif args.command == "urlcheck":
        check_url(args.url)

    elif args.command == "hashdb":
        crack_hash(args.hash)

    elif args.command == "processmon":
        if args.list:
            list_processes()
        elif args.suspicious:
            list_suspicious()
        else:
            monitor_processes() if args.live or not (args.list or args.suspicious) else None

    else:
        parser.print_help()
