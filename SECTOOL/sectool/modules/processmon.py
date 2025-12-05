import psutil
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ---------------------------------------------------
# Suspicious indicators (you can add/remove later)
# ---------------------------------------------------
SUSPICIOUS_NAMES = [
    "keylogger", "meterpreter", "xmrig", "cryptominer",
    "darkcomet", "njrat", "quasar", "backdoor",
    "mimikatz", "nc.exe"
]

# ---------------------------------------------------
# Helper: Identify suspicious process
# ---------------------------------------------------
def is_suspicious(proc):
    try:
        name = (proc.info.get("name") or "").lower()

        # Known malicious patterns
        for bad in SUSPICIOUS_NAMES:
            if bad in name:
                return True

        # High CPU usage
        if proc.info.get("cpu_percent", 0) > 85:
            return True

        # RAM > 800 MB
        mem = proc.info.get("memory_info")
        if mem and (mem.rss > 800 * 1024 * 1024):
            return True

        return False

    except:
        return False


# ---------------------------------------------------
# Helper: Get network connections (safe)
# ---------------------------------------------------
def get_network_activity(proc):
    try:
        conns = proc.net_connections(kind="inet")
        out = []
        for c in conns:
            if c.raddr:
                out.append(f"{c.laddr.ip}:{c.laddr.port} → {c.raddr.ip}:{c.raddr.port}")
        return out
    except:
        return []


# ---------------------------------------------------
# List all running processes (single snapshot)
# ---------------------------------------------------
def list_processes():
    console.print("\n[bold cyan]📋 PROCESS LIST SNAPSHOT[/bold cyan]\n")

    table = Table(title="Running Processes", expand=True)
    table.add_column("PID", justify="right", style="cyan")
    table.add_column("Name", style="yellow")
    table.add_column("CPU %", style="magenta", justify="right")
    table.add_column("RAM (MB)", style="green", justify="right")

    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
        try:
            mem_mb = proc.info["memory_info"].rss / (1024 * 1024)
            table.add_row(
                str(proc.info["pid"]),
                proc.info["name"] or "unknown",
                str(proc.info.get("cpu_percent", 0)),
                f"{mem_mb:.1f}",
            )
        except:
            pass

    console.print(table)


# ---------------------------------------------------
# Show suspicious processes only
# ---------------------------------------------------
def list_suspicious():
    console.print("\n[bold red]⚠ SUSPICIOUS PROCESS DETECTED[/bold red]\n")

    table = Table(title="Suspicious Processes", expand=True)
    table.add_column("PID", style="red")
    table.add_column("Name", style="yellow")
    table.add_column("Reason", style="magenta")

    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
        try:
            if is_suspicious(proc):
                table.add_row(
                    str(proc.info["pid"]),
                    proc.info["name"] or "unknown",
                    "Suspicious indicators"
                )
        except:
            continue

    console.print(table)


# ---------------------------------------------------
# Real-time process monitor (advanced mode)
# ---------------------------------------------------
def monitor_processes():
    console.print(Panel.fit(
        "[bold cyan]🧠 Real-Time Process Monitor[/bold cyan]\n"
        "Tracking CPU, RAM, network and suspicious behavior...",
        border_style="blue"
    ))

    known = set()

    try:
        while True:
            console.clear()
            table = Table(title="System Process Activity", expand=True)

            table.add_column("PID", justify="right", style="cyan")
            table.add_column("Name", style="yellow")
            table.add_column("CPU %", justify="right", style="magenta")
            table.add_column("RAM (MB)", justify="right", style="green")
            table.add_column("Network", style="white")
            table.add_column("Alerts", style="red")

            current = set()

            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):

                try:
                    pid = proc.info["pid"]
                    current.add(pid)

                    alerts = []

                    # Detect new process
                    if pid not in known:
                        alerts.append("Started")

                    # Suspicious detection
                    if is_suspicious(proc):
                        alerts.append("Suspicious")

                    # Network connections
                    conns = get_network_activity(proc)
                    net_text = "\n".join(conns) if conns else "-"

                    mem_mb = proc.info["memory_info"].rss / (1024 * 1024)

                    table.add_row(
                        str(pid),
                        proc.info["name"] or "unknown",
                        str(proc.info.get("cpu_percent", 0)),
                        f"{mem_mb:.1f}",
                        net_text,
                        ", ".join(alerts) if alerts else "",
                    )

                except:
                    continue

            # Detect terminated processes
            terminated = known - current
            for t in terminated:
                console.print(f"[red][-] Process Terminated:[/red] {t}")

            known = current
            console.print(table)

            time.sleep(2)

    except KeyboardInterrupt:
        console.print("\n[bold green]✓ Monitoring stopped by user.[/bold green]")
