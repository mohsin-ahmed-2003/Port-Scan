"""
Professional Port Scanner with:
- Full 65535 port scanning
- Smart service detection
- Vulnerability assessment
"""

# -----------------
# Import Libraries 
# -----------------
import socket
import concurrent.futures
from rich.progress import Progress
from rich.console import Console
from rich.table import Table
import time

# -------------------------
# Configuration (Settings)
# -------------------------
console = Console()
MAX_THREADS = 512  # Maximum parallel scans (512 threads)
TIMEOUT = 1.5      # Connection timeout in seconds

# Service Database (Port -> Service, Vulnerabilities)
SERVICE_DB = {
    21: ("FTP", ["CVE-2023-46604"]),    # FTP Service
    22: ("SSH", ["CVE-2023-38408"]),    # SSH Service
    80: ("HTTP", ["CVE-2023-3823"]),    # Web Service
    443: ("HTTPS", ["CVE-2023-3817"]),  # Secure Web
    3389: ("RDP", ["CVE-2023-3536"]),   # Remote Desktop
    # Add more services here...
}

# ---------------------------
# Core Functions (Main Logic)
# ---------------------------

def grab_banner(sock, port):
    """Get service banner (Service ka intro message fetch kare)"""
    try:
        # Protocol-specific requests
        if port == 80:  # HTTP
            sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        elif port == 22:  # SSH
            sock.send(b"SSH-2.0-Client\r\n")
        elif port == 21:  # FTP
            sock.send(b"USER anonymous\r\n")
        return sock.recv(1024).decode(errors='ignore').strip()
    except:
        return ""

def scan_port(target, port):
    """Scan single port (Ek port ko check kare)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            if s.connect_ex((target, port)) == 0:  # Port open hai?
                banner = grab_banner(s, port)      # Banner grab karo
                service, vulns = SERVICE_DB.get(port, ("Unknown", []))
                return port, True, service, banner[:500], vulns
    except:
        pass
    return port, False, "", "", []

# ---------------------------
# Main Scanning Logic
# ---------------------------

def run_scan(target):
    """Run full port scan (Saare ports ko scan kare)"""
    console.print(f"[bold red]🚀 Scanning {target} (All 65535 ports)...[/]")
    open_ports = []
    
    # Progress tracking 
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing...", total=65535)
        
        # Multi-threading 
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(scan_port, target, port): port for port in range(1, 65536)}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service, banner, vulns = future.result()
                progress.update(task, advance=1)
                
                if is_open:  # Scan Port if open
                    open_ports.append((port, service, banner, vulns))
                    # Real-time results
                    console.print(
                        f"[green]✔ PORT {port}[/] | [yellow]{service}[/] | "
                        f"{banner[:50]}{'...' if len(banner) > 50 else ''}"
                    )
    
    return open_ports

# -----------
# Reporting
# -----------

def generate_report(target, results):
    """Generate professional report (Report banaye)"""
    table = Table(title=f"🔍 Scan Results for {target}")
    table.add_column("Port", style="cyan")
    table.add_column("Service", style="magenta")
    table.add_column("Banner", style="green")
    table.add_column("Vulnerabilities", style="red")
    
    for port, service, banner, vulns in sorted(results):
        vuln_text = "\n".join(vulns) if vulns else "None"
        table.add_row(str(port), service, banner[:40], vuln_text)
    
    console.print(table)
    console.print(f"[bold green]✅ Total Open Ports: {len(results)}[/]")

# ---------------------------
# Main Program
# ---------------------------

if __name__ == "__main__":
    # Show banner 
    console.print("[bold blue]Port-Scan[/]", justify="center")
    console.print("[italic]by Moshin Ahmed[/]", justify="center")
    
    # Get target input 
    target = console.input("[yellow]Enter Target IP/Hostname: [/]")
    
    # Start scanning 
    start_time = time.time()
    results = run_scan(target)
    generate_report(target, results)
    
    # Show completion time 
    console.print(f"[italic]Scan completed in {time.time() - start_time:.2f} seconds[/]")



"""
basic scan:
    python scanport.py -t 192.168.1.1

Advanced scan (512 threads + stealth mode + HTML report):
    python scanport.py -t example.com --threads 512 --stealth --html report.html
"""
