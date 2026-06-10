"""
scanner.py - Network Scanner (Ping Sweep + Port Scanner)
Covers: ARP concepts, ICMP, TCP sockets, service identification (CCNA)
"""

import socket
import concurrent.futures
import ipaddress
import subprocess
import platform
import time
from typing import Callable


# Common ports and their service names (CCNA relevant)
COMMON_PORTS = {
    20:   "FTP-Data",
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP-Server",
    68:   "DHCP-Client",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    119:  "NNTP",
    123:  "NTP",
    143:  "IMAP",
    161:  "SNMP",
    162:  "SNMP-Trap",
    179:  "BGP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    500:  "IKE/IPSec",
    514:  "Syslog",
    520:  "RIP",
    554:  "RTSP",
    587:  "SMTP-TLS",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle-DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}


def ping_host(ip: str, timeout: float = 1.0) -> dict:
    """
    Ping a single host using ICMP (system ping command).
    Works on Windows, macOS, and Linux.
    """
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        latency = round((time.time() - start) * 1000, 2)
        alive = result.returncode == 0
    except subprocess.TimeoutExpired:
        alive   = False
        latency = None

    hostname = None
    if alive:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = None

    return {
        "ip":       ip,
        "alive":    alive,
        "latency":  latency,
        "hostname": hostname,
    }


def ping_sweep(network_cidr: str, max_workers: int = 50,
               progress_cb: Callable = None) -> list:
    """
    Scan all hosts in a subnet using concurrent ping.
    Returns list of alive hosts.

    Example:
        results = ping_sweep("192.168.1.0/24")
    """
    try:
        network = ipaddress.IPv4Network(network_cidr, strict=False)
    except ValueError as e:
        return [{"error": str(e)}]

    hosts = list(network.hosts())
    if len(hosts) > 1024:
        return [{"error": "Network too large (max /22 = 1022 hosts)"}]

    results    = []
    completed  = 0
    total      = len(hosts)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_host, str(ip)): str(ip) for ip in hosts}

        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            results.append(result)
            completed += 1
            if progress_cb:
                progress_cb(completed, total)

    # Sort by IP address
    results.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
    alive = [r for r in results if r.get("alive")]
    return alive


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """
    TCP connect scan on a single port.
    This is what 'nmap -sT' does — full TCP handshake.
    """
    service = COMMON_PORTS.get(port, "Unknown")
    start   = time.time()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        latency = round((time.time() - start) * 1000, 2)

        if result == 0:
            # Try banner grab
            banner = grab_banner(ip, port)
            return {
                "port":    port,
                "state":   "open",
                "service": service,
                "latency": latency,
                "banner":  banner,
            }
        else:
            return {"port": port, "state": "closed", "service": service}

    except socket.timeout:
        return {"port": port, "state": "filtered", "service": service}
    except Exception:
        return {"port": port, "state": "error", "service": service}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a service banner (version info)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send a probe for HTTP
        if port in (80, 8080, 8443):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

        data = sock.recv(256)
        sock.close()
        return data.decode("utf-8", errors="ignore").strip().split("\n")[0][:80]
    except Exception:
        return None


def port_scan(ip: str, ports: list = None, max_workers: int = 100) -> dict:
    """
    Scan multiple ports on a single host.

    Args:
        ip: Target IP address
        ports: List of ports (default: common ports)
        max_workers: Thread pool size
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x["port"])
    open_ports = [r for r in results if r["state"] == "open"]

    # Try reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = ip

    return {
        "target":     ip,
        "hostname":   hostname,
        "total_ports_scanned": len(ports),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "scan_time":  time.strftime("%Y-%m-%d %H:%M:%S"),
    }
