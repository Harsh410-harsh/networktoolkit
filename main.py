#!/usr/bin/env python3
"""
NetToolkit CLI - CCNA Networking Tools
Usage: python main.py [command] [args]

Commands:
    subnet  <ip/cidr>                   - Subnet calculator
    vlsm    <network> <h1> <h2> ...     - VLSM subnetter
    check   <ip> <subnet>               - Check if IP is in subnet
    scan    <network_cidr>              - Ping sweep
    ports   <ip> [port1 port2 ...]      - Port scanner
"""

import sys
import json
import argparse
from src.subnet_calc import calculate_subnet, vlsm_subnets, ip_in_subnet
from src.scanner import ping_sweep, port_scan, COMMON_PORTS


# ─── Formatting helpers ───────────────────────────────────────────────────────

CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
BOLD    = "\033[1m"
RESET   = "\033[0m"
DIM     = "\033[2m"


def header(title: str):
    width = 60
    print(f"\n{CYAN}{'─' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{CYAN}{'─' * width}{RESET}")


def row(label: str, value, color=""):
    print(f"  {DIM}{label:<24}{RESET}{color}{value}{RESET}")


def binary_mask_visual(binary: str) -> str:
    """Display binary mask with clear network/host split."""
    ones  = binary.count("1")
    zeros = binary.count("0")
    colored = f"{GREEN}{binary[:ones]}{RESET}{RED}{binary[ones:]}{RESET}"
    parts = [binary[i:i+8] for i in range(0, 32, 8)]
    return f"  {'  '.join(parts)}"


# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_subnet(args):
    header(f"Subnet Calculator  →  {args.cidr}")
    result = calculate_subnet(args.cidr)

    if "error" in result:
        print(f"  {RED}Error: {result['error']}{RESET}")
        return

    row("Network Address",   result["network_address"],   GREEN)
    row("Broadcast Address", result["broadcast_address"],  YELLOW)
    row("Subnet Mask",       result["subnet_mask"])
    row("Wildcard Mask",     result["wildcard_mask"])
    row("Prefix Length",     f"/{result['prefix_length']}")
    row("Total IPs",         f"{result['total_ips']:,}")
    row("Usable Hosts",      f"{result['usable_hosts']:,}")
    row("First Host",        result["first_host"],         GREEN)
    row("Last Host",         result["last_host"],          GREEN)
    row("Network Class",     result["network_class"])
    row("Private Network",   "Yes" if result["is_private"] else "No")

    print(f"\n  {DIM}Binary Subnet Mask:{RESET}")
    octets = result["binary_mask"]
    ones   = result["prefix_length"]
    parts  = [octets[i:i+8] for i in range(0, 32, 8)]
    visual = "  ".join(
        f"{GREEN}{p[:max(0, ones - i*8)]}{RESET}{RED}{p[max(0, ones - i*8):]}{RESET}"
        for i, p in enumerate(parts)
    )
    print(f"  {visual}")
    print(f"  {DIM}{'─'*8}  {'─'*8}  {'─'*8}  {'─'*8}{RESET}")
    print(f"  {GREEN}Network bits{RESET}              {RED}Host bits{RESET}\n")


def cmd_vlsm(args):
    hosts = [int(h) for h in args.hosts]
    header(f"VLSM  →  {args.network}  |  Requirements: {hosts}")

    results = vlsm_subnets(args.network, hosts)

    print(f"  {'#':<4} {'Hosts Req':<12} {'Subnet':<20} {'Mask':<18} {'Usable':<10} {'First Host':<18} {'Last Host'}")
    print(f"  {'─'*4} {'─'*12} {'─'*20} {'─'*18} {'─'*10} {'─'*18} {'─'*15}")

    for r in results:
        if "error" in r and "subnet" not in r:
            print(f"  {r['subnet_index']:<4} {r['hosts_required']:<12} {RED}ERROR: {r['error']}{RESET}")
        else:
            print(f"  {r['subnet_index']:<4} {r['hosts_required']:<12} {GREEN}{r['subnet']:<20}{RESET} "
                  f"{r['subnet_mask']:<18} {r['usable_hosts']:<10} {r['first_host']:<18} {r['last_host']}")
    print()


def cmd_check(args):
    header(f"IP Membership Check")
    result = ip_in_subnet(args.ip, args.subnet)

    if "error" in result:
        print(f"  {RED}Error: {result['error']}{RESET}")
        return

    color = GREEN if result["belongs"] else RED
    icon  = "✓" if result["belongs"] else "✗"
    print(f"\n  {color}{BOLD}{icon}  {result['reason']}{RESET}\n")


def cmd_scan(args):
    header(f"Ping Sweep  →  {args.network}")
    print(f"  {DIM}Scanning... (this may take a moment){RESET}\n")

    scanned   = [0]
    from ipaddress import IPv4Network
    try:
        total = len(list(IPv4Network(args.network, strict=False).hosts()))
    except Exception:
        total = "?"

    def progress(done, tot):
        pct = int(done / tot * 40)
        bar = f"[{'█' * pct}{'░' * (40 - pct)}] {done}/{tot}"
        print(f"\r  {bar}", end="", flush=True)

    results = ping_sweep(args.network, progress_cb=progress)
    print()  # newline after progress bar

    if results and "error" in results[0]:
        print(f"  {RED}Error: {results[0]['error']}{RESET}")
        return

    if not results:
        print(f"  {YELLOW}No alive hosts found.{RESET}\n")
        return

    print(f"\n  {GREEN}Found {len(results)} alive host(s):{RESET}\n")
    print(f"  {'IP Address':<18} {'Latency':<12} {'Hostname'}")
    print(f"  {'─'*18} {'─'*12} {'─'*30}")
    for h in results:
        lat = f"{h['latency']}ms" if h.get("latency") else "—"
        hn  = h.get("hostname") or "—"
        print(f"  {GREEN}{h['ip']:<18}{RESET} {lat:<12} {DIM}{hn}{RESET}")
    print()


def cmd_ports(args):
    ports = [int(p) for p in args.ports] if args.ports else None
    port_list_desc = f"{len(ports)} custom ports" if ports else f"{len(COMMON_PORTS)} common ports"
    header(f"Port Scan  →  {args.ip}  ({port_list_desc})")
    print(f"  {DIM}Scanning... {RESET}\n")

    result = port_scan(args.ip, ports)

    row("Target",   result["target"])
    row("Hostname", result["hostname"])
    row("Scanned",  result["total_ports_scanned"])
    row("Open",     result["open_count"], GREEN)
    row("Time",     result["scan_time"])

    if not result["open_ports"]:
        print(f"\n  {YELLOW}No open ports found.{RESET}\n")
        return

    print(f"\n  {'Port':<8} {'State':<10} {'Service':<20} {'Banner'}")
    print(f"  {'─'*8} {'─'*10} {'─'*20} {'─'*40}")
    for p in result["open_ports"]:
        banner = (p.get("banner") or "")[:40]
        print(f"  {GREEN}{p['port']:<8}{RESET} {GREEN}{p['state']:<10}{RESET} "
              f"{p['service']:<20} {DIM}{banner}{RESET}")
    print()


# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="NetToolkit",
        description="CCNA Network Toolkit — Subnet Calculator + Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # subnet
    p1 = sub.add_parser("subnet", help="Subnet calculator")
    p1.add_argument("cidr", help="IP/CIDR e.g. 192.168.1.0/24")

    # vlsm
    p2 = sub.add_parser("vlsm", help="VLSM subnetting")
    p2.add_argument("network", help="Base network e.g. 192.168.1.0/24")
    p2.add_argument("hosts", nargs="+", help="Host requirements e.g. 50 25 10 5")

    # check
    p3 = sub.add_parser("check", help="Check if IP is in subnet")
    p3.add_argument("ip",     help="IP address e.g. 192.168.1.45")
    p3.add_argument("subnet", help="Subnet e.g. 192.168.1.0/26")

    # scan
    p4 = sub.add_parser("scan", help="Ping sweep a subnet")
    p4.add_argument("network", help="Network CIDR e.g. 192.168.1.0/24")

    # ports
    p5 = sub.add_parser("ports", help="Port scan a host")
    p5.add_argument("ip",    help="Target IP")
    p5.add_argument("ports", nargs="*", help="Specific ports (default: common ports)")

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    dispatch = {
        "subnet": cmd_subnet,
        "vlsm":   cmd_vlsm,
        "check":  cmd_check,
        "scan":   cmd_scan,
        "ports":  cmd_ports,
    }

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
