# NetToolkit — CCNA Network Tools

A Python-based networking toolkit covering core CCNA concepts:
- Subnet calculation (CIDR, masks, host ranges)
- VLSM (Variable Length Subnet Masking)
- IP membership checking
- Ping sweep (host discovery)
- TCP port scanning with service identification

---

## Skills Practiced

| CCNA Topic | Tool |
|---|---|
| IP Addressing & Subnetting | Subnet Calculator |
| VLSM | VLSM Allocator |
| Network classes, private ranges | Subnet Calculator |
| Host discovery (ICMP) | Ping Sweep |
| TCP/UDP ports, well-known services | Port Scanner |
| DNS resolution | Scanner (hostname lookup) |

---

## Quick Start

### Install dependencies
```bash
pip install flask
```

### CLI mode
```bash
# Subnet info
python main.py subnet 192.168.1.0/24

# VLSM allocation
python main.py vlsm 192.168.1.0/24 50 25 10 5

# Check if IP is in subnet
python main.py check 192.168.1.45 192.168.1.0/26

# Ping sweep a network
python main.py scan 192.168.1.0/24

# Port scan a host (common ports)
python main.py ports 192.168.1.1

# Port scan specific ports
python main.py ports 192.168.1.1 22 80 443 8080
```

### Web Dashboard
```bash
python app.py
# Open http://localhost:5000
```

---

## File Structure

```
network_toolkit/
├── main.py              # CLI entry point
├── app.py               # Web dashboard (Flask)
├── src/
│   ├── subnet_calc.py   # Subnet, VLSM, IP check logic
│   └── scanner.py       # Ping sweep + port scanner
└── README.md
```

---

## How to Make It Your Own

1. Add more port→service mappings in `scanner.py → COMMON_PORTS`
2. Add UDP scanning support (for DNS/DHCP/SNMP)
3. Add OSPF/EIGRP subnet summarization calculator
4. Add traceroute visualization
5. Export results to PDF/CSV report

---

## Requirements

- Python 3.8+
- Flask (only for web dashboard)
- Works on Windows, macOS, Linux
- No root/admin needed for port scanning (TCP connect scan)
- Ping sweep may need admin on some systems

---

## Notes

- Port scanner uses TCP connect scan — no root needed
- Ping sweep uses system `ping` command
- For real networks, replace ping with `scapy` ARP for more reliable LAN discovery
