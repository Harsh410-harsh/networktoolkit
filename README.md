# NetToolkit — Network Tools for CCNA Students
A simple Python project that helps you learn and practice networking concepts used in CCNA.
No complicated setup — just run and use!

## What Does This Project Do?
This tool helps you:

Calculate subnet details (mask, hosts, broadcast address)
Split one network into smaller subnets (VLSM)
Check if an IP address belongs to a subnet
Find all active devices on your network (Ping Sweep)
Check which ports are open on a device (Port Scanner)


##  Requirements

Python 3.8 or higher
Flask (only for the web dashboard)

Install Flask:
pip install flask

#  How to Run

## Option 1 — Command Line (Terminal)
  Open terminal in the project folder and run:
  python main.py subnet 192.168.1.0/24
  
## Option 2 — Web Dashboard (Browser)
    python app.py
   Then open your browser and go to: http://127.0.0.1:5000

# Commands — Simple Examples

## 1. Subnet Calculator
Find all details about a network.
python main.py subnet 192.168.1.0/24
What you get: Network address, broadcast address, subnet mask, how many hosts, first and last IP, etc.

## 2. VLSM — Split a Network
Divide one big network into smaller pieces based on how many devices you need.
python main.py vlsm 192.168.1.0/24 50 25 10 5
This splits 192.168.1.0/24 into 4 subnets:

First subnet for 50 devices
Second subnet for 25 devices
Third subnet for 10 devices
Fourth subnet for 5 devices


## 3. IP Check
Check if an IP address is inside a subnet or not.
python main.py check 192.168.1.100 192.168.1.0/26
Output: ✓ (inside) or ✗ (outside)

## 4. Ping Sweep
Find all active/online devices in your network.
python main.py scan 192.168.1.0/24
Shows a list of all devices that responded to ping.

## 5. Port Scanner
Check which ports are open on a device.
python main.py ports 192.168.1.1
Scans common ports like 22 (SSH), 80 (HTTP), 443 (HTTPS), etc.

# Project Structure
networktoolkit/
│
├── main.py            → Run commands from terminal
├── app.py             → Web dashboard
│
├── src/
│   ├── subnet_calc.py → Subnet, VLSM, IP check logic
│   └── scanner.py     → Ping sweep and port scanner
│
└── README.md          → This file

## CCNA Topics Covered
This ToolCCNA TopicSubnet CalculatorIP Addressing, SubnettingVLSM (Variable Length Subnet) MaskingIP CheckSubnetting MathPing SweepICMP, Host DiscoveryPort ScannerTCP Ports, Well-Known Services

##  Built With

Python 3 — Main programming language
Flask — For the web dashboard
ipaddress — Python built-in library for networking
socket — Python built-in library for port scanning


# Author
Harsh — github.com/Harsh410-harsh
Made as a learning project while studying CCNA networking concepts.

# License
Free to use for learning and practice.
