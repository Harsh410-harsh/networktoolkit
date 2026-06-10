"""
subnet_calc.py - Subnet Calculator
Covers: IP addressing, CIDR notation, subnetting (CCNA core topic)
"""

import ipaddress
import struct
import socket


def calculate_subnet(ip_cidr: str) -> dict:
    """
    Given an IP/CIDR like '192.168.1.0/24', return full subnet info.
    """
    try:
        network = ipaddress.IPv4Network(ip_cidr, strict=False)
    except ValueError as e:
        return {"error": str(e)}

    hosts = list(network.hosts())
    first_host = str(hosts[0]) if hosts else "N/A"
    last_host  = str(hosts[-1]) if hosts else "N/A"

    # Wildcard mask = inverse of subnet mask
    mask_int     = int(network.netmask)
    wildcard_int = 0xFFFFFFFF ^ mask_int
    wildcard     = socket.inet_ntoa(struct.pack(">I", wildcard_int))

    # Classify network class (CCNA classful concept)
    first_octet = int(str(network.network_address).split(".")[0])
    if 1 <= first_octet <= 126:
        net_class = "Class A  (default mask /8)"
    elif 128 <= first_octet <= 191:
        net_class = "Class B  (default mask /16)"
    elif 192 <= first_octet <= 223:
        net_class = "Class C  (default mask /24)"
    elif 224 <= first_octet <= 239:
        net_class = "Class D  (Multicast)"
    else:
        net_class = "Class E  (Experimental)"

    return {
        "network_address":   str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "subnet_mask":       str(network.netmask),
        "wildcard_mask":     wildcard,
        "prefix_length":     network.prefixlen,
        "total_ips":         network.num_addresses,
        "usable_hosts":      max(network.num_addresses - 2, 0),
        "first_host":        first_host,
        "last_host":         last_host,
        "network_class":     net_class,
        "is_private":        network.is_private,
        "binary_mask":       format(int(network.netmask), "032b"),
        "cidr":              str(network),
    }


def vlsm_subnets(base_network: str, host_requirements: list) -> list:
    """
    VLSM - Variable Length Subnet Masking.
    Given a base network and a list of required host counts,
    return optimally sized subnets (largest-first allocation).

    Example:
        vlsm_subnets("192.168.1.0/24", [50, 25, 10, 5])
    """
    try:
        network = ipaddress.IPv4Network(base_network, strict=False)
    except ValueError as e:
        return [{"error": str(e)}]

    # Sort descending - allocate largest first
    requirements = sorted(enumerate(host_requirements), key=lambda x: x[1], reverse=True)

    results   = [None] * len(host_requirements)
    available = [network]

    for original_idx, hosts_needed in requirements:
        # Find smallest prefix that fits
        needed_prefix = 32
        while (2 ** (32 - needed_prefix) - 2) < hosts_needed and needed_prefix > 0:
            needed_prefix -= 1

        # Find a free block
        allocated = None
        for i, block in enumerate(available):
            if block.prefixlen <= needed_prefix:
                # Carve out a subnet of needed_prefix from this block
                sub = list(block.subnets(new_prefix=needed_prefix))[0]
                allocated = sub
                available.pop(i)
                # Put remaining space back
                remaining = list(block.address_exclude(sub))
                available.extend(remaining)
                available.sort(key=lambda n: n.prefixlen, reverse=True)
                break

        if allocated:
            results[original_idx] = {
                "subnet_index":   original_idx + 1,
                "hosts_required": hosts_needed,
                "subnet":         str(allocated),
                "subnet_mask":    str(allocated.netmask),
                "usable_hosts":   allocated.num_addresses - 2,
                "first_host":     str(list(allocated.hosts())[0]) if list(allocated.hosts()) else "N/A",
                "last_host":      str(list(allocated.hosts())[-1]) if list(allocated.hosts()) else "N/A",
                "broadcast":      str(allocated.broadcast_address),
            }
        else:
            results[original_idx] = {
                "subnet_index":   original_idx + 1,
                "hosts_required": hosts_needed,
                "error":          "Not enough space in base network",
            }

    return results


def ip_in_subnet(ip: str, subnet: str) -> dict:
    """Check if an IP belongs to a given subnet."""
    try:
        host    = ipaddress.IPv4Address(ip)
        network = ipaddress.IPv4Network(subnet, strict=False)
        belongs = host in network
        return {
            "ip":      ip,
            "subnet":  subnet,
            "belongs": belongs,
            "reason":  f"{ip} is {'inside' if belongs else 'outside'} {subnet}",
        }
    except ValueError as e:
        return {"error": str(e)}
