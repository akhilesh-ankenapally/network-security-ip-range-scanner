"""
scanner.py - Core IP range parsing and multi-threaded ICMP ping discovery.
Project 3: Network Security IP Range Scanner (Prototype)
"""

import ipaddress
import platform
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Any

# Safe upper limit for rapid college prototype demonstration
MAX_ALLOWED_HOSTS = 256


def parse_ip_range(target: str, max_hosts: int = MAX_ALLOWED_HOSTS) -> List[str]:
    """
    Parses various IP range notations into a sorted list of IP strings.
    Supported formats:
      - CIDR: e.g. 192.168.1.0/28, 10.0.0.0/24
      - Hyphen range: e.g. 192.168.1.1-20 or 192.168.1.1-192.168.1.20
      - Single IP: e.g. 192.168.1.1, 127.0.0.1
    """
    target = target.strip()
    if not target:
        raise ValueError("Please provide an IP address, range, or CIDR subnet.")

    # 1. CIDR notation (e.g. 192.168.1.0/28)
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR subnet '{target}': {e}")

        # Check total addresses
        if network.num_addresses > max_hosts + 2:
            raise ValueError(
                f"CIDR subnet contains {network.num_addresses} addresses. "
                f"Maximum allowed for this prototype is {max_hosts} hosts."
            )

        # /31 and /32 handle specifically, otherwise use usable hosts()
        if network.prefixlen >= 31:
            hosts = [str(ip) for ip in network]
        else:
            hosts = [str(ip) for ip in network.hosts()]

        if not hosts:
            hosts = [str(network.network_address)]

        return hosts

    # 2. Hyphen range notation (e.g. 192.168.1.1-20 or 192.168.1.1-192.168.1.10)
    if "-" in target:
        parts = [p.strip() for p in target.split("-", 1)]
        start_str, end_str = parts[0], parts[1]

        try:
            start_ip = ipaddress.ip_address(start_str)
        except ValueError:
            raise ValueError(f"Invalid starting IP address '{start_str}'.")

        # If end is only an octet number, e.g. "20"
        if end_str.isdigit():
            start_octets = start_str.split(".")
            if len(start_octets) != 4:
                raise ValueError("Hyphen range with last-octet format requires a valid IPv4 address.")
            end_num = int(end_str)
            if end_num < 0 or end_num > 255:
                raise ValueError(f"Last octet '{end_str}' must be between 0 and 255.")
            end_ip_str = f"{start_octets[0]}.{start_octets[1]}.{start_octets[2]}.{end_num}"
            try:
                end_ip = ipaddress.ip_address(end_ip_str)
            except ValueError:
                raise ValueError(f"Invalid constructed ending IP address '{end_ip_str}'.")
        else:
            try:
                end_ip = ipaddress.ip_address(end_str)
            except ValueError:
                raise ValueError(f"Invalid ending IP address '{end_str}'.")

        if start_ip.version != end_ip.version:
            raise ValueError("Start and end IP versions must match.")

        start_int = int(start_ip)
        end_int = int(end_ip)

        if start_int > end_int:
            raise ValueError(f"Starting IP ({start_ip}) cannot be greater than ending IP ({end_ip}).")

        count = end_int - start_int + 1
        if count > max_hosts:
            raise ValueError(
                f"Requested range contains {count} hosts. "
                f"Maximum allowed for this prototype is {max_hosts} hosts."
            )

        hosts = [str(ipaddress.ip_address(i)) for i in range(start_int, end_int + 1)]
        return hosts

    # 3. Single IP address
    try:
        single_ip = ipaddress.ip_address(target)
        return [str(single_ip)]
    except ValueError:
        raise ValueError(f"Invalid IP address or format '{target}'. Use formats like 192.168.1.1, 192.168.1.1-20, or 192.168.1.0/28.")


def ping_host(ip: str, timeout_ms: int = 400) -> Dict[str, Any]:
    """
    Pings a single IP address and returns status ('Active' or 'Inactive')
    and latency in milliseconds if responsive.
    """
    is_windows = platform.system().lower() == "windows"

    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # Unix/Linux/macOS
        timeout_sec = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=(timeout_ms / 1000.0) + 1.2
        )
        output = proc.stdout

        # Verify whether host actually responded
        if proc.returncode == 0:
            # Check for Windows false-positives where local gateway returns 'Destination host unreachable' with code 0
            lowered = output.lower()
            if "unreachable" in lowered or "timed out" in lowered or "could not find host" in lowered:
                return {"ip": ip, "status": "Inactive", "latency_ms": None}

            # Must contain TTL to confirm remote ICMP Echo Reply
            if "ttl=" in lowered:
                # Extract latency
                latency = None
                time_match = re.search(r"time[=<]([0-9.]+)\s*ms", output, re.IGNORECASE)
                if time_match:
                    try:
                        latency = float(time_match.group(1))
                    except ValueError:
                        latency = 0.0
                elif "<1ms" in output:
                    latency = 0.5
                return {"ip": ip, "status": "Active", "latency_ms": latency}

        return {"ip": ip, "status": "Inactive", "latency_ms": None}

    except (subprocess.TimeoutExpired, Exception):
        return {"ip": ip, "status": "Inactive", "latency_ms": None}


def scan_range(target: str, max_workers: int = 32) -> Dict[str, Any]:
    """
    Scans an IP range concurrently and returns aggregated summary and host list.
    """
    start_time = time.time()
    ip_list = parse_ip_range(target)

    if not ip_list:
        raise ValueError("No hosts found to scan.")

    # Concurrently ping hosts
    results_map: Dict[str, Dict[str, Any]] = {}
    worker_count = min(max_workers, max(1, len(ip_list)))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                res = future.result()
                results_map[ip] = res
            except Exception:
                results_map[ip] = {"ip": ip, "status": "Inactive", "latency_ms": None}

    # Maintain original sorted order
    sorted_hosts = [results_map.get(ip, {"ip": ip, "status": "Inactive", "latency_ms": None}) for ip in ip_list]

    active_count = sum(1 for h in sorted_hosts if h["status"] == "Active")
    inactive_count = len(sorted_hosts) - active_count
    elapsed = round(time.time() - start_time, 2)

    return {
        "success": True,
        "target": target,
        "summary": {
            "total": len(sorted_hosts),
            "active": active_count,
            "inactive": inactive_count,
            "duration_seconds": elapsed
        },
        "hosts": sorted_hosts
    }
