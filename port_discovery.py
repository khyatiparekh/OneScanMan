import os
import subprocess
import re
from utils import is_valid_ipv4

def parse_masscan_output(output):
    open_ports = {}
    for line in output.splitlines():
        match = re.search(r'(\d+)/([a-zA-Z]+)\s+\w+\s+\w+', line)
        if match:
            port = int(match.group(1))
            protocol = match.group(2).lower()
            open_ports[port] = protocol

    return open_ports

def parse_nmap_output(output):
    open_ports = {}
    for line in output.splitlines():
        match = re.search(r'(\d+)/(tcp|udp)\s+open', line)
        if match:
            port = int(match.group(1))
            protocol = match.group(2).lower()
            open_ports[port] = protocol

    return open_ports

def run_nmap(ip_address, output_file, scan_type, colors, timeout=2000):
    command = [f"sudo nmap -p- -sU --min-rate 1000 --open -T4 {ip_address} -oN {output_file}_udp", 
                f"sudo nmap -p- -sS --min-rate 1000 --open -T4 {ip_address} -oN {output_file}_tcp",
                f"sudo nmap -O {ip_address} -oN {output_file}_os"]

    scan_type_u = scan_type.upper()
    if scan_type == "tcp":
        command_run = command[1]
        print(f"\033[1m{colors['yellow']}[Port Discovery][{colors['cyan']}TCP{colors['reset']}\033[1m{colors['yellow']}][{colors['reset']}\033[1m{colors['cyan']}nmap{colors['reset']}\033[1m{colors['yellow']}]{colors['reset']}\033[0m{colors['reset']}\033[0m")
    elif scan_type == "udp":
        command_run = command[0]
        print(f"\033[1m{colors['yellow']}[Port Discovery][{colors['cyan']}UDP{colors['reset']}\033[1m{colors['yellow']}][{colors['reset']}\033[1m{colors['cyan']}nmap{colors['reset']}\033[1m{colors['yellow']}]{colors['reset']}\033[0m{colors['reset']}\033[0m")
    else:
        command_run = command[2]
        print(f"\033[1m{colors['yellow']}[OS Discovery][{colors['cyan']}OS{colors['reset']}\033[1m{colors['yellow']}][{colors['reset']}\033[1m{colors['cyan']}nmap{colors['reset']}\033[1m{colors['yellow']}]{colors['reset']}\033[0m{colors['reset']}\033[0m")

    try:
        output = subprocess.check_output(command_run, shell=True, text=True, timeout=timeout)
        with open(output_file, 'w') as f:
            f.write(output)
        open_ports = parse_nmap_output(output)
        return open_ports
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}[Failure][Port Discovery][{scan_type_u}][nmap][{e}]{colors['reset']}")
        return {}

def run_port_discovery(ip_address, output_file, interface, colors, scan_type, timeout=2000):

    if scan_type == "udp":
        nmap_output_file = output_file.replace("masscan", "nmap_udp")
    else:
        nmap_output_file = output_file.replace("masscan", "nmap_tcp")

    if len(nmap_output_file) == 0:
        pass
    else:
        return run_nmap(ip_address, nmap_output_file, scan_type, colors)

    command = f"sudo masscan {ip_address} -p1-65535,U:1-65535 --wait 0 --rate 1000 -e {interface} > {output_file}"
    print(f"\033[1m{colors['yellow']}[Port Discovery]\033[1m{colors['yellow']}[{colors['reset']}\033[1m{colors['cyan']}masscan{colors['reset']}\033[1m{colors['yellow']}]{colors['reset']}\033[0m{colors['reset']}\033[0m")

    if scan_type == "udp":
        masscan_output_file = output_file.replace("nmap_udp", "masscan_udp")
    else:
        masscan_output_file = output_file.replace("nmap_udp", "masscan_tcp")

    try:
        subprocess.run(command, shell=True, check=True, timeout=timeout)
        with open(masscan_output_file, 'r') as f:
            output = f.read()
        open_ports = parse_masscan_output(output)

        return open_ports
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}[-][Failure][Port Discovery][masscan][{e}]{colors['reset']}")
        return False

