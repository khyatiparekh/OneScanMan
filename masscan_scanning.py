import os
import subprocess
import re

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

def run_nmap(ip_address, output_file, colors, timeout=300):
    print(f"\n\n\033[1m{colors['yellow']}[#] Running nmap port scanning{colors['reset']}\033[0m\n")
    
    command = f"sudo nmap -p- --min-rate 1000 --open -T4 {ip_address} -oN {output_file}"

    try:
        output = subprocess.check_output(command, shell=True, text=True, timeout=timeout)
        with open(output_file, 'w') as f:
            f.write(output)
        open_ports = parse_nmap_output(output)
        
        return open_ports
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}[-] Nmap port scanning failed with error code {e.returncode}{colors['reset']}")
        return {}

def run_masscan(ip_address, output_file, interface, colors, timeout=300):
    command = f"sudo masscan {ip_address} -p1-65535,U:1-65535 --wait 0 --rate 1000 -e {interface} > {output_file}"

    print(f"\n\n\033[1m{colors['yellow']}[#] Discovering open Ports{colors['reset']}\033[0m [{command}]\n")

    try:
        subprocess.run(command, shell=True, check=True, timeout=timeout)
        with open(output_file, 'r') as f:
            output = f.read()
        open_ports = parse_masscan_output(output)

        return open_ports
    
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}[-] Masscan failed with error code {e.returncode}. Falling back to nmap for port scanning.{colors['reset']}")
        nmap_output_file = output_file.replace("masscan", "nmap")
        return run_nmap(ip_address, nmap_output_file, colors)

