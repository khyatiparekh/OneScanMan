#!/usr/bin/env python3
import sys
import queue
import os
from smbmap_runner import run_smbmap
import concurrent.futures
import threading
from concurrent.futures import ThreadPoolExecutor
from port_discovery import run_port_discovery
from nmap_scanning import run_nmap, get_service_to_port_map
from dirsearch_scan import run_dirsearch
from nikto_scanning import run_nikto
from banner_grabbing import banner_grabbing
from ssl_scan import run_ssl_scan
from utils import get_ip_from_domain, is_valid_ipv4
from web_info_gather import web_recon
import requests
import urllib3
import argparse
from constants import all_tools

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print_lock = threading.Lock()

colors = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'cyan': '\033[96m',
    'reset': '\033[0m'
}

def synchronized_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

def display_info():
    print("-----------------------------------------------------------------------------------------------------------------")
    print(f"\n{colors['cyan']}[#] Tools of importance\n{colors['reset']}")
    print("-----------------------------------------------------------------------------------------------------------------")

    for sections in all_tools:
        print(f"\n{colors['cyan']}", sections, f"{colors['reset']}")

        for tools in all_tools[sections]:
            print(f"   {colors['yellow']}", tools, f": \n{colors['reset']}       {colors['red']}Description:{colors['reset']} {colors['green']}", all_tools[sections][tools]['description'], f"{colors['reset']}\n       {colors['red']}Command:{colors['reset']} {colors['green']}", all_tools[sections][tools]['command'], f"{colors['reset']}\n")

def grab_banner_for_port(args):
    ip_address, port, colors, all_websites = args
    banner = banner_grabbing(ip_address, port, colors, all_websites)
    if banner:
        return f"{colors['green']}[\u2713] Banner for port {port}:{colors['reset']} {banner}"
    else:
        return f"{colors['red']}[-] No banner received for{colors['reset']} port {port}"

def grab_banners_concurrently(ip_address, open_ports, colors, all_websites, max_workers=10):
    print(f"\n\033[1m{colors['yellow']}[#] Banner Grabbing{colors['reset']}\033[0m\n")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = executor.map(grab_banner_for_port, [(ip_address, port, colors, all_websites) for port in open_ports])
        for future in futures:
            results.append(future)

    return results

def is_website_up(ip_address, port, protocol):
    try:
        url = f"{protocol}://{ip_address}:{port}"
        requests.head(url, timeout=5, verify=False)
        return True
    except Exception as e:
        return False
   
def check_http(ip_address, port):
    try:
        if is_website_up(ip_address, port, 'http'):
            print(f"{colors['green']}[\u2713] Webserver Detected:{colors['reset']} -http- {port}")
            return (port, "http")
    except Exception as e:
        pass
    return None

def check_https(ip_address, port):
    try:
        if is_website_up(ip_address, port, 'https'):
            print(f"{colors['green']}[\u2713] Webserver Detected:{colors['reset']} {colors['cyan']}-https-{colors['reset']} {port}")
            return (port, "ssl")
    except Exception as e:
        pass
    return None
   
def scan_services(ip_address, service_to_port_map, output_dir, colors):

    for service in ('http', 'ssl'):
        if service in service_to_port_map:
            for port in service_to_port_map[service]:
                synchronized_print(f"\n\n{colors['yellow']}\033[1m\n[--------] Scanning port: {port} [--------]{colors['reset']}\033[0m")
                run_dirsearch(ip_address, port, output_dir, colors)

def main(args):
    target = args.target
    output_dir = "./Reports/" + str(args.output_dir)
    interface = args.interface
       
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    ip_address = target if is_valid_ipv4(target) else target
    ip_address = target
    if ip_address is None:
        print(f"{colors['red']}[-] Invalid IP address or domain name: {target}{colors['reset']}")
        sys.exit(1)

    print(f"\n\n\033[1m{colors['yellow']}[--------] Scanning IP:{colors['reset']}\033[0m \033[1m{colors['cyan']}{ip_address}{colors['reset']}\033[0m \033[1m{colors['yellow']}[--------]{colors['reset']}\033[0m")

    try:
        ports_and_protocol = run_port_discovery(ip_address, os.path.join(output_dir, 'masscan.txt'), interface, colors)

        open_ports = []
        protocols = {}

        for port, protocol in ports_and_protocol.items():
            open_ports.append(port)
            protocols[port] = protocol

        if open_ports:
            open_ports_str = ', '.join(f"{port}/{protocol}" for port, protocol in protocols.items())
            print(f"{colors['green']}[\u2713] Discovered open ports:{colors['reset']} {open_ports_str}")

            all_websites = {}
            with concurrent.futures.ThreadPoolExecutor() as executor:
                print(f"\n\033[1m{colors['yellow']}[#] Checking for {colors['yellow']}webservers{colors['reset']} {colors['reset']}\033[0m\n")

                futures_http = {executor.submit(check_http, ip_address, port): port for port in open_ports}
                futures_https = {executor.submit(check_https, ip_address, port): port for port in open_ports}

                for future in concurrent.futures.as_completed(futures_http):
                    result = future.result()
                    if result:
                        all_websites[result[0]] = result[1]

                for future in concurrent.futures.as_completed(futures_https):
                    result = future.result()
                    if result:
                        all_websites[result[0]] = result[1]

            service_to_port_map, service_banners = get_service_to_port_map(ip_address, protocols, colors)

            # Banner grabbing for all open ports
            banners = grab_banners_concurrently(ip_address, open_ports, colors, all_websites)

            print(f"{colors['yellow']}[*] Method 1 output [{colors['cyan']}http.client/netcat{colors['reset']}{colors['yellow']}]:{colors['reset']}")
            for banner in banners:
                print(banner)

            print(f"\n{colors['yellow']}[*] Method 2 output [{colors['cyan']}nmap{colors['reset']}{colors['yellow']}]:{colors['reset']}")
            for ports in service_banners:
                print(f"{colors['green']}[\u2713] Banner for port {colors['cyan']}{ports}{colors['reset']}{colors['yellow']}:{colors['reset']} {service_banners[ports]}")

            service_names = list(service_to_port_map.keys())

            for service_name in service_names:
                for port, service in all_websites.items():
                    if port in service_to_port_map[service_name]:
                        if service == service_name:
                            pass
                        else:
                            service_to_port_map[service_name].remove(port)

                            if service in service_to_port_map:
                                service_to_port_map[service].append(port)
                            else:
                                service_to_port_map[service] = [port]
                    else:
                        if service in service_to_port_map:
                            service_to_port_map[service].append(port)
                        else:
                            service_to_port_map[service] = [port]

                    if port in all_websites:
                        service = all_websites[port]
                       
            service_to_port_map = {service: list(set(ports)) for service, ports in service_to_port_map.items()}

            # Run smbmap if the service is netbios-ssn or microsoft-ds
            if 'smb' in service_to_port_map:
                smbmap_output = run_smbmap(ip_address, output_dir, colors)

                if smbmap_output:
                    with open(os.path.join(output_dir, "smbmap_output.txt"), 'w') as f:
                        f.write(smbmap_output)
                    print(smbmap_output)
                   
            # Add fuff for finding vhosts here [Bruteforce]

            run_nmap(ip_address, open_ports, os.path.join(output_dir, 'nmap_scripts'), colors, service_to_port_map)

            scan_services(ip_address, service_to_port_map, output_dir, colors)

            # Run Nikto for detected web servers
            for service in ('http', 'ssl'):
                if service in service_to_port_map:
                    for port in service_to_port_map[service]:
                        run_nikto(ip_address, port, os.path.join(output_dir, f'nikto_port_{port}.txt'), colors)

        else:
            print(f"{colors['red']}[-] No open ports detected on {target}{colors['reset']}")

    except Exception as e:
        print(f"\n{colors['red']}Error: {str(e)}{colors['reset']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script for web reconnaissance and enumeration.')
    
    subparsers = parser.add_subparsers(dest='command')
    
    enum_parser = subparsers.add_parser('enum', help='Perform enumeration')
    enum_parser.add_argument('--target', '-t', required=True, type=str, help='Target IP address or domain name')
    enum_parser.add_argument('--output_dir', '-o', required=True, type=str, help='Directory to store output')
    enum_parser.add_argument('--interface', '-i', required=True, type=str, help='Interface to use for scanning')

    web_recon_parser = subparsers.add_parser('web_recon', help='Perform web reconnaissance')
    web_recon_parser.add_argument('--scan_type', '-s', required=True, type=str, nargs='+', help='Type of scan to perform. i.e. All, files, links, domains, cewl, comments')
    web_recon_parser.add_argument('--proxy_url', '-p', required=True, type=str, help='Proxy URL')
    web_recon_parser.add_argument('--target_url', '-t', required=True, type=str, nargs='+', help='Target URL with paths. Example: http://target.com/path1 and http://target.com/path2 will be "http://target.com path1 path2"')

    info_parser = subparsers.add_parser('info', help='Display information of important tools')

    args = parser.parse_args()

    if args.command == 'enum':
        main(args)
    elif args.command == 'web_recon':
        scan_types = [x.lower() for x in args.scan_type]
        web_recon(args.target_url, scan_types, args.proxy_url)
    elif args.command == 'info':
        display_info()
    else:
        parser.print_help()
