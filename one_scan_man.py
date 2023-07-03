
#!/usr/bin/env python3
import sys
import queue
import os
from smbmap_runner import run_smbmap
import concurrent.futures
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor
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
    if banner != None and len(banner) > 0:
        if isinstance(banner, tuple) and len(banner) == 1:
            banner = banner[0]
            if isinstance(banner, str):
                banner = banner.strip()
        elif isinstance(banner, str):
            banner = banner.strip()
        return f"{colors['yellow']}[{colors['green']}Discovery{colors['yellow']}][Banner][{colors['cyan']}http.client/socket/netcat{colors['yellow']}][{colors['cyan']}{port}{colors['yellow']}]{colors['reset']}[{banner}]"
    else:
        banner = "Banner not found"
        return f"{colors['yellow']}[{colors['green']}Discovery{colors['yellow']}][Banner][{colors['cyan']}http.client/socket/netcat{colors['yellow']}][{colors['cyan']}{port}{colors['yellow']}]{colors['reset']}[{colors['red']}{banner}{colors['reset']}]"

def grab_banners_concurrently(ip_address, open_ports, colors, all_websites, max_workers=10):
    #print(f"\n\033[1m{colors['yellow']}[Banner Discovery]{colors['reset']}\033[0m\n")

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
            print(f"{colors['yellow']}[{colors['green']}Discovery{colors['yellow']}][Web Discovery][{colors['cyan']}Webserver{colors['yellow']}]{colors['reset']}[HTTP][{port}]")
            return (port, "http")
    except Exception as e:
        pass
    return None

def check_https(ip_address, port):
    try:
        if is_website_up(ip_address, port, 'https'):
            print(f"{colors['yellow']}[{colors['green']}Discovery{colors['yellow']}][Web Discovery][{colors['cyan']}Webserver{colors['yellow']}]{colors['reset']}[HTTPS][{port}]")
            return (port, "ssl")
    except Exception as e:
        pass
    return None
   
def scan_services(ip_address, service_to_port_map, output_dir, colors, args):

    for service in ('http', 'ssl'):
        if service in service_to_port_map:
            if service in 'http':
                web_recon(['http://'+ip_address], ['banner,comments,domains,links,files,params'], None, args)
            elif service in 'ssl':
                web_recon(['https://'+ip_address], ['banner,comments,domains,links,files,params'], None, args)
            # Add ffuf for finding vhosts here [Bruteforce]
            for port in service_to_port_map[service]:
                synchronized_print(f"\n\n{colors['yellow']}\033[1m\n[--------] Scanning port: {port} [--------]{colors['reset']}\033[0m")
                run_dirsearch(ip_address, port, output_dir, colors)

def main(scan_type, args):
    output_dir = "./Reports/" + str(args.output_dir)
    target = args.target
    interface = args.interface
    scan_type_u = scan_type.upper()
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        ports_and_protocol = run_port_discovery(ip_address, os.path.join(output_dir, 'masscan.txt'), interface, colors, scan_type)

        open_ports = []
        protocols = {}

        for port, protocol in ports_and_protocol.items():
            open_ports.append(port)
            protocols[port] = protocol

        if open_ports and scan_type != "os":
            open_ports_str = ', '.join(f"{port}/{protocol}" for port, protocol in protocols.items())
            print(f"{colors['yellow']}[{colors['green']}Discovery{colors['yellow']}][{colors['cyan']}{scan_type_u}{colors['yellow']}]{colors['reset']}[{open_ports_str}]")

            all_websites = {}
            with concurrent.futures.ThreadPoolExecutor() as executor:
                #print(f"\033[1m{colors['yellow']}[Web Discovery]{colors['yellow']}[Webservers]{colors['reset']}{colors['reset']}\033[0m")

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

            #print(f"{colors['yellow']}[Banner][{scan_type_u}][{colors['cyan']}http.client/socket/netcat{colors['yellow']}]{colors['reset']}")
            for banner in banners:
                if banner != None:
                    print(banner)

            #print(f"{colors['yellow']}[Banner][{scan_type_u}][{colors['cyan']}nmap{colors['yellow']}]{colors['reset']}")
            for ports in service_banners:
                if len(service_banners[ports]) == 0:
                    service_banners[ports] = "Banner not found"
                    print(f"{colors['yellow']}[{colors['green']}Discovery{colors['yellow']}][Banner][{colors['cyan']}nmap{colors['yellow']}][{colors['cyan']}{scan_type_u}{colors['yellow']}][{colors['cyan']}{ports}{colors['yellow']}]{colors['reset']}[{colors['red']}{service_banners[ports]}{colors['reset']}]")
                else:
                    if isinstance(service_banners[ports], str):
                        banner = service_banners[ports].strip()
                    else:
                        banner = service_banners[ports]
                    print(f"{colors['yellow']}[{colors['green']}Discovery{colors['yellow']}][Banner][{colors['cyan']}nmap{colors['yellow']}][{colors['cyan']}{scan_type_u}{colors['yellow']}][{colors['cyan']}{ports}{colors['yellow']}]{colors['reset']}[{colors['reset']}{banner}]")

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

            # Add ffuf for finding vhosts here [Bruteforce]

            run_nmap(ip_address, open_ports, os.path.join(output_dir, 'nmap_scripts'), colors, service_to_port_map)

            if scan_type == "udp":
                return

            scan_services(ip_address, service_to_port_map, output_dir, colors, args)

            # Run Nikto for detected web servers
            for service in ('http', 'ssl'):
                if service in service_to_port_map:
                    for port in service_to_port_map[service]:
                        run_nikto(ip_address, port, os.path.join(output_dir, f'nikto_port_{port}.txt'), colors)

        else:
            if scan_type != "os" and scan_type != "udp":
                print(f"{colors['red']}[Failure][{scan_type_u}][No open ports detected on {target}]{colors['reset']}")

    except Exception as e:
        print(f"{colors['red']}[Failure][{scan_type_u}][{str(e)}]{colors['reset']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script for web reconnaissance and enumeration.')
    
    subparsers = parser.add_subparsers(dest='command')
    
    enum_parser = subparsers.add_parser('enum', help='Perform enumeration')
    enum_parser.add_argument('--target', '-t', required=True, type=str, help='Target IP address or domain name')
    enum_parser.add_argument('--output_dir', '-o', required=True, type=str, help='Directory to store output')
    enum_parser.add_argument('--interface', '-i', required=True, type=str, help='Interface to use for scanning')

    web_recon_parser = subparsers.add_parser('web_recon', help='Perform web reconnaissance')
    web_recon_parser.add_argument('--scan_type', '-s', required=True, type=str, nargs='+', help='Type of scan to perform. i.e. All, files, links, domains, cewl, comments')
    web_recon_parser.add_argument('--proxy_url', '-p', type=str, help='Proxy URL')
    web_recon_parser.add_argument('--depth', '-d', type=str, help='Recurse Depth')
    web_recon_parser.add_argument('--target_url', '-t', required=True, type=str, nargs='+', help='Target URL with paths. Example: http://target.com/path1 and http://target.com/path2 will be "http://target.com path1 path2"')

    info_parser = subparsers.add_parser('info', help='Display information of important tools')

    args = parser.parse_args()

    if args.command == 'enum':
        target = args.target
        ip_address = target if is_valid_ipv4(target) else target
        ip_address = target
        if ip_address is None:
            print(f"{colors['red']}[-] Invalid IP address or domain name: {target}{colors['reset']}")
            sys.exit(1)        
            
        print(f"\n\n\033[1m{colors['yellow']}[--------] Scanning IP:{colors['reset']}\033[0m \033[1m{colors['cyan']}{ip_address}{colors['reset']}\033[0m \033[1m{colors['yellow']}[--------]{colors['reset']}\033[0m\n")

        scans = ['tcp', 'udp', 'os']

        with ProcessPoolExecutor(max_workers=3) as executor:
            for scan in scans:
                executor.submit(main, scan, args)

    elif args.command == 'web_recon':
        scan_types = [x.lower() for x in args.scan_type]
        if args.depth and int(args.depth) > 30:
            print(f"{colors['red']}\n[-] Max allowed depth is 30\n{colors['reset']}")
            parser.print_help()
            sys.exit()
        web_recon(args.target_url, scan_types, args.proxy_url, args)
    elif args.command == 'info':
        display_info()
    else:
        parser.print_help()
