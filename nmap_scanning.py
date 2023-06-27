import os
import subprocess
import nmap  
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanning_animation import scanning_animation

service_to_nse_scripts = {
    'http': [
        "http-title",
        "http-passwd",
        "http-enum",
        "http-vhosts",
        "http-methods",
        "http-shellshock",
        "http-sql-injection",
        "http-default-accounts",
        "http-php-version",
        "http-git",
        "http-gitweb-projects-enum",
        "http-robots.txt",
        "http-userdir-enum",
        "http-wordpress-enum",
        "http-wordpress-users",
        "http-iis-webdav-vuln",
        "http-webdav-scan",
        "http-frontpage-login"
    ],
    'ssl': [
        'ssl-cert',
        'ssl-heartbleed',
        'ssl-known-key',
        'ssl-poodle',
        'ssl-ccs-injection',
        'ssl-enum-ciphers', 
        'sslv2',
        'tls-ticketbleed',
    ],
    'smb': [
        'smb-enum-domains',
        'smb-enum-groups',
        'smb-enum-shares',
        'smb-enum-users',
        'smb-os-discovery',
        'smb-protocols',
        'smb-security-mode',
        'smb-vuln-ms08-067',
        'smb-vuln-ms17-010'
    ],
    'smtp': [
        'smtp-commands',
        'smtp-enum-users',
        'smtp-vuln-cve2010-4344',
        'smtp-vuln-cve2011-1720',
        'smtp-vuln-cve2011-1764'
    ],
    'ftp': [
        'ftp-anon',
        'ftp-bounce',
        'ftp-libopie',
        'ftp-proftpd-backdoor',
        'ftp-vsftpd-backdoor',
        'ftp-vuln-cve2010-4221'
    ],
    'ssh': [
        'ssh-hostkey',
        'ssh2-enum-algos',
        'ssh-run',
        'ssh-auth-methods',
        'ssh-publickey-acceptance',
        'sshv1',
    ],
    'mssql': [
        'ms-sql-info',
        'ms-sql-config',
        'ms-sql-dump-hashes',
        'ms-sql-empty-password',
        'ms-sql-hasdbaccess',
        'ms-sql-tables',
        'ms-sql-xp-cmdshell'
    ],
    'mysql': [
        'mysql-audit', 
        'mysql-enum', 
        'mysql-dump-hashes', 
        'mysql-empty-password', 
        'mysql-brute', 
        'mysql-users', 
        'mysql-variables', 
        'mysql-vuln-cve2012-2122',
        'mysql-info',
        'mysql-query'
    ]

}


service_name_mapping = {
    # SMB
    'msrpc': 'smb',
    'microsoft-ds': 'smb',
    'netbios-ssn': 'smb',

    # HTTP
    'http-proxy': 'http',
    'http-alt': 'http',
    'http-api': 'http',
    'www': 'http',
    'http-wmap': 'http',
    'http-mgmt': 'http',

    # SSL
    'https': 'ssl',
    'ssl/http': 'ssl',
    'ssl/imap': 'ssl',
    'ssl/pop3': 'ssl',
    'ssl/smtp': 'ssl',
    'tls/http': 'ssl',
    'ssl/ldap': 'ssl',
    'ssl/ftp': 'ssl',

    # SSH
    'ssh-proxy': 'ssh',
    'ssh-socks': 'ssh',

    # FTP
    'ftp-proxy': 'ftp',
    'ftp-data': 'ftp',
    'ftps': 'ftp',
    'ftp-ssl': 'ftp',

    # SMTP
    'smtp-proxy': 'smtp',
    'submission': 'smtp',
    'smtps': 'smtp',
    'smtp-ssl': 'smtp',

    # MSSQL
    'ms-sql-s': 'mssql',
    'ms-sql-m': 'mssql',

    # MySQL
    'mysql': 'mysql',
    'mysqld': 'mysql',
    'mysql-proxy': 'mysql',
}
    
def get_service_to_port_map(ip_address, open_ports, colors):

    nm = nmap.PortScanner()
    service_to_port_map = {}
    service_banners = {}

    tcp_ports = [str(port) for port, protocol in open_ports.items() if protocol == "tcp"]
    udp_ports = [str(port) for port, protocol in open_ports.items() if protocol == "udp"]
    unknown_protocols = [f"{protocol} for port {port}" for port, protocol in open_ports.items() if protocol not in ["tcp", "udp"]]

    if tcp_ports:
        arguments = "-sV -sT"
        command = f"sudo nmap {ip_address} -p {','.join(tcp_ports)} {arguments}"
        print(f"\n\033[1m{colors['yellow']}[#] Detecting Services on open {colors['cyan']}TCP {colors['reset']}{colors['yellow']}ports {colors['reset']}\033[0m [{command}]")
        nm.scan(ip_address, ','.join(tcp_ports), arguments=arguments)
        service_to_port_map, service_banners = collect_services(nm, service_to_port_map, service_banners)

    if udp_ports:
        arguments = "-sV -sU"
        command = f"sudo nmap {ip_address} -p {','.join(udp_ports)} {arguments}"
        print(f"\n\033[1m{colors['yellow']}[#] Detecting Services on open {colors['cyan']}UDP {colors['reset']}{colors['yellow']}ports {colors['reset']}\033[0m [{command}]")
        nm.scan(ip_address, ','.join(udp_ports), arguments=arguments)
        service_to_port_map, service_banners = collect_services(nm, service_to_port_map, service_banners)

    for protocol in unknown_protocols:
        print(f"{colors['red']}[-] Invalid {protocol}{colors['reset']}")

    return service_to_port_map, service_banners

def collect_services(nm, service_to_port_map, service_banners):
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for scanned_port in nm[host][proto].keys():
                service = nm[host][proto][scanned_port]['name']
                banner = nm[host][proto][scanned_port]['product']
                service_banners[scanned_port] = banner
                mapped_service = next((value for key, value in service_name_mapping.items() if key.lower() in service.lower() or service.lower() in key.lower()), service)
                if mapped_service in service_to_nse_scripts:
                    if mapped_service not in service_to_port_map:
                        service_to_port_map[mapped_service] = []
                    service_to_port_map[mapped_service].append(scanned_port)
    return service_to_port_map, service_banners


def run_nmap_scripts_on_port(ip_address, port, scripts, colors, retries=3):
    command = f"sudo nmap -n -Pn -T4 -p{port} --script {','.join(scripts)} {ip_address}"
    for i in range(retries):
        try:
            output = subprocess.check_output(command, shell=True, text=True)
            break
        except subprocess.CalledProcessError as e:
            print(f"{colors['red']}[-] Nmap scripts {scripts} on port {port} failed with error code {e.returncode}{colors['reset']}\n")
            print(f"{colors['yellow']}Retrying {i + 1}/{retries}{colors['reset']}")
            output = None
    return output

def run_nmap(ip_address, open_ports, output_dir, colors, service_to_port_map):
    print(f"\n\033[1m{colors['yellow']}[#] Enumerating the open ports{colors['reset']}\033[0m [sudo nmap -n -Pn -T4 -p<insert_port_here> --script <insert_script_names_here> {ip_address}]\n")

    stop_animation_event = threading.Event()
    animation_thread = threading.Thread(target=scanning_animation, args=(stop_animation_event,))
    animation_thread.start()

    os.makedirs(output_dir, exist_ok=True)

    with ThreadPoolExecutor(max_workers=10) as executor:

        futures = {}
        for service, ports in service_to_port_map.items():

            nse_scripts = service_to_nse_scripts[service]
            for port in ports:
                print(f"{colors['yellow']}\r\x1b[K[*] Scanning:{colors['reset']} Port {port}, Scripts {nse_scripts}")

                future = executor.submit(run_nmap_scripts_on_port, ip_address, port, nse_scripts, colors)
                futures[future] = (port, nse_scripts)

        for future in as_completed(futures):
            port, scripts = futures[future]
            output = future.result()
            if output is not None:
                # Combine the outputs of all scripts related to a port into a single file
                output_file = os.path.join(output_dir, f"port_{port}_scripts_output.txt")
                with open(output_file, 'a') as f:
                    f.write(f"Port {port} - Scripts: {scripts}\n")
                    f.write(output)
                    f.write("\n\n\n" + "=" * 80 + "\n\n")

            print(f"{colors['green']}\r\x1b[K[\u2713] Completed:{colors['reset']} Port {port}, Scripts {scripts}")

    stop_animation_event.set()
    animation_thread.join()
