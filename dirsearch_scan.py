import os
import subprocess
import socket
import requests
from requests.exceptions import RequestException
import concurrent.futures
import threading

print_lock = threading.Lock()

def synchronized_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

def is_website_up(ip_address, port, protocol):
    try:
        url = f"{protocol}://{ip_address}:{port}"
        response = requests.head(url, timeout=5)
        return True
    except RequestException:
        return False

def run_gobuster(ip_address, port, protocol, output_file, colors):
    command = f"sudo gobuster dir -u {protocol}://{ip_address}:{port} -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -s 200,204,301,302,307,401,403 -o {output_file}"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}[-] Gobuster failed with error code {e.returncode}{colors['reset']}")
        return False
    
    with open(output_file, 'r') as f:
        synchronized_print(f.read())

    return True

def dirsearch_scan(ip_address, port, protocol, output_file, colors, extensions):
    command = f"sudo dirsearch -u {protocol}://{ip_address}:{port} -e {extensions} -o {output_file} -format plain --timeout=5 --retries=2"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        synchronized_print(f"\n{colors['red']}[-] Dirsearch failed with error code {e.returncode}{colors['reset']}")
        synchronized_print(f"\n\n\033[1m{colors['yellow']}[>>] Running Gobuster as a backup scanner on {protocol.upper()}...{colors['reset']}\033[0m\n")
        return run_gobuster(ip_address, port, protocol, output_file, colors)

    with open(output_file, 'r') as f:
        synchronized_print(f.read())

    return True

def get_server_type(ip_address, port, protocol):
    try:
        url = f"{protocol}://{ip_address}:{port}"
        response = requests.head(url, timeout=5)
        server = response.headers.get('Server', '').lower()
        return server
    except RequestException:
        return None

def run_dirsearch(ip_address, port, output_dir, colors):
    print(f"\n\n\033[1m{colors['yellow']}[>>] Running Dirsearch{colors['reset']}\033[0m")

    os.makedirs(output_dir, exist_ok=True)

    protocols = ["http", "https"]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for protocol in protocols:
            output_file = os.path.join(output_dir, f'dirsearch_port_{port}_{protocol}.txt')
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            is_alive = is_website_up(ip_address, port, protocol)
            if is_alive:
                server = get_server_type(ip_address, port, protocol)
                synchronized_print(f"\n{colors['green']}[\u2713] Detected server type for {protocol.upper()} on port {port}: {server if server else 'Unknown'}{colors['reset']}")

                # Customize extensions based on server type
                if server and "apache" in server.lower() or "nginx" in server.lower():
                    extensions = "js,txt,html,php,php3,php4,php5,php7,phtml"  # Example for Apache servers
                elif server and "iis" in server.lower():
                    extensions = "js,txt,html,cs,dll,config,cshtml,asp,net,asax,aspx,ascx,ashx,asmx,axd,asp"
                elif server and "python" in server.lower():
                    extensions = "js,txt,html,py,pyc,pyo,pyd,wsgi,log,xml,json,conf,inc,sql,bak"
                elif server and "ruby" in server.lower():
                    extensions = "js,txt,html,rb,erb,rhtml,rake,rails,log,xml,json,conf,inc,sql,bak,yml,gem"                    
                elif server and "node" in server.lower():
                    extensions = "js,txt,html,json,ejs,jade,log,conf,inc,sql,bak,md,yml"
                else:
                    extensions = "php,html,js,txt,html,cs,dll,config,cshtml,asp,net,asax,aspx,ascx,ashx,asmx,axd,asp"

                futures.append(executor.submit(dirsearch_scan, ip_address, port, protocol, output_file, colors, extensions))
            else:
                pass

        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                synchronized_print(f"{colors['red']}[-] An error occurred while scanning: {e}{colors['reset']}")