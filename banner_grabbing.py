import socket
import ssl
import subprocess
import http.client

def banner_grabbing_netcat(ip_address, port, timeout):
    try:
        command = f"nc -w {timeout} {ip_address} {port}"
        banner = subprocess.check_output(command, shell=True, text=True, timeout=timeout)
        return banner.strip()
    except subprocess.TimeoutExpired:
        return None
    except subprocess.CalledProcessError as e:
        return None

def get_http_headers(ip_address, port, service):
    try:
        use_ssl = service == 'https'

        if use_ssl:
            conn = http.client.HTTPSConnection(ip_address, port, timeout=10, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip_address, port, timeout=10)

        conn.request("HEAD", "/")
        response = conn.getresponse()
        headers = response.getheaders()
        conn.close()

        header_return = ""
        for header in headers:
            if "server" in header[0].lower():
                return (header[1],)
        return headers
    except Exception as e:
        print(e)
        return None

def banner_grabbing(ip_address, port, colors, services):
    try:
        if port in services:
            banner = get_http_headers(ip_address, port, services[port])
        else:
            with socket.create_connection((ip_address, port), timeout=10) as sock:
                banner = sock.recv(4096).decode(errors='replace')
        return banner
    except Exception as e:
        return banner_grabbing_netcat(ip_address, port, 10)
