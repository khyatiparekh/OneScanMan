import socket
import ipaddress
import re

def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

# def is_valid_domain(domain):
#     if len(domain) > 255:
#         return False
#     if domain[-1] == ".":
#         domain = domain[:-1]
#     allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
#     return all(allowed.match(x) for x in domain.split("."))

def get_ip_from_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None
