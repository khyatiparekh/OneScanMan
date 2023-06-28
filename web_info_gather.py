import os
import requests
import argparse
import re
import sys
from tldextract import extract
from urlextract import URLExtract
import urllib3
import chardet
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment

colors = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'cyan': '\033[96m',
    'reset': '\033[0m'
}

# setup requests to use a proxy
session = requests.Session()
session.verify = False
session.timeout = 15
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to get all hyperlinks and paths from page
def get_links(url):
    try:
        soup = BeautifulSoup(session.get(url).content, "html.parser")
        for a in soup.findAll('a', href=True):
            href = a['href']
            if href and href != "#":
                yield href
    except Exception as e:
        print(f"{colors['red']}[-] Error fetching links from {url}: {str(e)}\n{colors['reset']}")

# Fetch all domains and email ids from webpage
def fetch_email_and_domain(url):
    try:
        response = session.get(url)
    except Exception as e:
        return [],[]
    encoding = chardet.detect(response.content)['encoding']
    response.encoding = encoding
    text = response.text

    # Regular expression for emails
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,15}\b'

    # Find all matches in the soup.text
    emails = re.findall(email_regex, text)

    extractor = URLExtract()
    urls = extractor.find_urls(text)

    domains = []
    for url in urls:
        tsd, td, tsu = extract(url) # returns subdomain, domain, and suffix
        domains.append(".".join(part for part in [tsd, td, tsu] if part))

    # Unique list
    unique_emails = list(set(emails))
    unique_domains = list(set(domains))

    return unique_emails, unique_domains

# Function to run cewl
def run_cewl(url, ip, path):
   
    print(f"Command: [cewl {url}]\n")
    if path =="/":
        path = ""

    try:
        command = f"cewl {url}"
        os.system(command)
    except Exception as e:
        print(f"{colors['red']}[-] Error running cewl on {url}: {str(e)}\n{colors['reset']}")


# Function to fetch and display contents of important files
def fetch_files(url):
    files = [
        "robots.txt",
        "sitemap_index.xml",
        "sitemap.xml",
        "sitemap-image.xml",
        "sitemap-news.xml",
        "sitemap-video.xml",
        "sitemap-mobile.xml",
        "sitemap-en.xml",
    ]

    for file in files:
        file_url = urljoin(str(url), str(file))
        try:
            response = session.get(file_url)
        except Exception as e:
            continue
        if response.status_code == 200:
            yield (file, response.text)
        elif response.status_code != 404:
            print(f"Error fetching {file} from {url}: HTTP {response.status_code}")

# Function to fetch all comments from webpage
def fetch_comments(url):
    try:
        soup = BeautifulSoup(session.get(url).content, "html.parser")
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        yield from comments
    except Exception as e:
        print(f"{colors['red']}[-] Error fetching comments from {url}: {str(e)}\n{colors['reset']}")

# Function to get the IP from the URL
def get_ip_from_url(url):
    hostname = urlparse(url).hostname
    return hostname

# Main function
def web_recon(url_paths, scans, proxy):
    scans = scans[0]
    result = {}
    for item in url_paths:
        # If protocol not provided, assume its http
        if item.strip().startswith("http") == False:
            item = "http://" + item

        matches = re.match(r'(https?://[^/\s]+)(?:\s+([\w\s]+))?', item)
        if matches:
            url = matches.group(1)
            paths = matches.group(2)
            if paths:
                paths = paths.split()
            else:
                paths = []
            result[url] = result.get(url, []) + paths

    for url in result:
        print(f"\n{colors['cyan']}[Target --> URL:{url}]\n{colors['reset']}")

        ip = get_ip_from_url(url)
        paths = result[url]
        if ip is None:
            continue

        if proxy:
            session.proxies = {
                'http': str(proxy),
                'https': str(proxy),
            }
            try:
                session.get(url)
            except Exception as e:
                if "cannot connect to proxy" in str(e).lower() or "not supported proxy scheme" in str(e).lower():
                    print(f"{colors['red']}\n[-] Error connecting to proxy. Please use following format: (protocol)://(domain):(port)\n{colors['reset']}")
                    sys.exit()

        if "files" in scans or "all" in scans:
            print(f"\n{colors['yellow']}[#] Robot Files for {url}\n{colors['reset']}")

            o_files = dict(fetch_files(url))
            for files in o_files:
                print(f"\n{colors['green']}File: {files}\n{colors['reset']}")
                content = o_files[files]
                print(f"{content}")

        if "/" not in paths:
            paths.append("/")

        for path in paths:
            print(f"\n{colors['cyan']}[PATH:{path}]\n{colors['reset']}")
            url_path = urljoin(url, path)
            output = {}
            if "links" in scans or "all" in scans:
                print(f"\n{colors['yellow']}[#] Get Links{colors['reset']}")
                output["links"] = list(get_links(url_path))
                if len(output["links"]) > 0:
                    links = "\n".join(output["links"])
                    print(f"\n{colors['green']}{links}\n{colors['reset']}")
                else:
                    print("\n")
            if "domains" in scans or "all" in scans:
                print(f"\n{colors['yellow']}[#] Domains [Possible use: Vhosts]\n{colors['reset']}")
                emails, domains = fetch_email_and_domain(url_path)
                print(f"\n{colors['green']}Emails:\n{colors['reset']}")
                for email in emails:
                    print(f"{email}")
                print(f"\n{colors['green']}Domains/IP:\n{colors['reset']}")
                for domain in domains:
                    print(f"{domain}")
            if "comments" in scans or "all" in scans:
                print(f"\n{colors['yellow']}[#] Comments{colors['reset']}")

                output["comments"] = list(fetch_comments(url_path))
                if len(output["comments"]) > 0:
                    comments = "\n".join(output["comments"])
                    print(f"\n{colors['green']}{comments}\n{colors['reset']}")
                else:
                    print("\n")
            if "cewl" in scans or "all" in scans:
                print(f"\n{colors['yellow']}[#] Word List\n{colors['reset']}")
                output["cewl_output"] = run_cewl(url_path, ip, path)                    
            print(f"{colors['red']}\n-------------------------------URL {url}, Path {path} ends here--------------------------------------\n{colors['reset']}")
