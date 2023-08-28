# OneScanMan
All it takes is one normal scan. (Initial network enumeration script for CTFs. Created with HTB and OSCP in mind.)

![main-qimg-53c69fa4bdd51f447dce1f43a4522ade-lq](https://github.com/khyatiparekh/OneScanMan/assets/3457866/3735b8e0-bcbd-474f-8976-4832425ea420)

## Setup Virtual Environment
### Install virtualenv
```pip install virtualenv```

### Create a virtual environment
```virtualenv Enum```

### Activate the virtual environment
```source Enum/bin/activate```

## Prerequisite:
- Run the following commands before executing the script:
    - ``` pip install -r requirements.txt ```
    - ``` sudo apt-get install dirsearch gobuster ```
 
## USAGE: 
```
usage: one_scan_man.py [-h] {enum,web_recon,info} ...

Script for web reconnaissance and enumeration.

positional arguments:
  {enum,web_recon,info}
    enum                Perform enumeration.
    web_recon           Perform web reconnaissance.
    info                Display information of important tools

options:
  -h, --help            show this help message and exit
```

# Features
Enumeration
- Performs network enumeration using the following tools:
     - nmap/masscan
     - dirsearch/gobuster
     - nikto
     - smbmap
     - smbclient
- Performs the following tasks:
     - Port Discovery
     - Service Discovery
     - Banner Grabbing
     - Samba Enumeration
     - nmap script scanning
     - Directory brute force
     - Web application Enumeration
          - Run Nikto
          - Scrape webpage to find the following:
               - Links
               - Robot files
               - Parameters in URL's present within the webpage
               - Domains
               - Comments
               - Banner
```
usage: one_scan_man.py enum [-h] --target TARGET --output_dir OUTPUT_DIR --interface INTERFACE

options:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        Target IP address or domain name
  --output_dir OUTPUT_DIR, -o OUTPUT_DIR
                        Directory to store output
  --interface INTERFACE, -i INTERFACE
                        Interface to use for scanning
```

           
Web Recon
- Performs the following tasks:
   - Extract Links
   - Discover Robot files
   - Extract Parameters in URL's present within the webpage
   - Extract Cookies
   - Extract Domains
   - Extract Comments
   - Discover Banner
   - Run Gobuster
   - Run cewl to create wordlist from webpage
   - Run nmap known http recon scripts
```
usage: one_scan_man.py web_recon [-h] --scan_type SCAN_TYPE [SCAN_TYPE ...] [--proxy_url PROXY_URL] [--depth DEPTH] [--cookies COOKIES] --target_url TARGET_URL [TARGET_URL ...]

options:
  -h, --help            show this help message and exit
  --scan_type SCAN_TYPE [SCAN_TYPE ...], -s SCAN_TYPE [SCAN_TYPE ...]
                        Type of scan to perform: All, files, params, cookies, links, domains, cewl, comments, banner, dirbust
  --proxy_url PROXY_URL, -p PROXY_URL
                        Proxy URL
  --depth DEPTH, -d DEPTH
                        Recurse Depth
  --cookies COOKIES, -c COOKIES
                        Cookies
  --target_url TARGET_URL [TARGET_URL ...], -t TARGET_URL [TARGET_URL ...]
                        Target URL with paths. Example: http://target.com/path1 and http://target.com/path2 will be "http://target.com path1 path2"
```

Info
- Lists information about important tools and their basic usage.
```
usage: one_scan_man.py info [-h]

options:
  -h, --help  show this help message and exit
```  

## Example:
```python one_scan_man.py enum -t 192.168.203.50 -o 192.168.203.50 -i tun0```

```python one_scan_man.py web_recon -s All -p http://localhost:8080 -u "http://192.168.203.50 test1 test2"'``` 

```python one_scan_man.py info```



