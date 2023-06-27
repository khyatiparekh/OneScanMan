# AutoEnum
All it takes is one serious scan. (Initial network enumeration script for CTFs. Created with HTB and OSCP in mind.)

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

Enum
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
```
usage: one_scan_man.py web_recon [-h] --scan_type SCAN_TYPE [SCAN_TYPE ...] --proxy_url PROXY_URL --target_url TARGET_URL [TARGET_URL ...]

options:
  -h, --help            show this help message and exit
  --scan_type SCAN_TYPE [SCAN_TYPE ...], -s SCAN_TYPE [SCAN_TYPE ...]
                        Type of scan to perform. i.e. All, files, links, domains, cewl, comments
  --proxy_url PROXY_URL, -p PROXY_URL
                        Proxy URL
  --target_url TARGET_URL [TARGET_URL ...], -t TARGET_URL [TARGET_URL ...]
                        Target URL with paths. Example: http://target.com/path1 and http://target.com/path2 will be "http://target.com path1 path2"
```

Info
```
usage: one_scan_man.py info [-h]

options:
  -h, --help  show this help message and exit
```

## Example:
```python one_scan_man.py enum -t 192.168.203.50 -o 192.168.203.50 -i tun0```

```python one_scan_man.py web_recon -s All -p http://localhost:8080 -u "http://192.168.203.50 test1 test2"'``` 

```python one_scan_man.py info```



