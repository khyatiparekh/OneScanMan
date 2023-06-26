# OSCP Enumeration Script
Initial network and web application enumeration script for OSCP and Hack The Box

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
- [Enumeration] ```python main.py enum <IP_ADDRESS_OR_DOMAIN> <OUTPUT_DIRECTORY> <INTERFACE> ```
- [Information] ```python main.py INFO``` 
- [Web Recon] ```python main.py web_recon 'all' '<proxy_url>' '<target_urls_with_path>'``` 
     - Example: ``` python main.py web_recon 'all' 'http://localhost:8080' 'http://192.168.20.29 test_path test_path_1'``` 

## Example:
``` python main.py 10.129.23.55 scan_name tun0 ``` 


