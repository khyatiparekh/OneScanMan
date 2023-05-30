# OSCP Enumeration Script
Initial network and web application enumeration script for OSCP and Hack The Box

## Prerequisite:
- Run the following commands before executing the script:
    - ``` chmod +x $<project directory>/masscan/bin/masscan ```
    - ``` pip install -r requirements.txt ```
## USAGE: 
- python main.py <IP_ADDRESS_OR_DOMAIN> <OUTPUT_DIRECTORY> <INTERFACE> 
- python main.py INFO

## Example:
``` python main.py 10.129.23.55 scan_name tun0 ``` 

