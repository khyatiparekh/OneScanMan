import subprocess
import os

def run_smbmap(ip_address, output_dir, colors):
    command = f"sudo smbmap -H {ip_address} > {output_dir}/smbmap_output.txt"

    try:
        subprocess.run(command, shell=True, check=True)
        with open(f"{output_dir}/smbmap_output.txt", "r") as output_file:
            output = output_file.read()
        print_smbmap_output(output, colors)
        list_accessible_shares(ip_address, output_dir, output, colors)
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}[Failure][Samba Discovery][smbmap][{e}]{colors['reset']}")

def print_smbmap_output(output, colors):
    print(f"\033[1m{colors['yellow']}[Samba Discovery][{colors['cyan']}smbmap{colors['yellow']}]{colors['reset']}\033[0m")

    for line in output.splitlines():
        if "Working on it..." not in line and "Authentication error" not in line and "445 not open" not in line:
            print(line)

def list_accessible_shares(ip_address, output_dir, smbmap_output, colors):
    accessible_shares = []
    special_chars = ['\0', '/', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '{', '}', '[', ']', ':', ';', '\'', '<', '>', '?', ',']

    for line in smbmap_output.splitlines():
        if 'READ' in line or 'WRITE' in line:
            share_name = line.split()[0]
            accessible_shares.append(share_name)

    tmp_share = ""
    for share in accessible_shares:
        tmp_share = share
        for characs in special_chars:
            if characs in tmp_share:
                tmp_share = tmp_share.replace(characs, "")
        list_all_files(ip_address, share, output_dir, colors)

def list_all_files(ip_address, share_name, output_dir, colors):

    output_folder = f"{output_dir}/{share_name}_files"
    os.makedirs(output_folder, exist_ok=True)

    command = f"smbclient //{ip_address}/{share_name} -N -c 'lcd {output_folder}; recurse ON; ls' > {output_dir}/{share_name}_files.txt"

    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}[Failure][Samba Discovery][smbclient][{e}]{colors['reset']}")

    with open(f"{output_dir}/{share_name}_files.txt", "r") as output_file:
        output = output_file.read()

    print(f"{colors['yellow']}[{colors['green']}Discovery{colors['yellow']}][Samba Discovery][{colors['cyan']}smbclient{colors['yellow']}]{colors['green']}[{colors['cyan']}List Files: {colors['red']}{share_name}{colors['yellow']}]{colors['reset']}")
    print(output)

