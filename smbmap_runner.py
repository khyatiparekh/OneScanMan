import subprocess
import os

def run_smbmap(ip_address, output_dir, colors):
    command = f"sudo smbmap -H {ip_address} > {output_dir}/smbmap_output.txt"

    print(f"\n\033[1m{colors['yellow']}[#] Running {colors['cyan']}smbmap{colors['reset']}{colors['reset']}\033[0m [{command}]\n")

    try:
        subprocess.run(command, shell=True, check=True)
        with open(f"{output_dir}/smbmap_output.txt", "r") as output_file:
            output = output_file.read()
        print_smbmap_output(output, colors)
        list_accessible_shares(ip_address, output_dir, output, colors)
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}\n[-] smbmap failed with error code {e.returncode}\nError message: {e.output}{colors['reset']}")

def print_smbmap_output(output, colors):
    print(f"{colors['yellow']}[*] smbmap output:{colors['reset']}")
    for line in output.splitlines():
        if "Working on it..." not in line:
            print(line)

def list_accessible_shares(ip_address, output_dir, smbmap_output, colors):
    accessible_shares = []

    for line in smbmap_output.splitlines():
        if 'READ' in line or 'WRITE' in line:
            share_name = line.split()[0]
            accessible_shares.append(share_name)

    for share in accessible_shares:
        command = f"sudo smbmap -R {share} -H {ip_address} > {output_dir}/{share}_files.txt"
        subprocess.run(command, shell=True, check=True)

        with open(f"{output_dir}/{share}_files.txt", "r") as output_file:
            output = output_file.read()
        print(f"{colors['yellow']}\n[*] Files in {share}:{colors['reset']}")
        for line in output.splitlines():
            if "Working on it..." not in line:
                print(line)

        download_files(ip_address, output_dir, share, colors)

def download_files(ip_address, output_dir, share_name, colors):
    print(f"{colors['yellow']}\n[*] Downloading files for share {share_name}:{colors['reset']}")

    output_folder = f"{output_dir}/smbmap_{share_name}-share_downloaded"
    os.makedirs(output_folder, exist_ok=True)

    command = f"smbclient //{ip_address}/{share_name} -N -c 'prompt OFF; recurse ON; lcd {output_folder}; mget *'"
    subprocess.run(command, shell=True, check=True)

