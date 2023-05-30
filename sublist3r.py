import os
import subprocess

def run_sublist3r(domain, output_file, colors):
    print(f"\n\n\033[1m{colors['yellow']}[#] Running sublist3r{colors['reset']}\033[0m")

    command = f"sublist3r -d {domain} -o {output_file}"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}[-] Sublist3r failed with error code {e.returncode}{colors['reset']}")
        return False
    return True

def run_subdomain_scan(domain, output_file, colors):
    if not run_sublist3r(domain, output_file, colors):
        print(f"{colors['red']}[-] No backup scanner configured for subdomain scanning{colors['reset']}")
