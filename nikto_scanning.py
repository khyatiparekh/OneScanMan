import os
import subprocess

def run_nikto(ip_address, port, output_file, colors, timeout=900):
    print(f"\n\n\033[1m{colors['yellow']}[>>] Running Nikto{colors['reset']}\033[0m\n")

    command = f"nikto -host {ip_address} -port {port} -output {output_file} -Format csv"
    try:
        subprocess.run(command, shell=True, check=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"{colors['red']}[-] Nikto scanning timed out after {timeout} seconds{colors['reset']}")
    except subprocess.CalledProcessError as e:
        print(f"{colors['red']}[-] Nikto scanning failed with error code {e.returncode}{colors['reset']}")
    return True
