import subprocess
import threading

print_lock = threading.Lock()

def run_testssl(ip_address, port, output_file, colors):
    command = ["testssl", "--logfile", output_file, "--append", f"{ip_address}:{port}"]
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Output:\n{e.output}")
        print(f"{colors['red']}[-] testssl failed with error code {e.returncode}{colors['reset']}")
        return False

    with open(output_file, 'r') as f:
        print(f.read())

    return True

def run_ssl_scan(ip_address, port, output_file, colors):
    print(f"\n\n\033[1m{colors['yellow']}[>>] Running SSL Scan{colors['reset']}\033[0m")

