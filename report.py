 import socket
import subprocess
import sys
from datetime import datetime

# Target configuration
TARGET = "127.0.0.1"  # Replace with target IP or domain
PORTS = [21, 22, 25, 80, 443, 3306, 8080]  # Standard services to scan
TIMEOUT = 1.0  # Seconds to wait per socket connection


def check_host_alive(target_ip):
    """Uses subprocess to run a single ping check before scanning."""
    try:
        # Executes 'ping -c 1' on Linux/Mac or 'ping -n 1' on Windows
        param = "-n" if sys.platform.startswith("win") else "-c"
        result = subprocess.run(
            ["ping", param, "1", target_ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"[!] Subprocess ping check failed: {e}")
        return False


def grab_banner(target_ip, port):
    """Attempts to grab service banner string from an open port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((target_ip, port))

        # Send a basic probe for HTTP ports, otherwise listen for initial server banner
        if port in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")

        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner if banner else "No banner response"
    except Exception:
        return "Banner grab timed out/failed"


def scan_target(target_ip, port_list):
    """Scans designated ports and checks for open connections."""
    print(f"[*] Starting scan on target: {target_ip}")
    print(f"[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(f"{'PORT':<10}{'STATE':<10}{'BANNER / VERSION PROBE'}")
    print("-" * 60)

    for port in port_list:
        try:
            # Create a standard TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)

            # Try connecting to port
            result = sock.connect_ex((target_ip, port))

            if result == 0:
                sock.close()
                banner = grab_banner(target_ip, port)
                # Clean multi-line banners for concise display
                clean_banner = banner.split("\n")[0] if banner else "Unknown"
                print(f"{port:<10}{'OPEN':<10}{clean_banner}")
            else:
                sock.close()

        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
            sys.exit()
        except socket.error:
            print(f"[!] Could not connect to host {target_ip}.")
            sys.exit()


if __name__ == "__main__":
    # 1. Verify host reachability via subprocess
    alive = check_host_alive(TARGET)
    print(f"[*] Host Reachability (Ping Check): {'UP' if alive else 'DOWN/BLOCKED'}\n")

    # 2. Run port scan & version extraction
    scan_target(TARGET, PORTS)