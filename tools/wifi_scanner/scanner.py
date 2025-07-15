# scanner.py
import os
import time
import subprocess
from utils import enable_monitor_mode, disable_monitor_mode, parse_airodump_csv

INTERFACE = "wlan0"  # Your adapter name (e.g., wlan1 if using USB)
DUMP_PREFIX = "scan_output"
DUMP_FILE = f"{DUMP_PREFIX}-01.csv"

def start_scan(interface):
    print(f"[+] Starting airodump-ng scan on {interface}...")
    subprocess.Popen([
        "sudo", "airodump-ng", "-w", DUMP_PREFIX,
        "--output-format", "csv", interface
    ])
    time.sleep(70)  # Scan duration (can be changed)
    subprocess.call(["sudo", "pkill", "airodump-ng"])  # Stop after scan

def main():
    enable_monitor_mode(INTERFACE)
    start_scan(INTERFACE)

    if os.path.exists(DUMP_FILE):
        networks = parse_airodump_csv(DUMP_FILE)
        print("\n--- Detected Networks ---")
        for i, net in enumerate(networks):
            print(f"{i+1}. SSID: {net['SSID'] or '[Hidden]'} | BSSID: {net['BSSID']} | CH: {net['channel']} | Signal: {net['signal']} | Enc: {net['encryption']}")
    else:
        print("[-] Scan failed. No output file created.")

    disable_monitor_mode(INTERFACE)

if __name__ == "__main__":
    main()
