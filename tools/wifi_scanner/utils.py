# utils.py
import subprocess
import csv

def enable_monitor_mode(interface):
    print(f"[+] Enabling monitor mode on {interface}...")
    subprocess.call(["sudo", "ip", "link", "set", interface, "down"])
    subprocess.call(["sudo", "iw", interface, "set", "monitor", "control"])
    subprocess.call(["sudo", "ip", "link", "set", interface, "up"])

def disable_monitor_mode(interface):
    print(f"[+] Disabling monitor mode on {interface}...")
    subprocess.call(["sudo", "ip", "link", "set", interface, "down"])
    subprocess.call(["sudo", "iw", interface, "set", "managed"])
    subprocess.call(["sudo", "ip", "link", "set", interface, "up"])

def parse_airodump_csv(filename):
    networks = []
    try:
        with open(filename, newline='') as csvfile:
            reader = csv.reader(csvfile)
            reading_networks = True
            for row in reader:
                if len(row) == 0:
                    reading_networks = False
                    continue
                if reading_networks and len(row) >= 14 and row[0] != 'BSSID':
                    try:
                        networks.append({
                            "BSSID": row[0].strip(),
                            "channel": row[3].strip(),
                            "encryption": row[5].strip(),
                            "signal": row[8].strip(),
                            "SSID": row[13].strip()
                        })
                    except IndexError:
                        continue
    except Exception as e:
        print(f"[-] Error reading CSV: {e}")
    return networks
