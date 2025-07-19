import csv
import json
import glob
import os

def find_latest_scan_file():
    scanner_dir = os.path.abspath(os.path.join(os.getcwd(), "..", "wifi_scanner"))
    files = glob.glob(os.path.join(scanner_dir, "scan_output-*.csv"))
    if not files:
        print("No scan_output files found in wifi_scanner/")
        return None
    latest_file = max(files, key=os.path.getctime)
    print(f"[+] Using latest scan file: {latest_file}")
    return latest_file


def load_networks(csv_file):
    networks = []
    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as file:
        lines = file.readlines()

    # Find where the header starts
    header_index = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("BSSID"):
            header_index = i
            break

    if header_index == -1:
        print("Could not find valid CSV header in scan file.")
        return []

    # Use only rows after header
    cleaned_lines = lines[header_index:]
    reader = csv.DictReader(cleaned_lines)

    for row in reader:
        # Skip empty or invalid rows
        essid = row.get(' ESSID') or row.get('ESSID') or ''
        bssid = row.get('BSSID', '')
        if essid.strip() and bssid.count(':') == 5:
            networks.append({
                "ESSID": essid.strip(),
                "BSSID": bssid.strip(),
                "Channel": row.get(' channel', row.get('channel', '')).strip(),
                "Power": row.get(' Power', row.get('Power', '')).strip()
            })

    return networks


def display_networks(networks):
    print("\nAvailable Wi-Fi Networks:\n")
    for i, net in enumerate(networks):
        print(f"[{i}] SSID: {net['ESSID']} | BSSID: {net['BSSID']} | Channel: {net['Channel']} | Signal: {net['Power']} dBm")
    print()

def select_network(networks):
    try:
        index = int(input("Enter the index of the target network to select: "))
        if 0 <= index < len(networks):
            return networks[index]
        else:
            print("Invalid index.")
            return None
    except ValueError:
        print("Invalid input.")
        return None

def save_selection(network, json_file='selected_target.json'):
    with open(json_file, 'w') as file:
        json.dump(network, file, indent=4)
    print(f"\n[+] Target saved to {json_file}")

def main():
    csv_file = find_latest_scan_file()
    if not csv_file:
        return

    networks = load_networks(csv_file)
    if not networks:
        print("No valid networks found in the CSV.")
        return

    display_networks(networks)
    selected = select_network(networks)
    if selected:
        save_selection(selected)

if __name__ == '__main__':
    main()
