import subprocess
import json
from datetime import datetime

def save_output(filename, data):
    with open(filename, "w") as f:
        f.write(data)

def save_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def ping_sweep(target):
    print(f"\n[+] Running Ping Sweep on {target}...")
    output = subprocess.check_output(["nmap", "-sn", target], text=True)
    save_output("ping_sweep_raw.txt", output)

    alive_hosts = []
    for line in output.splitlines():
        if "Nmap scan report for" in line:
            ip = line.split()[-1]
            alive_hosts.append(ip)

    save_json("ping_sweep_results.json", alive_hosts)
    print(f"[+] Found {len(alive_hosts)} alive hosts. Saved to ping_sweep_results.json ✅")

def basic_port_scan(target):
    print(f"\n[+] Running Basic Port Scan on {target}...")
    output = subprocess.check_output(["nmap", "-sS", "-Pn", target], text=True)
    save_output("basic_port_scan_raw.txt", output)
    print(f"[+] ✅ Basic Port Scan Completed. Raw output saved to basic_port_scan_raw.txt")

def full_port_scan(target):
    print(f"\n[+] Running Full Port Scan on {target}...")
    output = subprocess.check_output(["nmap", "-p-", "-Pn", target], text=True)
    save_output("full_port_scan_raw.txt", output)
    print(f"[+] ✅ Full Port Scan Completed. Raw output saved to full_port_scan_raw.txt")

def main():
    print("\n🟣 Network Discovery Tool 🟣")
    target = input("Enter target range (e.g., 192.168.1.0/24): ").strip()

    print("\nChoose scan type:")
    print("1️⃣  Ping Sweep (alive hosts, clean list)")
    print("2️⃣  Basic Port Scan (top 1000 ports, raw output)")
    print("3️⃣  Full Port Scan (all ports, raw output)")
    choice = input("Enter your choice (1/2/3): ").strip()

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    print(f"\n[+] Timestamp: {timestamp}")

    if choice == '1':
        ping_sweep(target)
    elif choice == '2':
        basic_port_scan(target)
    elif choice == '3':
        full_port_scan(target)
    else:
        print("\n❗ Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
