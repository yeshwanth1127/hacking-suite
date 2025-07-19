import subprocess
import json
from datetime import datetime

def load_alive_hosts(filename="ping_sweep_results.json"):
    with open(filename) as f:
        alive_hosts = json.load(f)
    return alive_hosts

def run_rustscan(ip):
    print(f"[+] Running RustScan on {ip}")
    output_file = f"rustscan_raw_{ip}.txt"
    json_file = f"rustscan_parsed_{ip}.json"

    # RustScan command
    cmd = ["rustscan", "-a", ip, "--ulimit", "5000", "--", "-Pn", "-n", "-T4", "-oG", "-"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Save raw output
    with open(output_file, "w") as f:
        f.write(result.stdout)

    # Parse open ports
    open_ports = []
    for line in result.stdout.splitlines():
        if line.startswith("Host:") and "Ports:" in line:
            ports_section = line.split("Ports:")[1].strip()
            ports = [p.split('/')[0] for p in ports_section.split(", ") if "/open/" in p]
            open_ports.extend(ports)

    # Save clean JSON
    result_json = {"ip": ip, "open_ports": open_ports}
    with open(json_file, "w") as f:
        json.dump(result_json, f, indent=4)

    print(f"[+] ✅ RustScan completed for {ip}: Found {len(open_ports)} open ports. Results saved.")
    return result_json

def main():
    print("🟣 RustScan Automation Started")
    alive_hosts = load_alive_hosts()
    summary = []

    for ip in alive_hosts:
        result = run_rustscan(ip)
        summary.append(result)

    # Save final summary for all hosts
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    with open(f"rustscan_summary_{timestamp}.json", "w") as f:
        json.dump(summary, f, indent=4)

    print(f"\n✅ All RustScan results saved to rustscan_summary_{timestamp}.json")

if __name__ == "__main__":
    main()
