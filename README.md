
Ethical Wi-Fi Twin Automation Tool

This project is a graphical user interface (GUI) application built with Python and PyQt5. It's designed as a proof-of-concept for authorized penetration testing and network security education. The tool automates the process of creating a Wi-Fi "evil twin" to demonstrate how these attacks work and to help network administrators identify and mitigate vulnerabilities.

Disclaimer and Ethical Use ⚠️

This tool is for educational purposes and authorized security testing only. It's designed to be used by cybersecurity professionals and students to understand and counter cyber threats.

Misuse of this software is illegal and unethical. You must have explicit, written permission from the network owner before using this tool. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.

Features

The tool provides a simple, step-by-step process for conducting a simulated evil twin attack:

GUI-Based Workflow: A user-friendly interface guides you through the attack stages.

Automated Setup: Automatically sets your wireless adapters to monitor mode.

Network Scanning: Scans for available wireless networks and displays their details.

Deauthentication Attack: Launches a denial-of-service attack to disconnect clients from a target network, forcing them to reconnect.

Rogue Access Point: Creates a fake Wi-Fi network (the evil twin) with the same name as the target network.

Captive Portal Spoofing: Serves a fake login page to clients that connect to the twin, demonstrating how attackers can phish for credentials.

Credential Logging: Captures and logs any submitted credentials for security analysis.

Prerequisites and Installation

Hardware

A computer with a Linux-based operating system (Kali Linux is recommended as it includes all necessary tools).

Two compatible wireless adapters that support monitor mode and packet injection.

Software

Python 3.x

The aircrack-ng suite of tools (airmon-ng, airodump-ng, aireplay-ng)

hostapd

dnsmasq

apache2

PyQt5 library

Installation Steps

Clone the repository:

Bash

git clone https://github.com/chinthajayanth/Wifi_Evil_Twin.git

cd Wifi_Evil_Twin

Install system dependencies:

Bash

sudo apt-get update

sudo apt-get install aircrack-ng hostapd dnsmasq apache2 python3-pyqt5

Install Python libraries:

Bash

pip3 install -r requirements.txt

Usage

Run the tool:

Bash
sudo python3 evil_twin_tool.py
(Note: The script requires sudo privileges to manage network interfaces and services.)

Follow the GUI steps:

Click "Setup Monitor Mode" to prepare your wireless cards.

Click "Scan Networks" to find a target.

Select your target from the dropdown list and click "Select Target."

Click "Launch Attack" to begin the simulated test.

Clean up: The tool attempts to clean up processes when closed. If it fails, manually run the following commands to stop services and return your wireless cards to managed mode:

Bash
sudo service apache2 stop

sudo pkill dnsmasq

sudo airmon-ng stop wlan0mon

sudo airmon-ng stop wlan1mon
