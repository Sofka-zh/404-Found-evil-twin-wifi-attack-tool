# Evil Twin WiFi Attack Tool

This is a tool that fully implements the evil twin attack targeting open WiFi networks.

## Overview

The Evil Twin attack creates a rogue access point that mimics a legitimate open WiFi network. When victims connect to the fake AP, they are presented with a captive portal that can capture credentials or other information.

## Requirements

### Hardware
- **Option 1**: Two laptops booted with Kali Linux
- **Option 2**: One laptop with a WiFi USB adapter

### Software Dependencies
Install the following packages on your Kali Linux system:

```bash
# Update package lists
sudo apt update

# Install required packages
sudo apt install -y aircrack-ng
sudo apt install -y lighttpd
sudo apt install -y hostapd
sudo apt install -y dnsmasq
```

## Installation

1. Clone this repository:
```bash
git clone <https://github.com/Sofka-zh/404-Found-evil-twin-wifi-attack-tool.git>
cd 404-Found-evil-twin-wifi-attack-tool
```

2. Ensure all dependencies are installed (see above)

3. Make sure the Python scripts have execution permissions:
```bash
chmod +x ap+phishing.py
chmod +x Evil-Twin-WiFi-Attack-Tool.py
```

## Usage

### Step 1: Start the Rogue Access Point

On the first laptop (or on your main system), run the AP and phishing server:

```bash
sudo python3 ap+phishing.py
```

This script will:
- Create a rogue access point mimicking the target network
- Set up a captive portal at `http://10.0.0.1`
- Start capturing credentials when victims attempt to authenticate

### Step 2: Launch Deauthentication Attack

On the second laptop (or using a WiFi USB adapter), run the deauthentication script:

```bash
sudo python3 Evil-Twin-WiFi-Attack-Tool.py
```

This script will:
- Send deauthentication packets to clients connected to the legitimate AP
- Force victims to disconnect and search for available networks
- Victims will automatically reconnect to your rogue AP (which appears identical)

### Expected Results

When the attack is successful:
1. Victim devices will disconnect from the legitimate AP
2. Devices will connect to your rogue AP
3. A captive portal will automatically open on the victim's device
4. Any credentials entered will be captured and saved
5. You should see connection logs in the terminal running `ap+phishing.py`

## Project Structure

- `ap+phishing.py` - Creates the rogue access point and captive portal
- `Evil-Twin-WiFi-Attack-Tool.py` - Performs deauthentication attacks
- Configuration files for `hostapd`, `dnsmasq`, and `lighttpd`
- HTML/CSS files for the captive portal interface

## ⚠️ Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Unauthorized access to computer networks is illegal. Always obtain proper authorization before conducting any security testing.