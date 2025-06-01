# -*- coding: utf-8 -*-
"""Handles scanning for wireless networks using airodump-ng."""

import subprocess
import time
import os
import csv
import signal
from datetime import datetime

# Define a global variable to hold the airodump process
airodump_process = None

def run_command(command):
    """Executes a shell command and returns its output (simplified)."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, encoding="utf-8")
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        # Don't print error here, let the caller handle it if needed
        return None, e.stderr.strip()
    except FileNotFoundError:
        return None, "Command not found"

def start_airodump_scan(monitor_interface, output_prefix="scan_results", scan_bands="bg", channel=None):
    """Starts airodump-ng scan in the background."""
    global airodump_process

    if airodump_process and airodump_process.poll() is None:
        print("[!] An airodump-ng process is already running.")
        return None, None

    # Ensure the output directory exists
    output_dir = os.path.dirname(output_prefix)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Clean up previous scan files with the same prefix
    for ext in [".csv", ".cap", ".kismet.csv", ".kismet.netxml", ".log.csv"]:
        try:
            os.remove(f"{output_prefix}-01{ext}")
        except OSError:
            pass # File doesn't exist, which is fine

    # Construct the airodump-ng command
    # --write-interval 1: Update CSV every 1 second for faster updates
    # --output-format csv: Only save CSV format for easier parsing
    # --band <bands>: Specify bands (a, b, g, n)
    command = f"airodump-ng --write {output_prefix} --write-interval 1 --output-format csv --band {scan_bands}"
    if channel:
        command += f" --channel {channel}"
    command += f" {monitor_interface}"

    print(f"[*] Starting network scan: {command}")
    try:
        # Use Popen to run in the background and manage the process
        # preexec_fn=os.setsid: Run airodump in a new session to manage its termination properly
        airodump_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        print(f"[+] Airodump-ng started (PID: {airodump_process.pid}). Scan data will be in {output_prefix}-01.csv")
        # Give it a moment to start and create the file
        time.sleep(3)
        csv_file = f"{output_prefix}-01.csv"
        if not os.path.exists(csv_file):
             print("[!] Airodump-ng started but CSV file not found after 3 seconds. Check stderr.")
             stderr_output = airodump_process.stderr.read()
             print(f"[!] Airodump stderr: {stderr_output}")
             stop_airodump_scan() # Clean up the process
             return None, None
        return airodump_process, csv_file
    except Exception as e:
        print(f"[!] Failed to start airodump-ng: {e}")
        airodump_process = None
        return None, None

def stop_airodump_scan():
    """Stops the running airodump-ng process."""
    global airodump_process
    if airodump_process and airodump_process.poll() is None:
        print(f"[*] Stopping airodump-ng process (PID: {airodump_process.pid})...")
        try:
            # Send SIGTERM to the process group to ensure child processes are also killed
            os.killpg(os.getpgid(airodump_process.pid), signal.SIGTERM)
            airodump_process.wait(timeout=5) # Wait for graceful termination
            print("[+] Airodump-ng stopped.")
        except ProcessLookupError:
             print("[!] Process already terminated.")
        except subprocess.TimeoutExpired:
            print("[!] Airodump-ng did not terminate gracefully, sending SIGKILL...")
            try:
                os.killpg(os.getpgid(airodump_process.pid), signal.SIGKILL)
                print("[+] Airodump-ng killed.")
            except Exception as kill_err:
                 print(f"[!] Error sending SIGKILL: {kill_err}")
        except Exception as e:
            print(f"[!] Error stopping airodump-ng: {e}")
        finally:
             airodump_process = None
    else:
        print("[*] No active airodump-ng process found to stop.")

def parse_airodump_csv(csv_file):
    """Parses the airodump-ng CSV file to extract AP and client info."""
    access_points = []
    clients = []

    if not os.path.exists(csv_file):
        # print(f"[!] Scan file not found: {csv_file}")
        return [], [] # Return empty lists if file doesn't exist yet

    try:
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            # Skip lines until we find the AP header or Client header
            lines = f.readlines()

        ap_section_start = -1
        client_section_start = -1

        for i, line in enumerate(lines):
            if line.strip().startswith("BSSID, First time seen"): # AP header
                ap_section_start = i
            elif line.strip().startswith("Station MAC, First time seen"): # Client header
                client_section_start = i
                break # Found both headers

        # Parse Access Points
        if ap_section_start != -1:
            ap_end = client_section_start if client_section_start != -1 else len(lines)
            ap_reader = csv.reader(lines[ap_section_start + 1 : ap_end])
            for row in ap_reader:
                if len(row) >= 14:
                    bssid = row[0].strip()
                    if bssid == "BSSID" or not bssid: # Skip header row or empty rows
                        continue
                    # Basic parsing, can be made more robust
                    ap = {
                        "bssid": bssid,
                        "first_seen": row[1].strip(),
                        "last_seen": row[2].strip(),
                        "channel": row[3].strip(),
                        "speed": row[4].strip(),
                        "privacy": row[5].strip(),
                        "cipher": row[6].strip(),
                        "authentication": row[7].strip(),
                        "power": row[8].strip(),
                        "beacons": row[9].strip(),
                        "iv": row[10].strip(),
                        "ip": row[11].strip(),
                        "id_length": row[12].strip(),
                        "essid": row[13].strip(),
                        "key": row[14].strip() if len(row) > 14 else ""
                    }
                    # Filter out potential client entries mistakenly listed here
                    if ap["essid"] or ap["beacons"] != "0":
                         access_points.append(ap)

        # Parse Clients
        if client_section_start != -1:
            client_reader = csv.reader(lines[client_section_start + 1:])
            for row in client_reader:
                 if len(row) >= 7:
                    station_mac = row[0].strip()
                    if station_mac == "Station MAC" or not station_mac: # Skip header or empty rows
                        continue
                    client = {
                        "station_mac": station_mac,
                        "first_seen": row[1].strip(),
                        "last_seen": row[2].strip(),
                        "power": row[3].strip(),
                        "packets": row[4].strip(),
                        "bssid": row[5].strip(), # AP it's connected to
                        "probed_essids": row[6].strip()
                    }
                    clients.append(client)

    except FileNotFoundError:
        # print(f"[!] Scan file not found during parsing: {csv_file}")
        pass # Expected if scan just started
    except Exception as e:
        print(f"[!] Error parsing CSV file {csv_file}: {e}")

    return access_points, clients

if __name__ == "__main__":
    # Example Usage (requires running as root and a monitor mode interface)
    # Make sure interface_manager.py is in the same directory or PYTHONPATH
    try:
        from interface_manager import get_wireless_interfaces, enable_monitor_mode, disable_monitor_mode
    except ImportError:
        print("[!] Failed to import interface_manager. Make sure it's accessible.")
        exit(1)

    interfaces = get_wireless_interfaces()
    if not interfaces:
        print("[!] No wireless interfaces found.")
        exit(1)

    selected_interface = interfaces[0] # Choose the first interface
    print(f"[*] Using interface: {selected_interface}")

    monitor_iface = enable_monitor_mode(selected_interface)
    if not monitor_iface:
        print("[!] Failed to enable monitor mode.")
        exit(1)

    scan_prefix = "/home/ubuntu/test_scan"
    process, csv_file_path = start_airodump_scan(monitor_iface, output_prefix=scan_prefix)

    if process and csv_file_path:
        print(f"[*] Scan running for 15 seconds... Output: {csv_file_path}")
        try:
            for i in range(15):
                time.sleep(1)
                aps, cls = parse_airodump_csv(csv_file_path)
                print(f"-- Time {i+1}s: Found {len(aps)} APs, {len(cls)} Clients --")
                # Optional: Print details of found APs
                # for ap in aps:
                #     print(f"  AP: {ap['essid']} ({ap['bssid']}) - Ch: {ap['channel']}, Enc: {ap['privacy']}, Pwr: {ap['power']}")

        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
        finally:
            stop_airodump_scan()
            # Clean up scan files
            print("[*] Cleaning up scan files...")
            for ext in [".csv", ".cap", ".kismet.csv", ".kismet.netxml", ".log.csv"]:
                 try:
                     os.remove(f"{scan_prefix}-01{ext}")
                 except OSError:
                     pass
    else:
        print("[!] Failed to start scan.")

    # Disable monitor mode
    disable_monitor_mode(monitor_iface)

    print("[*] Example finished.")

