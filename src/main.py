# -*- coding: utf-8 -*-
"""Main entry point for the Wireless Audit Tool."""

import sys
import time
import os
import argparse

# Adjust path to import modules from the src directory
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Import core modules
import dependency_manager
from modules import interface_manager
from modules import scanner
from modules import handshake_capture

# --- Constants ---
OUTPUT_BASE_DIR = "/home/ubuntu/wireless_audit_output"
SCAN_DURATION_DEFAULT = 20 # seconds
CAPTURE_TIMEOUT_DEFAULT = 120 # seconds

def display_menu(interface_name, monitor_interface_name):
    """Displays the main menu options."""
    print("\n--- Main Menu ---")
    print(f"Interface: {interface_name}")
    if monitor_interface_name:
        print(f"Monitor Mode Interface: {monitor_interface_name}")
    else:
        print("Monitor Mode: Disabled")
    print("1. Scan for Networks")
    print("2. Capture Handshake (WPA/WPA2)")
    # Add more options here as modules are implemented (WPS, Evil Twin, etc.)
    print("9. Exit")
    print("-----------------")

def select_target_ap(aps):
    """Allows the user to select a target AP from the list."""
    if not aps:
        print("[!] No Access Points found to select from.")
        return None

    print("\n--- Select Target Access Point ---")
    wpa_aps = [ap for ap in aps if "WPA" in ap.get("privacy", "")]
    if not wpa_aps:
        print("[!] No WPA/WPA2 networks found in the scan results.")
        return None

    for i, ap in enumerate(wpa_aps):
        essid = ap.get("essid", "<Hidden>")
        bssid = ap.get("bssid", "N/A")
        channel = ap.get("channel", "?")
        power = ap.get("power", "?")
        privacy = ap.get("privacy", "?")
        print(f"  {i}: {essid} ({bssid}) - Ch: {channel}, Pwr: {power}, Enc: {privacy}")

    while True:
        try:
            choice = input("Enter the number of the target AP: ")
            if not choice:
                 continue
            index = int(choice)
            if 0 <= index < len(wpa_aps):
                return wpa_aps[index]
            else:
                print("[!] Invalid selection.")
        except ValueError:
            print("[!] Invalid input. Please enter a number.")
        except EOFError:
             print("\n[!] Input aborted.")
             return None

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description="Wireless Audit Tool - Proof of Concept")
    parser.add_argument("-i", "--interface", help="Specify the wireless interface to use.")
    # Add more arguments as needed (e.g., target BSSID, output dir)
    args = parser.parse_args()

    print("--- Wireless Audit Tool Initializing ---")

    # 0. Check Dependencies
    success, _, _ = dependency_manager.check_dependencies()
    if not success:
        print("[!] Essential dependencies missing. Please install them and try again.")
        sys.exit(1)

    # 1. Select Interface
    selected_interface = args.interface
    if not selected_interface:
        interfaces = interface_manager.get_wireless_interfaces()
        if not interfaces:
            print("[!] No wireless interfaces found. Exiting.")
            sys.exit(1)
        if len(interfaces) == 1:
            selected_interface = interfaces[0]
            print(f"[*] Automatically selected interface: {selected_interface}")
        else:
            print("[*] Available wireless interfaces:")
            for idx, iface in enumerate(interfaces):
                print(f"  {idx}: {iface}")
            while selected_interface is None:
                try:
                    choice = input("Select the interface number to use: ")
                    if not choice:
                         continue
                    iface_idx = int(choice)
                    if 0 <= iface_idx < len(interfaces):
                        selected_interface = interfaces[iface_idx]
                    else:
                        print("[!] Invalid selection.")
                except ValueError:
                    print("[!] Invalid input. Please enter a number.")
                except EOFError:
                     print("\n[!] Input aborted. Exiting.")
                     sys.exit(1)

    print(f"[*] Using interface: {selected_interface}")

    # Ensure output directory exists
    if not os.path.exists(OUTPUT_BASE_DIR):
        try:
            os.makedirs(OUTPUT_BASE_DIR)
            print(f"[*] Created output directory: {OUTPUT_BASE_DIR}")
        except OSError as e:
            print(f"[!] Failed to create output directory {OUTPUT_BASE_DIR}: {e}")
            # Decide if this is fatal or if we should use current dir
            sys.exit(1)

    # 2. Enable Monitor Mode (handle cleanup)
    monitor_interface = None
    try:
        monitor_interface = interface_manager.enable_monitor_mode(selected_interface)
        if not monitor_interface:
            print(f"[!] Failed to enable monitor mode on {selected_interface}. Exiting.")
            sys.exit(1)

        # --- Main Application Loop ---
        last_scan_results = []
        while True:
            display_menu(selected_interface, monitor_interface)
            try:
                choice = input("Enter your choice: ")
                if not choice:
                     continue

                if choice == "1":
                    # Scan for Networks
                    print(f"\n[*] Starting network scan for {SCAN_DURATION_DEFAULT} seconds...")
                    scan_prefix = os.path.join(OUTPUT_BASE_DIR, "live_scan")
                    scan_proc, scan_csv = scanner.start_airodump_scan(monitor_interface, output_prefix=scan_prefix)
                    if scan_proc and scan_csv:
                        end_time = time.time() + SCAN_DURATION_DEFAULT
                        while time.time() < end_time:
                             aps, cls = scanner.parse_airodump_csv(scan_csv)
                             # Simple dynamic display
                             print(f"\r[*] Scanning... Found {len(aps)} APs, {len(cls)} Clients. Time left: {int(end_time - time.time())}s", end="")
                             time.sleep(1)
                        print("\r[*] Scan finished.                                       ") # Clear line
                        scanner.stop_airodump_scan()
                        last_scan_results, _ = scanner.parse_airodump_csv(scan_csv)
                        # Clean up scan files
                        for ext in [".csv", ".cap", ".kismet.csv", ".kismet.netxml", ".log.csv"]:
                            try: os.remove(f"{scan_prefix}-01{ext}")
                            except OSError: pass
                        # Display results (optional)
                        if last_scan_results:
                             print("[*] Scan Results (WPA/WPA2 only):")
                             select_target_ap(last_scan_results) # Just display for now
                        else:
                             print("[!] No networks found.")
                    else:
                        print("[!] Failed to start scan process.")

                elif choice == "2":
                    # Capture Handshake
                    target_ap = select_target_ap(last_scan_results)
                    if target_ap:
                        bssid = target_ap.get("bssid")
                        channel = target_ap.get("channel")
                        essid = target_ap.get("essid", bssid)
                        if bssid and channel:
                            print(f"\n[*] Attempting handshake capture for {essid} ({bssid}) on Ch: {channel}")
                            capture_prefix = os.path.join(OUTPUT_BASE_DIR, f"capture_{bssid.replace(':', '')}")
                            cap_proc, cap_file = handshake_capture.start_handshake_capture(monitor_interface, bssid, channel, capture_prefix)
                            if cap_proc and cap_file:
                                handshake_found = False
                                start_time = time.time()
                                # Start deauth periodically
                                deauth_proc = handshake_capture.start_deauth_attack(monitor_interface, bssid, packets=5)
                                print(f"[*] Monitoring for handshake for {CAPTURE_TIMEOUT_DEFAULT} seconds (Ctrl+C to stop early)...")
                                try:
                                    while time.time() - start_time < CAPTURE_TIMEOUT_DEFAULT:
                                        if handshake_capture.check_for_handshake_in_output(cap_proc):
                                            handshake_found = True
                                            print("\n[+] Handshake detected in airodump output!")
                                            break
                                        # Optional: Add file check periodically
                                        # if int(time.time() - start_time) % 15 == 0:
                                        #     if handshake_capture.check_handshake_in_file(cap_file, bssid, essid):
                                        #         handshake_found = True
                                        #         print("\n[+] Handshake verified in capture file!")
                                        #         break
                                        print(f"\r[*] Monitoring... Time elapsed: {int(time.time() - start_time)}s", end="")
                                        time.sleep(1)
                                except KeyboardInterrupt:
                                     print("\n[!] Capture interrupted by user.")
                                finally:
                                    print("\r[*] Stopping capture processes...                           ")
                                    handshake_capture.stop_handshake_capture()
                                    handshake_capture.stop_deauth_attack()

                                if handshake_found:
                                    print(f"[+] Handshake capture successful! Verifying file: {cap_file}")
                                    time.sleep(1) # Give fs time
                                    handshake_capture.check_handshake_in_file(cap_file, bssid, essid)
                                    print(f"[*] Capture file saved: {cap_file}")
                                else:
                                    print(f"\n[-] Handshake not captured within the timeout. Capture file (may be incomplete): {cap_file}")
                            else:
                                print("[!] Failed to start capture process.")
                        else:
                            print("[!] Target AP information incomplete (BSSID or Channel missing).")
                    else:
                        print("[!] No target selected or no suitable APs found in last scan.")

                elif choice == "9":
                    print("[*] Exiting tool...")
                    break # Exit the main loop
                else:
                    print("[!] Invalid choice. Please try again.")

            except KeyboardInterrupt:
                print("\n[!] Operation interrupted by user. Returning to menu.")
                # Ensure any running subprocesses specific to the interrupted operation are stopped
                scanner.stop_airodump_scan() # Stop scanner if running
                handshake_capture.stop_handshake_capture() # Stop capture if running
                handshake_capture.stop_deauth_attack() # Stop deauth if running
            except EOFError:
                 print("\n[!] Input stream closed. Exiting.")
                 break

    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # --- Cleanup --- #
        print("[*] Performing cleanup...")
        # Stop any potentially running background processes managed globally
        scanner.stop_airodump_scan()
        handshake_capture.stop_handshake_capture()
        handshake_capture.stop_deauth_attack()
        # Disable monitor mode
        if monitor_interface:
            interface_manager.disable_monitor_mode(monitor_interface)
        print("--- Wireless Audit Tool Finished ---")

if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("[!] This tool requires root privileges to manage network interfaces and capture packets.")
        print("Please run using sudo.")
        sys.exit(1)
    main()

