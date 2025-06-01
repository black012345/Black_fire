# -*- coding: utf-8 -*-
"""Handles cracking captured WPA/WPA2 handshakes using aircrack-ng and hashcat."""

import subprocess
import os
import signal
import time
import re

# Define global variables for processes
aircrack_process = None
hashcat_process = None

def run_command(command, capture=True, timeout=None):
    """Executes a shell command (simplified)."""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            capture_output=capture, 
            text=True, 
            encoding="utf-8", 
            errors="ignore",
            timeout=timeout
        )
        return result.stdout.strip() if capture else "", result.stderr.strip() if capture else ""
    except subprocess.TimeoutExpired:
        return None, "Command timed out"
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if capture else "Process failed"
        return None, stderr_output
    except FileNotFoundError:
        return None, "Command not found"

def stop_process(process, name="process"):
    """Stops a running process group."""
    if process and process.poll() is None:
        print(f"[*] Stopping {name} (PID: {process.pid})...")
        try:
            # Try SIGTERM first
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=3)
            print(f"[+] {name} stopped gracefully.")
        except ProcessLookupError:
            print(f"[!] {name} already terminated.")
        except subprocess.TimeoutExpired:
            print(f"[!] {name} did not terminate gracefully, sending SIGKILL...")
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                process.wait(timeout=2) # Wait briefly after kill
                print(f"[+] {name} killed.")
            except Exception as kill_err:
                 print(f"[!] Error sending SIGKILL to {name}: {kill_err}")
        except Exception as e:
            print(f"[!] Error stopping {name}: {e}")
        finally:
            process = None # Ensure process variable is cleared
    return None # Return None to clear the global variable

def start_aircrack_attack(capture_file, wordlist_file, target_bssid=None, target_essid=None):
    """Starts an aircrack-ng dictionary attack."""
    global aircrack_process

    if aircrack_process and aircrack_process.poll() is None:
        print("[!] An aircrack-ng process is already running.")
        return None

    # Check if files exist
    if not os.path.exists(capture_file):
        print(f"[!] Capture file not found: {capture_file}")
        return None
    if not os.path.exists(wordlist_file):
        print(f"[!] Wordlist file not found: {wordlist_file}")
        return None
    
    # Check if aircrack-ng exists
    stdout_check, _ = run_command("which aircrack-ng")
    if not stdout_check:
         print("[!] Error: aircrack-ng command not found.")
         return None

    command = f"aircrack-ng -w {shlex.quote(wordlist_file)}"
    if target_bssid:
        command += f" -b {shlex.quote(target_bssid)}"
    elif target_essid:
         command += f" -e {shlex.quote(target_essid)}"
    # Add capture file at the end
    command += f" {shlex.quote(capture_file)}"

    print(f"[*] Starting aircrack-ng attack: {command}")
    try:
        # Use Popen to manage the process and capture output
        aircrack_process = subprocess.Popen(
            command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            encoding="utf-8", 
            errors="ignore",
            preexec_fn=os.setsid
        )
        print(f"[+] Aircrack-ng started (PID: {aircrack_process.pid}). Press Ctrl+C to stop.")
        return aircrack_process
    except Exception as e:
        print(f"[!] Failed to start aircrack-ng: {e}")
        aircrack_process = None
        return None

def stop_aircrack_attack():
    """Stops the running aircrack-ng attack."""
    global aircrack_process
    aircrack_process = stop_process(aircrack_process, "aircrack-ng")

def check_aircrack_output(process):
    """Checks the stdout of aircrack-ng for the cracked key."""
    if not process or process.poll() is not None:
        return None, False # No key found, process not running

    key_found = None
    finished = False
    try:
        # Non-blocking read
        for line in iter(process.stdout.readline, "): 
            if not line:
                 break # No more output for now
            print(line.strip()) # Print live output
            if "KEY FOUND!" in line:
                match = re.search(r"KEY FOUND! \[ (.*) \]", line)
                if match:
                    key_found = match.group(1)
                    print(f"\n[+] KEY FOUND: {key_found}")
                    finished = True # Stop checking once key is found
                    break
            elif "Passphrase not in dictionary" in line or "Failed. Next try" in line or "No networks found" in line:
                 # Indicate that the process might finish without finding the key
                 pass # Continue reading output
            elif "Quitting aircrack-ng" in line:
                 finished = True
                 break
                 
        # Check if process terminated after reading available output
        if process.poll() is not None and not key_found:
             finished = True # Process ended without finding key
             print("[*] Aircrack-ng finished without finding the key.")

    except Exception as e:
        # Handle exceptions if the process terminates unexpectedly
        # print(f"[!] Error reading aircrack-ng stdout: {e}")
        if process.poll() is not None:
             finished = True # Assume finished if error occurs and process is dead

    return key_found, finished

# --- Placeholder functions for Hashcat --- 
# These require converting .cap to .hc22000 format first

def convert_cap_to_hc22000(capture_file, output_hc_file):
    """Converts a .cap file to hashcat's hc22000 format using hcxpcapngtool."""
    print("[!] .cap to hc22000 conversion not implemented yet.")
    # Check if hcxpcapngtool exists
    # Command: hcxpcapngtool -o <output_hc_file> <capture_file>
    # Handle potential errors and return True/False
    return False

def start_hashcat_attack(hc22000_file, wordlist_file, extra_args="-m 22000"):
    """Starts a hashcat dictionary attack on a hc22000 file."""
    global hashcat_process
    print("[!] Hashcat attack function not implemented yet.")
    # Check if hashcat exists
    # Check if hc22000_file and wordlist_file exist
    # Command: hashcat [extra_args] <hc22000_file> <wordlist_file>
    # Use Popen
    # Return process handle
    return None

def stop_hashcat_attack():
    """Stops the running hashcat attack."""
    global hashcat_process
    hashcat_process = stop_process(hashcat_process, "hashcat")

def check_hashcat_output(process):
    """Checks hashcat output for cracked passwords."""
    print("[!] Hashcat output checking not implemented yet.")
    # Read process stdout/stderr
    # Look for cracked password lines or status updates
    # Hashcat often requires checking the .potfile after completion
    return None, False # key, finished

# --- Example Usage --- 
if __name__ == "__main__":
    import sys
    import shlex # Import shlex here for example usage

    # Check for root (aircrack might not strictly need it, but previous steps do)
    if os.geteuid() != 0:
        print("[!] This example might require root if interacting with interfaces.")
        # sys.exit(1) # Allow running for simple file cracking test

    # --- Configuration (Update these paths) ---
    # Use a capture file known to have a handshake
    TEST_CAP_FILE = "/path/to/your/test_handshake.cap" 
    # Use a small wordlist containing the known password for testing
    TEST_WORDLIST = "/path/to/your/test_wordlist.txt" 
    TARGET_BSSID = "00:11:22:33:44:55" # Optional: Specify BSSID if cap has multiple networks
    # --- End Configuration ---

    if not os.path.exists(TEST_CAP_FILE) or not os.path.exists(TEST_WORDLIST):
        print(f"[!] Please update TEST_CAP_FILE ({TEST_CAP_FILE}) and TEST_WORDLIST ({TEST_WORDLIST}) paths in the script.")
        sys.exit(1)

    print(f"[*] Starting test attack on {TEST_CAP_FILE} with wordlist {TEST_WORDLIST}")
    crack_proc = start_aircrack_attack(TEST_CAP_FILE, TEST_WORDLIST, target_bssid=TARGET_BSSID)

    if crack_proc:
        found_key = None
        is_finished = False
        start_time = time.time()
        try:
            while not is_finished:
                found_key, is_finished = check_aircrack_output(crack_proc)
                if found_key:
                    break
                # Add a timeout mechanism if desired
                # if time.time() - start_time > 300: # 5 minute timeout example
                #     print("\n[!] Attack timed out.")
                #     break
                time.sleep(0.5) # Check output periodically
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user.")
        finally:
            stop_aircrack_attack()

        if found_key:
            print(f"\n[SUCCESS] Password found: {found_key}")
        else:
            print("\n[FAILURE] Password not found in the provided wordlist.")
    else:
        print("[!] Failed to start aircrack-ng process.")

    print("[*] Example finished.")

