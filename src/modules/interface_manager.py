# -*- coding: utf-8 -*-
"""Manages wireless network interfaces (detection, mode switching) with enhanced error handling."""

import subprocess
import re
import time
import os

def run_command(command, check=False):
    """Executes a shell command and returns stdout, stderr, and return code."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=check, # Only raise exception if check is True
            capture_output=True,
            text=True,
            encoding=\'utf-8\',
            errors=\'ignore\'
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.CalledProcessError as e:
        # This block is reached only if check=True and command fails
        print(f"[!] Error executing command (check=True): {command}")
        print(f"[!] Stderr: {e.stderr.strip()}")
        return None, e.stderr.strip(), e.returncode
    except FileNotFoundError:
        print(f"[!] Error: Command not found: {command.split()[0]}")
        return None, "Command not found", 127
    except Exception as e:
        print(f"[!] Unexpected error running command {command}: {e}")
        return None, str(e), 1

def get_wireless_interfaces():
    """Detects available wireless interfaces using iw dev."""
    interfaces = []
    stdout, stderr, retcode = run_command("iw dev")
    if retcode == 0 and stdout:
        # Find physical devices (phy#)
        phys = re.findall(r"phy#(\d+)", stdout)
        for phy in phys:
            # Find interfaces associated with this phy
            phy_section_match = re.search(rf"phy#{phy}(.*?)(?=phy#|$)", stdout, re.DOTALL)
            if phy_section_match:
                phy_section = phy_section_match.group(1)
                # Find interfaces within this section
                phy_interfaces = re.findall(r"\tInterface\s+(\w+)", phy_section)
                interfaces.extend(phy_interfaces)
    else:
        # Fallback using ip link (less reliable for wireless type)
        stdout_ip, _, _ = run_command("ip link show | grep -oP ".*:\\s+\\K(wlan\\d+|wl\\w+|ath\\d+|ra\\d+)"")
        if stdout_ip:
            interfaces.extend(stdout_ip.splitlines())
            
    # Remove duplicates and known virtual interfaces potentially created by airmon
    interfaces = [iface for iface in list(set(interfaces)) if not iface.endswith("mon") and not iface.startswith("mon")]
    return interfaces

def get_interface_details(interface):
    """Gets mode and phy for a specific interface using iw dev."""
    stdout, stderr, retcode = run_command(f"iw dev {interface} info")
    if retcode == 0 and stdout:
        mode_match = re.search(r"\ttype\s+(\w+)", stdout)
        phy_match = re.search(r"\twiphy\s+(\d+)", stdout)
        mode = mode_match.group(1) if mode_match else "unknown"
        phy = f"phy{phy_match.group(1)}" if phy_match else "unknown"
        return {"mode": mode, "phy": phy}
    return None

def find_monitor_interface_for_phy(phy):
    """Checks if a monitor interface already exists for a given phy."""
    stdout, stderr, retcode = run_command("iw dev")
    if retcode == 0 and stdout:
        phy_section_match = re.search(rf"phy#{phy.replace("phy","")}(.*?)(?=phy#|$)", stdout, re.DOTALL)
        if phy_section_match:
            phy_section = phy_section_match.group(1)
            # Find monitor interfaces within this section
            monitor_interfaces = re.findall(r"\tInterface\s+(\w+).*?\n\t\ttype\s+monitor", phy_section)
            if monitor_interfaces:
                return monitor_interfaces[0] # Return the first one found
    return None

def kill_interfering_processes():
    """Uses airmon-ng check kill to stop processes that might interfere. Returns True if successful."""
    print("[*] Checking for and killing interfering processes...")
    # Run without check=True to avoid crashing if airmon-ng fails
    stdout, stderr, retcode = run_command("airmon-ng check kill") 
    if retcode != 0:
        print(f"[!] Warning: airmon-ng check kill failed (Code: {retcode}). Stderr: {stderr}")
        # Don't necessarily stop the whole process, maybe monitor mode can still be enabled
        return False
    else:
        print("[*] Interfering processes checked/killed.")
        return True

def enable_monitor_mode_enhanced(interface):
    """Enables monitor mode intelligently, checking existing state. Returns (success, mon_iface_name, error_msg)."""
    print(f"[*] Attempting to enable monitor mode on {interface}...")
    
    # 1. Check current state
    details = get_interface_details(interface)
    if not details:
        return False, None, f"Could not get details for interface {interface}."
        
    current_mode = details["mode"]
    phy = details["phy"]
    
    if current_mode == "monitor":
        print(f"[+] Interface {interface} is already in monitor mode.")
        return True, interface, None
        
    # Check if another monitor interface exists for the same physical device
    existing_mon_iface = find_monitor_interface_for_phy(phy)
    if existing_mon_iface:
         print(f"[+] Monitor mode seems already active for {phy} on interface {existing_mon_iface}.")
         # Decide if we should use this existing one or try to create a new one
         # For simplicity, let's use the existing one
         return True, existing_mon_iface, None

    # 2. Kill interfering processes (best effort)
    kill_interfering_processes()
    time.sleep(1) # Give processes time to terminate

    # 3. Start monitor mode using airmon-ng
    print(f"[*] Running: airmon-ng start {interface}")
    stdout, stderr, retcode = run_command(f"airmon-ng start {interface}")

    if retcode != 0:
        error_msg = f"airmon-ng start failed (Code: {retcode}). Stderr: {stderr}"
        print(f"[!] {error_msg}")
        # Check for common error: "Device or resource busy"
        if "Device or resource busy" in stderr:
             error_msg += " Try running \'airmon-ng check kill\' again manually."
        # Check for error mentioned in user image: "monitor mode already enabled"
        if "monitor mode already enabled" in stderr:
             error_msg += " Airmon-ng reports mode already enabled, but couldn\'t find the interface. Manual check needed."
             # Try finding it again
             time.sleep(1)
             existing_mon_iface = find_monitor_interface_for_phy(phy)
             if existing_mon_iface:
                  print(f"[+] Found existing monitor interface {existing_mon_iface} after error.")
                  return True, existing_mon_iface, None
             else:
                  return False, None, error_msg # Still couldn't find it
        return False, None, error_msg

    # 4. Find the new monitor interface name
    # Parse stdout for the new name
    # Examples:
    #   (monitor mode vif enabled for [phy0]wlan0 on mon0)
    #   (monitor mode enabled on wlan0mon)
    match = re.search(r"monitor mode (?:vif )?enabled.*? on (\w+)\)?", stdout, re.IGNORECASE)
    if match:
        monitor_interface_name = match.group(1)
        print(f"[*] Airmon-ng output suggests monitor interface: {monitor_interface_name}")
    else:
        # Fallback: Check common naming conventions like wlanXmon or monX
        print("[!] Could not reliably parse monitor interface name from airmon-ng output.")
        print(f"[*] Output: {stdout}")
        # Try common patterns
        potential_name1 = interface + "mon"
        potential_name2 = "mon" + interface.replace("wlan", "").replace("wl","") # e.g., mon0 from wlan0
        stdout_iw, _, _ = run_command("iw dev")
        found_name = None
        if potential_name1 in stdout_iw:
            found_name = potential_name1
        elif potential_name2 in stdout_iw:
             found_name = potential_name2
             
        if found_name:
             monitor_interface_name = found_name
             print(f"[*] Fallback check suggests monitor interface might be: {monitor_interface_name}")
        else:
             print("[!] Failed to determine monitor interface name via fallback.")
             return False, None, "Could not determine monitor interface name after airmon-ng start."

    # 5. Verify the new interface is actually in monitor mode
    time.sleep(1) # Give the interface time to settle
    new_details = get_interface_details(monitor_interface_name)
    if new_details and new_details["mode"] == "monitor":
        print(f"[+] Successfully enabled monitor mode on: {monitor_interface_name}")
        return True, monitor_interface_name, None
    else:
        error_msg = f"Interface {monitor_interface_name} found, but not in monitor mode (Mode: {new_details["mode"] if new_details else \'unknown\'})."
        print(f"[!] {error_msg}")
        # Attempt cleanup
        print(f"[*] Attempting to stop potentially failed monitor interface {monitor_interface_name}...")
        run_command(f"airmon-ng stop {monitor_interface_name}")
        return False, None, error_msg

def disable_monitor_mode_enhanced(monitor_interface_to_stop, original_interface_hint=None):
    """Disables monitor mode intelligently. Returns (success, message)."""
    print(f"[*] Attempting to disable monitor mode on {monitor_interface_to_stop}...")

    # 1. Stop monitor mode using airmon-ng
    stdout, stderr, retcode = run_command(f"airmon-ng stop {monitor_interface_to_stop}")

    if retcode != 0:
        error_msg = f"airmon-ng stop failed (Code: {retcode}). Stderr: {stderr}"
        print(f"[!] {error_msg}")
        # Check if it failed because the interface doesn't exist (maybe already stopped)
        if "No such device" in stderr or "does not exist" in stderr:
             print("[*] Interface likely already stopped or removed.")
             # Let's check if the original interface is back in managed mode
             if original_interface_hint:
                  details = get_interface_details(original_interface_hint)
                  if details and details["mode"] == "managed":
                       print(f"[+] Original interface {original_interface_hint} confirmed in managed mode.")
                       return True, "Monitor mode stopped (interface was likely already down)."
                  else:
                       msg = f"Monitor interface stopped, but original interface {original_interface_hint} not found or not in managed mode."
                       print(f"[!] {msg}")
                       return False, msg
             else:
                  # No original hint, assume success if stop command indicated device gone
                  return True, "Monitor mode stopped (interface was likely already down)."
        return False, error_msg

    # 2. Verify monitor interface is gone
    time.sleep(1)
    details_mon = get_interface_details(monitor_interface_to_stop)
    if details_mon:
        msg = f"Monitor interface {monitor_interface_to_stop} still exists after stop command (Mode: {details_mon[\'mode\']})."
        print(f"[!] {msg}")
        # Maybe try `ip link set dev {monitor_interface_to_stop} down`? For now, report failure.
        return False, msg

    # 3. Verify original interface is back in managed mode (if hint provided)
    original_iface_name = original_interface_hint
    if not original_iface_name:
        # Try to guess original name from monitor name (e.g., wlan0mon -> wlan0)
        if monitor_interface_to_stop.endswith("mon"):
            original_iface_name = monitor_interface_to_stop[:-3]
        elif monitor_interface_to_stop.startswith("mon"):
             # Less reliable, e.g., mon0 -> wlan0? Need mapping.
             pass # Cannot reliably guess here
             
    if original_iface_name:
        print(f"[*] Checking status of original interface {original_iface_name}...")
        details_orig = get_interface_details(original_iface_name)
        if details_orig and details_orig["mode"] == "managed":
            print(f"[+] Original interface {original_iface_name} confirmed back in managed mode.")
            # Optionally restart NetworkManager if needed
            # print("[*] Consider restarting NetworkManager: sudo systemctl restart NetworkManager")
            return True, f"Monitor mode disabled. {original_iface_name} is in managed mode."
        else:
            mode = details_orig["mode"] if details_orig else "not found"
            msg = f"Monitor mode stopped, but original interface {original_iface_name} is {mode}. Manual check/restart may be needed."
            print(f"[!] {msg}")
            # Return success=True because monitor is stopped, but with a warning message
            return True, msg 
    else:
        # Monitor stopped, but couldn't verify original interface
        return True, "Monitor mode disabled. Could not verify original interface status."

# --- Example Usage (for testing) ---
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run with sudo.")
        exit()
        
    print("[*] Detecting wireless interfaces...")
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print("[!] No wireless interfaces found. Exiting.")
    else:
        print(f"[*] Found interfaces: {', '.join(interfaces)}")
        selected_interface = interfaces[0] # Select the first one for testing
        print(f"\n[*] Testing Enhanced Monitor Mode on: {selected_interface}")

        success, mon_iface, error = enable_monitor_mode_enhanced(selected_interface)

        if success:
            print(f"\n[+] Monitor interface {mon_iface} active. Waiting 5 seconds...")
            time.sleep(5)
            print(f"\n[*] Testing Enhanced Disable Monitor Mode on: {mon_iface}")
            disable_success, disable_msg = disable_monitor_mode_enhanced(mon_iface, selected_interface)
            print(f"[*] Disable Result: Success={disable_success}, Message='{disable_msg}'")
        else:
            print(f"\n[!] Failed to enable monitor mode for {selected_interface}. Error: {error}")

