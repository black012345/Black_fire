# -*- coding: utf-8 -*-
"""Main entry point for the Wireless Audit Tool with an airgeddon-like Curses TUI."""

import sys
import time
import os
import curses
import traceback

# Adjust path to import modules from the src directory
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, os.path.dirname(SRC_DIR)) # Add parent of src to path

# Import core modules
import src.dependency_manager as dependency_manager
from src.modules import interface_manager
from src.modules import scanner
from src.modules import handshake_capture
from src.modules import wps_attacks
from src.modules import handshake_cracker
from src.modules import evil_twin

# --- Constants ---
OUTPUT_BASE_DIR = "/home/ubuntu/wireless_audit_output"
APP_VERSION = "0.1.1-dev" # Incremented version
SCAN_TIMEOUT_DEFAULT = 60 # Default scan time if not interrupted
CAPTURE_TIMEOUT_DEFAULT = 180 # Default capture time

# --- Global State ---
selected_interface = None
monitor_interface = None
interface_mode = "None" # None, Managed, Monitor
last_scan_results = []
selected_target_ap = None

# --- Curses Helper Functions ---

def init_colors():
    """Initialize color pairs for curses."""
    curses.start_color()
    curses.use_default_colors() # Use terminal default background
    # Pair 1: Header/Title (Bright Cyan on Default)
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    # Pair 2: Menu Options (White on Default)
    curses.init_pair(2, curses.COLOR_WHITE, -1)
    # Pair 3: Selected Menu Option (Black on Green)
    curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_GREEN)
    # Pair 4: Status Info (Green on Default)
    curses.init_pair(4, curses.COLOR_GREEN, -1)
    # Pair 5: Warning/Input Prompt (Yellow on Default)
    curses.init_pair(5, curses.COLOR_YELLOW, -1)
    # Pair 6: Error (Red on Default)
    curses.init_pair(6, curses.COLOR_RED, -1)
    # Pair 7: Dimmed/Disabled Option (Dark Gray/Default White on Default)
    # Note: COLOR_DARKGRAY might not be available, using DIM attribute instead
    curses.init_pair(7, curses.COLOR_WHITE, -1) # Use with A_DIM

def display_header(stdscr):
    """Displays the header with interface status."""
    h, w = stdscr.getmaxyx()
    header_line1 = f"********* Wireless Audit Tool v{APP_VERSION} Main Menu *********"
    iface_status = f"Interface {selected_interface if selected_interface else ">>Not selected<<"} selected. Mode: {interface_mode}"
    target_status = f"Target: {selected_target_ap["essid"] if selected_target_ap else ">>None<<"} ({selected_target_ap["bssid"] if selected_target_ap else "N/A"})"
    
    # Clear previous header lines
    stdscr.move(0, 0)
    stdscr.clrtoeol()
    stdscr.move(1, 0)
    stdscr.clrtoeol()
    stdscr.move(2, 0)
    stdscr.clrtoeol()
    stdscr.move(3, 0)
    stdscr.clrtoeol()

    stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(0, max(0, w // 2 - len(header_line1) // 2), header_line1[:w-1])
    stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
    
    stdscr.attron(curses.color_pair(4))
    stdscr.addstr(1, max(0, w // 2 - len(iface_status) // 2), iface_status[:w-1])
    stdscr.addstr(2, max(0, w // 2 - len(target_status) // 2), target_status[:w-1])
    stdscr.attroff(curses.color_pair(4))
    stdscr.addstr(3, 0, "-" * (w - 1))

def display_menu(stdscr, title, options, selected_index, start_y=5):
    """Displays a numbered menu with title and options."""
    h, w = stdscr.getmaxyx()
    
    # Clear previous menu area
    for y_clear in range(start_y, h - 1):
         stdscr.move(y_clear, 0)
         stdscr.clrtoeol()
         
    # Optional Title for the menu section itself
    if title:
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(start_y -1 , 2, title[:w-3])
        stdscr.attroff(curses.color_pair(1))

    for i, option_data in enumerate(options):
        y = start_y + i
        if y >= h - 1: # Ensure menu fits within screen height
             break 
        x = 4
        
        if isinstance(option_data, str):
            option_text = option_data
            enabled = True
        elif isinstance(option_data, dict):
            option_text = option_data.get("text", "Unknown Option")
            enabled = option_data.get("enabled", True)
        else:
            option_text = "Invalid Option Format"
            enabled = False
            
        display_text = f"{i}. {option_text}"
        
        if not enabled:
            stdscr.attron(curses.color_pair(7) | curses.A_DIM)
            stdscr.addstr(y, x, display_text[:w-x-1])
            stdscr.attroff(curses.color_pair(7) | curses.A_DIM)
        elif i == selected_index:
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(y, x, display_text[:w-x-1])
            stdscr.attroff(curses.color_pair(3))
        else:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(y, x, display_text[:w-x-1])
            stdscr.attroff(curses.color_pair(2))
            
    # Footer instruction
    footer_text = "Select an option using number keys or UP/DOWN arrows. Press ENTER to confirm. Q to go back/exit."
    stdscr.move(h-1, 0)
    stdscr.clrtoeol()
    stdscr.attron(curses.color_pair(5))
    stdscr.addstr(h-1, 2, footer_text[:w-3])
    stdscr.attroff(curses.color_pair(5))

def get_menu_choice(stdscr, options, start_y=5):
    """Handles navigation and selection in a numbered menu. Returns index or -1 for back/quit."""
    selected_index = 0
    curses.curs_set(0)
    stdscr.keypad(True)
    
    while True:
        # Redraw header and menu
        display_header(stdscr)
        display_menu(stdscr, "", options, selected_index, start_y)
        stdscr.refresh()
        
        key = stdscr.getch()

        if key == curses.KEY_UP:
            selected_index = (selected_index - 1 + len(options)) % len(options)
        elif key == curses.KEY_DOWN:
            selected_index = (selected_index + 1) % len(options)
        elif key == curses.KEY_ENTER or key in [10, 13]:
            option_data = options[selected_index]
            enabled = isinstance(option_data, str) or option_data.get("enabled", True)
            if not enabled:
                 show_message(stdscr, "Action Unavailable", ["This option requires specific conditions (e.g., interface in monitor mode)."], color_pair=5)
                 continue
            else:
                 return selected_index
        elif ord("0") <= key <= ord(str(len(options) - 1)):
             chosen_index = key - ord("0")
             option_data = options[chosen_index]
             enabled = isinstance(option_data, str) or option_data.get("enabled", True)
             if not enabled:
                  show_message(stdscr, "Action Unavailable", ["This option requires specific conditions (e.g., interface in monitor mode)."], color_pair=5)
                  continue
             else:
                  return chosen_index
        elif key == ord("q") or key == ord("Q"):
             return -1 # Indicate back/quit

def show_message(stdscr, title, message_lines, color_pair=4, wait_for_key=True):
    """Displays a simple message box, waits for key press if needed."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    display_header(stdscr) # Keep header consistent
    
    msg_start_y = 5
    msg_start_x = 4
    
    stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(msg_start_y, msg_start_x, f"--- {title} ---")
    stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
    
    stdscr.attron(curses.color_pair(color_pair))
    y = msg_start_y + 2
    for line in message_lines:
        if y < h - 2:
            stdscr.addstr(y, msg_start_x, line[:w - msg_start_x - 1])
            y += 1
    stdscr.attroff(curses.color_pair(color_pair))
    
    if wait_for_key:
        stdscr.addstr(h - 1, msg_start_x, "Press any key to continue...")
        stdscr.refresh()
        stdscr.getch()
    else:
        stdscr.refresh()

def select_item_from_list_menu(stdscr, title, items):
    """Allows selecting an item from a list presented as a menu. Returns selected item or None."""
    if not items:
        show_message(stdscr, title, ["No items available."], color_pair=5)
        return None
        
    options = items + ["<< Back"] # Add a back option
    choice_index = get_menu_choice(stdscr, options, start_y=5)
    
    if choice_index == -1 or choice_index == len(items): # Back or Q
        return None
    else:
        return items[choice_index]

# --- Core Logic Functions (Refined Flow) --- 

def select_network_interface(stdscr):
    """Handles the interface selection process."""
    global selected_interface, monitor_interface, interface_mode
    
    show_message(stdscr, "Interface Selection", ["Detecting wireless interfaces..."], color_pair=4, wait_for_key=False)
    interfaces = interface_manager.get_wireless_interfaces()
    
    if not interfaces:
        show_message(stdscr, "Error", ["No wireless interfaces found.", "Ensure you have a wireless card and proper drivers."], color_pair=6)
        return

    chosen_interface = select_item_from_list_menu(stdscr, "Select Wireless Interface", interfaces)
    
    if chosen_interface:
        if chosen_interface == selected_interface:
             show_message(stdscr, "Info", [f"Interface {selected_interface} is already selected."], color_pair=4)
             return
             
        # If changing interface, ensure the old one is back in managed mode
        if monitor_interface:
            show_message(stdscr, "Interface Change", [f"Disabling monitor mode on previous interface {monitor_interface}..."], color_pair=5, wait_for_key=False)
            curses.endwin()
            interface_manager.disable_monitor_mode(monitor_interface)
            stdscr = curses.initscr() # Re-init curses
            init_colors()
            monitor_interface = None # Clear monitor state
            
        selected_interface = chosen_interface
        interface_mode = "Managed" # New interface starts as Managed
        show_message(stdscr, "Interface Selected", [f"Selected interface: {selected_interface}", "Mode set to Managed."], color_pair=4)

def set_interface_monitor_mode(stdscr):
    """Handles putting the selected interface into monitor mode."""
    global selected_interface, monitor_interface, interface_mode
    
    if not selected_interface:
        show_message(stdscr, "Error", ["No interface selected. Please select an interface first (Option 0)."], color_pair=6)
        return
        
    if interface_mode == "Monitor":
        show_message(stdscr, "Info", [f"Interface {selected_interface} ({monitor_interface}) is already in Monitor mode."], color_pair=4)
        return

    show_message(stdscr, "Monitor Mode", [f"Attempting to enable monitor mode on {selected_interface}..."], color_pair=5, wait_for_key=False)
    # Use the enhanced function from interface_manager
    curses.endwin()
    print(f"\n[*] Enabling monitor mode for {selected_interface}...")
    success, new_mon_iface_name, error_msg = interface_manager.enable_monitor_mode_enhanced(selected_interface)
    
    stdscr = curses.initscr()
    curses.cbreak()
    stdscr.keypad(True)
    init_colors()

    if success:
        monitor_interface = new_mon_iface_name
        interface_mode = "Monitor"
        show_message(stdscr, "Success", [f"Monitor mode enabled on: {monitor_interface}"], color_pair=4)
    else:
        interface_mode = "Managed" # Revert to managed as monitor failed
        monitor_interface = None
        error_lines = ["Failed to enable monitor mode."]
        if error_msg:
             error_lines.append(f"Reason: {error_msg}")
        error_lines.append("Check drivers, permissions, or kill interfering processes.")
        show_message(stdscr, "Error", error_lines, color_pair=6)

def set_interface_managed_mode(stdscr):
    """Handles putting the selected interface back into managed mode."""
    global selected_interface, monitor_interface, interface_mode

    if not selected_interface:
        show_message(stdscr, "Error", ["No interface selected."], color_pair=6)
        return
        
    if interface_mode == "Managed":
        show_message(stdscr, "Info", [f"Interface {selected_interface} is already in Managed mode."], color_pair=4)
        return
        
    # If monitor_interface name is known, use it. Otherwise, try selected_interface.
    iface_to_stop = monitor_interface if monitor_interface else selected_interface
    if not iface_to_stop:
         show_message(stdscr, "Error", ["Cannot determine which interface to stop monitor mode on."], color_pair=6)
         return

    show_message(stdscr, "Managed Mode", [f"Attempting to disable monitor mode on {iface_to_stop}..."], color_pair=5, wait_for_key=False)
    curses.endwin()
    print(f"\n[*] Disabling monitor mode on {iface_to_stop}...")
    success, msg = interface_manager.disable_monitor_mode_enhanced(iface_to_stop, selected_interface)
    
    stdscr = curses.initscr()
    curses.cbreak()
    stdscr.keypad(True)
    init_colors()
    
    if success:
        monitor_interface = None
        interface_mode = "Managed"
        show_message(stdscr, "Success", [f"Monitor mode disabled.", f"Interface {selected_interface} is back in Managed mode."], color_pair=4)
    else:
        error_lines = [f"Failed to disable monitor mode on {iface_to_stop}."]
        if msg:
            error_lines.append(f"Reason: {msg}")
        error_lines.append("Interface state might be unstable. You may need to restart networking.")
        show_message(stdscr, "Error", error_lines, color_pair=6)
        # We might leave mode as Monitor here, as disabling failed

def run_network_scan_menu(stdscr):
    """Handles the network scanning process via menu."""
    global last_scan_results, selected_target_ap
    
    if interface_mode != "Monitor":
        show_message(stdscr, "Action Required", ["Interface must be in Monitor mode to scan.", "Use option 1 to enable monitor mode first."], color_pair=5)
        return
        
    show_message(stdscr, "Network Scan", ["Preparing to scan..."], color_pair=4, wait_for_key=False)
    
    curses.endwin()
    print(f"\n[*] Starting network scan on {monitor_interface}... Press Ctrl+C to stop.")
    scan_prefix = os.path.join(OUTPUT_BASE_DIR, "live_scan")
    scan_proc, scan_csv = scanner.start_airodump_scan(monitor_interface, output_prefix=scan_prefix)
    current_scan_results = []
    
    if scan_proc and scan_csv:
        try:
            while True:
                 aps, cls = scanner.parse_airodump_csv(scan_csv)
                 print(f"\r[*] Scanning... Found {len(aps)} APs, {len(cls)} Clients. (Ctrl+C to stop) ", end="")
                 time.sleep(1)
        except KeyboardInterrupt:
             print("\n[!] Scan stopped by user.")
        finally:
            scanner.stop_airodump_scan()
            current_scan_results, _ = scanner.parse_airodump_csv(scan_csv)
            # Clean up scan files
            for ext in [".csv", ".cap", ".kismet.csv", ".kismet.netxml", ".log.csv"]:
                try: os.remove(f"{scan_prefix}-01{ext}")
                except OSError: pass
    else:
        print("[!] Failed to start scan process.")
        time.sleep(2)

    stdscr = curses.initscr()
    curses.cbreak()
    stdscr.keypad(True)
    init_colors()
    
    last_scan_results = current_scan_results
    selected_target_ap = None # Reset target after new scan
    
    if last_scan_results:
        show_message(stdscr, "Scan Finished", [f"Scan found {len(last_scan_results)} APs.", "Target selection reset."], color_pair=4)
        # Optionally go directly to target selection menu
        # select_target_ap_menu(stdscr)
    else:
        show_message(stdscr, "Scan Finished", ["No networks found."], color_pair=5)

def select_target_ap_menu(stdscr):
    """Menu to select a target AP from the last scan results."""
    global selected_target_ap
    
    if not last_scan_results:
        show_message(stdscr, "Select Target", ["No scan results available. Please run a scan first (Option 3)."], color_pair=5)
        return
        
    # Format for display, keeping original index
    ap_display_map = {
        f"{idx+1}. {ap.get("essid", "<Hidden>")} ({ap.get("bssid")}) Ch:{ap.get("channel")} Enc:{ap.get("privacy")}": idx
        for idx, ap in enumerate(last_scan_results)
    }
    ap_display_list = list(ap_display_map.keys())
    
    chosen_display_string = select_item_from_list_menu(stdscr, "Select Target AP", ap_display_list)
    
    if chosen_display_string is not None:
        original_index = ap_display_map.get(chosen_display_string)
        if original_index is not None and 0 <= original_index < len(last_scan_results):
            selected_target_ap = last_scan_results[original_index]
            show_message(stdscr, "Target Selected", [
                f"Selected Target: {selected_target_ap.get("essid")}",
                f"BSSID: {selected_target_ap.get("bssid")}",
                f"Channel: {selected_target_ap.get("channel")}"
            ], color_pair=4)
        else:
             # Should not happen if map is correct
             selected_target_ap = None
             show_message(stdscr, "Error", ["Failed to map selection back to target."], color_pair=6)
    # else: User chose Back or Q, keep previous selection

def run_handshake_capture_menu(stdscr):
    """Handles handshake capture process."""
    if interface_mode != "Monitor":
        show_message(stdscr, "Action Required", ["Interface must be in Monitor mode."], color_pair=5)
        return
    if not selected_target_ap:
        show_message(stdscr, "Action Required", ["No target AP selected. Please select a target first (Option 4)."], color_pair=5)
        return
        
    # --- Handshake Submenu --- 
    handshake_options = [
        "Start Handshake Capture (with Deauth)",
        "Check Handshake File", # Placeholder
        "<< Back"
    ]
    
    while True:
        choice_index = get_menu_choice(stdscr, handshake_options, start_y=5)
        
        if choice_index == -1 or choice_index == len(handshake_options) - 1: # Back or Q
            break
            
        option_text = handshake_options[choice_index]
        
        if option_text == "Start Handshake Capture (with Deauth)":
            curses.endwin()
            print("\n--- Handshake Capture --- ")
            bssid = selected_target_ap.get("bssid")
            channel = selected_target_ap.get("channel")
            essid = selected_target_ap.get("essid", bssid)
            print(f"[*] Target: {essid} ({bssid}) on Ch: {channel}")
            capture_prefix = os.path.join(OUTPUT_BASE_DIR, f"handshake_{bssid.replace(":", "")}")
            cap_file_base = f"{capture_prefix}-01.cap"
            
            print("[*] Starting packet capture...")
            capture_proc, cap_file = handshake_capture.start_handshake_capture(monitor_interface, bssid, channel, capture_prefix)
            
            if not capture_proc:
                print("[!] Failed to start capture process.")
                time.sleep(2)
            else:
                print(f"[*] Capture started. Saving to {cap_file_base}")
                print("[*] Sending deauthentication packets...")
                print("[*] Press Ctrl+C to stop capture and deauth attack.")
                deauth_proc = handshake_capture.start_deauth_attack(monitor_interface, bssid)
                
                handshake_found = False
                try:
                    timeout = time.time() + CAPTURE_TIMEOUT_DEFAULT
                    while time.time() < timeout:
                        print(f"\r[*] Monitoring for handshake... (Ctrl+C to stop) ", end="")
                        if os.path.exists(cap_file_base) and handshake_capture.check_handshake(cap_file_base, bssid):
                            print("\n[+] WPA Handshake captured!")
                            handshake_found = True
                            break
                        time.sleep(5)
                    if not handshake_found:
                         print(f"\n[!] Handshake capture timed out or not detected in {int(CAPTURE_TIMEOUT_DEFAULT)}s.")
                         
                except KeyboardInterrupt:
                    print("\n[!] Capture interrupted by user.")
                finally:
                    handshake_capture.stop_handshake_capture()
                    handshake_capture.stop_deauth_attack()
                    print("[*] Capture and deauth processes stopped.")
                    # Final check
                    if not handshake_found and os.path.exists(cap_file_base) and handshake_capture.check_handshake(cap_file_base, bssid):
                         print("[+] WPA Handshake found in file after stopping.")
                    elif not handshake_found:
                         print(f"[!] Handshake not found in {cap_file_base}.")
                         
            print("\nReturning to Handshake menu...")
            time.sleep(3)
            stdscr = curses.initscr()
            curses.cbreak()
            stdscr.keypad(True)
            init_colors()
            
        elif option_text == "Check Handshake File":
             show_message(stdscr, "Coming Soon", ["Function to manually check .cap files is pending."], color_pair=5)

# --- Placeholder Submenus --- 

def run_wps_attacks_menu(stdscr):
    if interface_mode != "Monitor":
        show_message(stdscr, "Action Required", ["Interface must be in Monitor mode."], color_pair=5)
        return
        
    wps_options = [
        "Scan for WPS Networks (wash)",
        "Run Pixie Dust Attack (reaver)", # Placeholder
        "Run Brute Force Attack (reaver/bully)", # Placeholder
        "<< Back"
    ]
    while True:
        choice_index = get_menu_choice(stdscr, wps_options, start_y=5)
        if choice_index == -1 or choice_index == len(wps_options) - 1:
            break
        show_message(stdscr, "Coming Soon", [f"WPS Attack function ", f"'{wps_options[choice_index]}' integration is pending."], color_pair=5)

def run_evil_twin_menu(stdscr):
    if interface_mode != "Monitor": # Might need managed mode for AP creation depending on setup
        show_message(stdscr, "Action Required", ["Interface might need to be in Monitor or Managed mode depending on attack."], color_pair=5)
        # return # Allow entry for now
        
    evil_twin_options = [
        "Create Basic Evil Twin AP (No Portal)", # Placeholder
        "Create Evil Twin with Captive Portal", # Placeholder
        "<< Back"
    ]
    while True:
        choice_index = get_menu_choice(stdscr, evil_twin_options, start_y=5)
        if choice_index == -1 or choice_index == len(evil_twin_options) - 1:
            break
        show_message(stdscr, "Coming Soon", [f"Evil Twin function ", f"'{evil_twin_options[choice_index]}' integration is pending."], color_pair=5)

def run_offline_decrypt_menu(stdscr):
    decrypt_options = [
        "Crack Handshake with Dictionary (aircrack-ng)", # Placeholder
        "Crack Handshake with Hashcat", # Placeholder
        "Convert .cap to Hashcat format", # Placeholder
        "<< Back"
    ]
    while True:
        choice_index = get_menu_choice(stdscr, decrypt_options, start_y=5)
        if choice_index == -1 or choice_index == len(decrypt_options) - 1:
            break
        show_message(stdscr, "Coming Soon", [f"Offline Decrypt function ", f"'{decrypt_options[choice_index]}' integration is pending."], color_pair=5)

# --- Main Application Loop --- 

def main_app(stdscr):
    """Main application function wrapped by curses."""
    global selected_interface, monitor_interface, interface_mode, last_scan_results, selected_target_ap
    
    curses.curs_set(0)
    init_colors()
    stdscr.nodelay(False)
    stdscr.keypad(True)

    # Initial Checks
    show_message(stdscr, "Initialization", ["Checking dependencies..."], color_pair=4, wait_for_key=False)
    time.sleep(0.5) # Brief pause
    success, missing, found = dependency_manager.check_dependencies()
    if not success:
        error_msg = ["Essential dependencies missing:"] + missing
        error_msg.append("Please install them and try again.")
        show_message(stdscr, "Dependency Error", error_msg, color_pair=6)
        return
    show_message(stdscr, "Initialization", ["Dependencies OK."], color_pair=4)

    if not os.path.exists(OUTPUT_BASE_DIR):
        try:
            os.makedirs(OUTPUT_BASE_DIR)
        except OSError as e:
            show_message(stdscr, "Error", [f"Failed to create output directory:", str(e)], color_pair=6)
            return

    # --- Main Menu Definition ---
    def get_main_menu_options():
        is_monitor = (interface_mode == "Monitor")
        is_managed = (interface_mode == "Managed")
        has_iface = (selected_interface is not None)
        has_target = (selected_target_ap is not None)
        has_scan = bool(last_scan_results)
        
        return [
            # 0
            "Select network interface",
            # 1
            {"text": "Put interface in monitor mode", "enabled": has_iface and is_managed},
            # 2
            {"text": "Put interface in managed mode", "enabled": has_iface and is_monitor},
            # --- Attack/Tool Menus ---
            # 3
            {"text": "Scan for Networks", "enabled": is_monitor},
            # 4
            {"text": "Select Target AP", "enabled": has_scan},
            # 5
            {"text": "Handshake/PMKID tools menu", "enabled": is_monitor and has_target},
            # 6
            {"text": "WPS attacks menu", "enabled": is_monitor},
            # 7
            {"text": "WEP attacks menu", "enabled": False}, # WEP is deprecated
            # 8
            {"text": "Evil Twin attacks menu", "enabled": has_iface}, # May need managed or monitor
            # 9
            {"text": "Offline WPA/WPA2 decrypt menu", "enabled": True}, # Can run anytime
            # --- Other ---
            # 10
            "About & Credits",
            # 11
            "Exit script"
        ]

    # --- Main Loop ---
    while True:
        main_menu_options = get_main_menu_options()
        choice_index = get_menu_choice(stdscr, main_menu_options)

        if choice_index == -1: # Q pressed
             # Find exit option index
             exit_indices = [i for i, opt in enumerate(main_menu_options) if isinstance(opt, str) and "exit" in opt.lower()]
             if exit_indices:
                 choice_index = exit_indices[0]
             else:
                 # If no explicit exit, Q might mean quit the app
                 confirm_quit = select_item_from_list_menu(stdscr, "Confirm Exit", ["No", "Yes"])
                 if confirm_quit == "Yes":
                     break
                 else:
                     continue # Go back to menu
            
        selected_option_data = main_menu_options[choice_index]
        option_text = selected_option_data if isinstance(selected_option_data, str) else selected_option_data.get("text")

        # Handle choices
        if option_text == "Exit script":
            confirm_quit = select_item_from_list_menu(stdscr, "Confirm Exit", ["No", "Yes"])
            if confirm_quit == "Yes":
                break
        elif option_text == "Select network interface":
            select_network_interface(stdscr)
        elif option_text == "Put interface in monitor mode":
            set_interface_monitor_mode(stdscr)
        elif option_text == "Put interface in managed mode":
            set_interface_managed_mode(stdscr)
        elif option_text == "Scan for Networks":
            run_network_scan_menu(stdscr)
        elif option_text == "Select Target AP":
            select_target_ap_menu(stdscr)
        elif option_text == "Handshake/PMKID tools menu":
            run_handshake_capture_menu(stdscr)
        elif option_text == "WPS attacks menu":
            run_wps_attacks_menu(stdscr)
        elif option_text == "WEP attacks menu":
             show_message(stdscr, "WEP Attacks", ["WEP is insecure and considered broken.", "This module is not implemented."], color_pair=5)
        elif option_text == "Evil Twin attacks menu":
             run_evil_twin_menu(stdscr)
        elif option_text == "Offline WPA/WPA2 decrypt menu":
             run_offline_decrypt_menu(stdscr)
        elif option_text == "About & Credits":
             show_message(stdscr, "About", [
                 f"Wireless Audit Tool v{APP_VERSION}", 
                 "Inspired by airgeddon", 
                 "Developed by Manus AI Agent",
                 "For educational purposes only."
                 ], color_pair=4)
        else:
            show_message(stdscr, "Error", [f"Unhandled menu option: {option_text}"], color_pair=6)

    # --- Cleanup on Exit --- #
    curses.endwin()
    print("[*] Performing cleanup...")
    scanner.stop_airodump_scan()
    handshake_capture.stop_handshake_capture()
    handshake_capture.stop_deauth_attack()
    wps_attacks.stop_wash_scan()
    evil_twin.stop_evil_twin()
    
    if monitor_interface:
        print(f"[*] Disabling monitor mode on {monitor_interface}...")
        interface_manager.disable_monitor_mode_enhanced(monitor_interface, selected_interface)
    print(f"--- Wireless Audit Tool v{APP_VERSION} Finished --- ")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This tool requires root privileges.")
        print("Please run using sudo.")
        sys.exit(1)

    stdscr = None # Define stdscr in outer scope for finally block
    try:
        stdscr = curses.initscr()
        curses.cbreak()
        curses.noecho()
        stdscr.keypad(True)
        main_app(stdscr)
    except Exception as e:
        if stdscr:
             curses.nocbreak(); stdscr.keypad(False); curses.echo()
             curses.endwin()
        print("\n[!] An unexpected error occurred:")
        traceback.print_exc()
        sys.exit(1)
    except KeyboardInterrupt:
         if stdscr:
             curses.nocbreak(); stdscr.keypad(False); curses.echo()
             curses.endwin()
         print("\n[!] Operation interrupted by user. Exiting gracefully.")
         print("[*] Performing final cleanup...")
         # Add cleanup calls here as well, similar to normal exit
         scanner.stop_airodump_scan()
         handshake_capture.stop_handshake_capture()
         # ... other cleanup ...
         print("--- Exited --- ")
         sys.exit(0)
    finally:
        if stdscr and not stdscr.isendwin():
             curses.nocbreak(); stdscr.keypad(False); curses.echo()
             curses.endwin()

