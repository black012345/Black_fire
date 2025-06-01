# -*- coding: utf-8 -*-
"""Manages checking for external tool dependencies."""

import shutil
import subprocess

# List of essential external tools required by the audit tool
# This list should be expanded based on the implemented attack modules
ESSENTIAL_TOOLS = [
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
    "wash",
    "reaver",
    "bully",
    "hostapd",
    "dnsmasq",
    "iw",
    "rfkill",
    # Add other tools as needed, e.g., hashcat, john, bettercap, mdk4
]

# Optional tools that enhance functionality but are not strictly required
OPTIONAL_TOOLS = [
    "hashcat",
    "john",
    "ettercap",
    "sslstrip",
    "bettercap",
    "mdk4",
    "hcxdumptool",
    "hcxpcapngtool",
]

def check_tool_exists(tool_name):
    """Checks if a tool exists in the system's PATH."""
    return shutil.which(tool_name) is not None

def check_dependencies():
    """Checks for all essential and optional dependencies."""
    print("[*] Checking for essential dependencies...")
    missing_essential = []
    for tool in ESSENTIAL_TOOLS:
        if not check_tool_exists(tool):
            missing_essential.append(tool)
            print(f"[!] Missing essential tool: {tool}")
        else:
            print(f"[+] Found: {tool}")

    print("\n[*] Checking for optional dependencies...")
    missing_optional = []
    for tool in OPTIONAL_TOOLS:
        if not check_tool_exists(tool):
            missing_optional.append(tool)
            print(f"[-] Missing optional tool: {tool}")
        else:
            print(f"[+] Found: {tool}")

    if missing_essential:
        print("\n[!] Error: One or more essential tools are missing.")
        print("Please install the following tools to ensure basic functionality:")
        for tool in missing_essential:
            print(f"  - {tool}")
        # Optionally, provide installation hints based on OS (e.g., apt install ...)
        # For now, just raise an error or exit
        # raise EnvironmentError("Missing essential dependencies")
        return False, missing_essential, missing_optional
    else:
        print("\n[+] All essential dependencies are met.")
        if missing_optional:
            print("\n[-] Note: Some optional tools are missing. Certain advanced features might be unavailable.")
            print("Consider installing: ", ", ".join(missing_optional))
        return True, [], missing_optional

if __name__ == "__main__":
    # Example usage when run directly
    success, missing_ess, missing_opt = check_dependencies()
    if not success:
        print("\nExiting due to missing essential dependencies.")
    else:
        print("\nDependency check complete.")

