#!/usr/bin/env python3
import subprocess
import re
import time
from datetime import datetime

def get_connected_devices():
    # Get ARP table
    arp_output = subprocess.check_output("arp -a", shell=True).decode()
    
    # Get DHCP leases (specific to macOS)
    try:
        with open('/var/db/dhcpd_leases', 'r') as f:
            dhcp_leases = f.read()
    except:
        dhcp_leases = ""

    devices = []
    
    # Parse ARP table
    for line in arp_output.split('\n'):
        if line.strip():
            match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{17})', line)
            if match:
                ip = match.group(1)
                mac = match.group(2).upper()
                
                # Try to get hostname
                try:
                    hostname = subprocess.check_output(f"host {ip}", shell=True).decode().split()[-1].rstrip('.')
                except:
                    hostname = "Unknown"
                
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
    
    return devices

def monitor_devices():
    print("Starting device monitor...")
    print("Press Ctrl+C to stop monitoring")
    
    known_devices = {}
    
    try:
        while True:
            current_devices = get_connected_devices()
            
            for device in current_devices:
                mac = device['mac']
                if mac not in known_devices:
                    print("\nNew device detected!")
                    print(f"IP Address: {device['ip']}")
                    print(f"MAC Address: {device['mac']}")
                    print(f"Hostname: {device['hostname']}")
                    print(f"First seen: {device['last_seen']}")
                    print("-" * 50)
                
                known_devices[mac] = device
            
            time.sleep(5)  # Check every 5 seconds
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
        
    # Print final summary
    print("\nConnected Devices Summary:")
    print("-" * 50)
    for device in known_devices.values():
        print(f"IP: {device['ip']:<15} MAC: {device['mac']:<17} Hostname: {device['hostname']}")

if __name__ == "__main__":
    monitor_devices()