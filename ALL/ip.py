import subprocess
import re

def get_devices_from_arp():
    """
    Uses 'arp -a' to get a list of devices connected to the same network.
    Returns a list of dictionaries containing IP and MAC addresses.
    """
    devices = []
    try:
        # Run the arp -a command
        result = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, text=True)
        
        # Parse the output
        for line in result.stdout.split("\n"):
            # Regex to extract IP and MAC addresses
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*?\s+([a-fA-F0-9:-]{17})", line)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                devices.append({"ip": ip, "mac": mac})
    except Exception as e:
        print(f"Error running 'arp -a': {e}")
    
    return devices

if __name__ == "__main__":
    devices = get_devices_from_arp()
    if devices:
        print("Devices connected to the same network:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
    else:
        print("No devices found or unable to retrieve ARP table.")
