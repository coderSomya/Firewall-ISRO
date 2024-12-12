import subprocess
import socket

def get_network_devices():
    devices = []

    # Run the 'arp -a' command
    output = subprocess.check_output("arp -a", shell=True).decode()
    
    # Parse the output
    for line in output.split("\n"):
        if line.strip():
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[1].strip("()")
                mac = parts[3]
                hostname = resolve_hostname(ip)
                devices.append({"IP": ip, "MAC": mac, "Hostname": hostname})
    return devices

def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = None
    return hostname

def display_devices(devices):
    print(f"{'IP Address':<20}{'MAC Address':<20}{'Hostname':<30}")
    print("="*70)
    for device in devices:
        print(f"{device['IP']:<20}{device['MAC']:<20}{device['Hostname']:<30}")

if __name__ == "__main__":
    devices = get_network_devices()
    display_devices(devices)
