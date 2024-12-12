from scapy.all import ARP, Ether, srp

def get_connected_devices(network: str):
    """
    Discover all devices connected to the same network.

    Args:
        network (str): The network range in CIDR format (e.g., "192.168.1.0/24").

    Returns:
        list of dict: A list of dictionaries containing IP and MAC addresses of connected devices.
    """
    devices = []
    try:
        # Create an ARP request packet
        arp_request = ARP(pdst=network)
        # Create an Ethernet frame to encapsulate the ARP request
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine the Ethernet frame and ARP request
        packet = ether / arp_request
        
        # Send the packet and receive responses
        result = srp(packet, timeout=2, verbose=False)[0]
        
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    except Exception as e:
        print(f"Error: {e}")
    
    return devices

# Example usage:
if __name__ == "__main__":
    network_range = "10.10.0.0/255"  # Adjust this based on your network
    connected_devices = get_connected_devices(network_range)
    
    print("Connected devices:")
    for device in connected_devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
