from scapy.all import sniff, IP
import logging
from datetime import datetime

# Configure logging to log to a file
logging.basicConfig(
    filename="traffic_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def log_packet(packet):
    """Callback to log source and destination IPs of captured packets."""
    if IP in packet:
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        logging.info(f"Source: {src_ip}, Destination: {dest_ip}")

def main():
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    try:
        # Sniff packets on all interfaces, filtering for IP traffic
        sniff(filter="ip", prn=log_packet, store=False)
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
    except PermissionError:
        print("Run the script as an administrator (sudo on Linux).")
    except Exception as e:
        print(f"An error occurred: {e}")

main()