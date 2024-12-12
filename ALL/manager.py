import subprocess
import re
import requests

def get_ips_in_network():
    """
    Get all IP addresses in the local network using 'arp -a'.
    Returns a list of IP addresses.
    """
    ips = []
    try:
        # Run the arp -a command
        result = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, text=True)
        
        # Parse the output
        for line in result.stdout.split("\n"):
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ips.append(match.group(1))
    except Exception as e:
        print(f"Error fetching IP addresses: {e}")
    return ips

def hit_server_api(ip, port=5000, app_name="my_app", destination_port=8080):
    """
    Hit the API endpoint at <ip>:<port>/block with given parameters.
    """
    url = f"http://{ip}:{port}/block"
    params = {"app_name": app_name, "destination_port": destination_port}
    try:
        response = requests.post(url, params=params, timeout=2)
        if response.status_code == 200:
            print(f"Success: {url} - {response.json()}")
        else:
            print(f"Failed: {url} - Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {url}: {e}")

if __name__ == "__main__":
    print("Fetching IPs in the network...")
    ips = get_ips_in_network()
    
    if not ips:
        print("No IP addresses found in the network.")
    else:
        print(f"Found IPs: {ips}")
            # hit_server_api(ip)
