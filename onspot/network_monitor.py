#!/usr/bin/env python3
from mitmproxy import ctx
from mitmproxy.tools.main import mitmdump
import json
import os

# Load block rules from config
def load_rules():
    try:
        with open('block_rules.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Initialize blocking rules
block_rules = {
    "client_blocks": {
        "00:11:22:33:44:55": ["b.com", "blocked-site.com"],  # Example MAC address and blocked sites
    }
}

def get_client_ip():
    """Get client IP from flow"""
    client_ip = ctx.client_conn.peername[0]
    return client_ip

def request(flow):
    """Handle each HTTP request"""
    client_ip = get_client_ip()
    host = flow.request.pretty_host
    
    # Check if client is blocked from accessing this host
    for mac, blocked_sites in block_rules["client_blocks"].items():
        if host in blocked_sites:
            ctx.log.info(f"Blocking access to {host} for client {client_ip}")
            flow.kill()  # Block the request
            return

    # Log allowed requests
    ctx.log.info(f"Allowed access to {host} for client {client_ip}")

def running():
    """Called when the proxy starts"""
    ctx.log.info("Proxy started - Monitoring network traffic")

# Save the current rules to file
def save_rules():
    with open('block_rules.json', 'w') as f:
        json.dump(block_rules, f, indent=2)

# Add a new blocking rule
def add_block_rule(mac_address, blocked_site):
    if mac_address not in block_rules["client_blocks"]:
        block_rules["client_blocks"][mac_address] = []
    block_rules["client_blocks"][mac_address].append(blocked_site)
    save_rules()

if __name__ == "__main__":
    # Save initial rules
    save_rules()
    
    # Start the proxy
    mitmdump([
        "-s", __file__,  # Load this script
        "-p", "8080",    # Port to run proxy on
        "--set", "block_hosting=false",  # Don't block connections to the proxy
    ])