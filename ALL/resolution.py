import socket
import dns.resolver
import concurrent.futures
import requests
import json
import logging
from typing import Set, List
import sys
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedDomainResolver:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        self.all_ips = set()

    def get_socket_ips(self, domain: str) -> Set[str]:
        """Get IPs using socket.getaddrinfo()"""
        ips = set()
        try:
            # Try different port combinations to get more IPs
            for port in [80, 443, None]:
                for family in [socket.AF_INET, socket.AF_INET6]:
                    try:
                        addrinfo = socket.getaddrinfo(domain, port, family)
                        for addr in addrinfo:
                            ip = addr[4][0]
                            ips.add(ip)
                    except:
                        continue
        except Exception as e:
            logger.error(f"Socket error for {domain}: {e}")
        return ips

    def get_dns_ips(self, domain: str) -> Set[str]:
        """Get IPs using DNS resolution"""
        ips = set()
        for record_type in ['A', 'AAAA']:
            try:
                answers = self.resolver.resolve(domain, record_type)
                for rdata in answers:
                    ips.add(rdata.address)
            except Exception as e:
                logger.debug(f"DNS {record_type} error for {domain}: {e}")
        return ips

    def get_cname_targets(self, domain: str) -> Set[str]:
        """Get all CNAME targets"""
        targets = set()
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                target = str(rdata.target).rstrip('.')
                targets.add(target)
                # Recursively resolve CNAME targets
                targets.update(self.get_cname_targets(target))
        except:
            pass
        return targets

    def get_cdn_ips(self, domain: str) -> Set[str]:
        """Get IPs from potential CDN endpoints"""
        ips = set()
        
        # Try common CDN subdomains
        cdn_prefixes = ['www', 'cdn', 'static', 'assets', 'media', 'images']
        for prefix in cdn_prefixes:
            cdn_domain = f"{prefix}.{domain}"
            ips.update(self.get_dns_ips(cdn_domain))
            ips.update(self.get_socket_ips(cdn_domain))

        return ips

    def get_http_ips(self, domain: str) -> Set[str]:
        """Get IPs by making HTTP requests"""
        ips = set()
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.head(url, timeout=3, allow_redirects=True)
                if response.headers.get('server'):
                    # If we get a response, try to resolve the final URL
                    final_domain = response.url.split('/')[2]
                    ips.update(self.get_dns_ips(final_domain))
                    ips.update(self.get_socket_ips(final_domain))
            except:
                continue
        return ips

    def resolve_all(self, domain: str) -> Set[str]:
        """Resolve all possible IPs for a domain using multiple methods"""
        all_ips = set()
        
        # Direct resolution methods
        all_ips.update(self.get_dns_ips(domain))
        all_ips.update(self.get_socket_ips(domain))
        
        # Get CNAME targets and resolve them
        cname_targets = self.get_cname_targets(domain)
        for target in cname_targets:
            all_ips.update(self.get_dns_ips(target))
            all_ips.update(self.get_socket_ips(target))
        
        # Get CDN IPs
        all_ips.update(self.get_cdn_ips(domain))
        
        # Get IPs from HTTP requests
        all_ips.update(self.get_http_ips(domain))

        # Remove any invalid IPs
        all_ips = {ip for ip in all_ips if self.is_valid_ip(ip)}
        
        return all_ips

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate if string is a valid IP address"""
        try:
            # Try parsing as IPv4
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                # Try parsing as IPv6
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False

    def block_ip_windows(self, ip: str, rule_name: str):
        """Add Windows Firewall rules to block an IP"""
        import subprocess
        
        try:
            # Block inbound
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_in',
                'dir=in',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ], check=True)

            # Block outbound
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_out',
                'dir=out',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ], check=True)
            
            return True
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python enhanced_resolver.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    resolver = EnhancedDomainResolver()
    
    print(f"\nResolving all IPs for {domain}...")
    print("-" * 50)
    
    ips = resolver.resolve_all(domain)
    
    print(f"\nFound {len(ips)} unique IPs:")
    for ip in sorted(ips):
        print(f"  - {ip}")
    
    if ips:
        choice = input("\nDo you want to block these IPs in Windows Firewall? (y/n): ")
        if choice.lower() == 'y':
            print("\nAdding firewall rules...")
            rule_name = f"Block_{domain.replace('.', '_')}"
            for ip in ips:
                if resolver.block_ip_windows(ip, f"{rule_name}_{ip}"):
                    print(f"Blocked {ip}")
                else:
                    print(f"Failed to block {ip}")

if __name__ == "__main__":
    main()