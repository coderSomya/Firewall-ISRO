import socket
import dns.resolver
import concurrent.futures
import requests
import json
import logging
import sys
import time
import argparse
from typing import Set, List, Dict
import ipaddress
import ssl
import OpenSSL.SSL
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import random
import threading
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ExhaustiveIPResolver:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # Multiple DNS servers for redundancy
        self.dns_servers = [
            '8.8.8.8',        # Google
            '1.1.1.1',        # Cloudflare
            '9.9.9.9',        # Quad9
            '208.67.222.222', # OpenDNS
            '8.26.56.26',     # Comodo
            '64.6.64.6'       # Verisign
        ]
        
        # Known CDN and cloud providers
        self.providers = {
            'cloudflare': ['cloudflare.com', '103.21.244.0/22', '103.22.200.0/22'],
            'akamai': ['akamai.net', '23.32.0.0/11', '104.64.0.0/10'],
            'fastly': ['fastly.net', '151.101.0.0/16', '23.235.32.0/20'],
            'cloudfront': ['cloudfront.net', '205.251.192.0/19', '204.246.164.0/22'],
            'google': ['google.com', '35.190.0.0/17', '130.211.0.0/16'],
            'azure': ['azure.com', '13.64.0.0/11', '13.96.0.0/13'],
            'aws': ['amazonaws.com', '3.0.0.0/9', '3.128.0.0/9']
        }
        
        # Common subdomain patterns
        self.subdomain_patterns = [
            'www', 'cdn', 'static', 'assets', 'media', 'images', 'video',
            'api', 'ws', 'dns', 'ns', 'mail', 'smtp', 'pop', 'imap',
            'ftp', 'sftp', 'dev', 'stage', 'staging', 'test', 'demo',
            'portal', 'admin', 'secure', 'login', 'auth', 'vpn', 'remote',
            'cloud', 'edge', 'global', 'prod', 'production', 'app', 'apps',
            'streaming', 'download', 'uploads', 'content', 'data', 'store',
            'm', 'mobile', 'wap', 'services', 'service', 'apis', 'gateway'
        ]

    def try_all_dns_servers(self, domain: str, record_type: str) -> Set[str]:
        """Try resolving domain using multiple DNS servers"""
        results = set()
        
        def try_dns_server(server):
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [socket.gethostbyname(server)]
                resolver.timeout = 2
                resolver.lifetime = 2
                answers = resolver.resolve(domain, record_type)
                return {str(rdata) for rdata in answers}
            except Exception:
                return set()

        with ThreadPoolExecutor(max_workers=len(self.dns_servers)) as executor:
            futures = {executor.submit(try_dns_server, server): server 
                      for server in self.dns_servers}
            for future in as_completed(futures):
                results.update(future.result())
        
        return results

    def get_all_dns_records(self, domain: str) -> Dict[str, Set[str]]:
        """Get all possible DNS records for a domain"""
        records = defaultdict(set)
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SRV', 'TXT']
        
        for record_type in record_types:
            records[record_type].update(self.try_all_dns_servers(domain, record_type))
            
        return records

    def get_ip_from_host(self, host: str) -> Set[str]:
        """Get IPs using socket methods"""
        ips = set()
        
        # Try different port combinations
        for port in [None, 80, 443, 8080, 8443]:
            for family in [socket.AF_INET, socket.AF_INET6]:
                try:
                    addrinfo = socket.getaddrinfo(host, port, family)
                    for addr in addrinfo:
                        ip = addr[4][0]
                        if self.is_valid_ip(ip):
                            ips.add(ip)
                except Exception:
                    continue
                    
        return ips

    def get_ssl_sans(self, domain: str) -> Set[str]:
        """Get Subject Alternative Names from SSL certificate"""
        sans = set()
        
        def try_port(port):
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        if 'subjectAltName' in cert:
                            sans.update(name[1] for name in cert['subjectAltName'] 
                                      if name[0] == 'DNS')
            except Exception:
                pass

        # Try multiple ports in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.map(try_port, [443, 8443])
            
        return sans

    def get_http_ips(self, domain: str) -> Set[str]:
        """Get IPs by making HTTP requests with different methods"""
        ips = set()
        
        def try_http_method(url, method):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': '*/*'
                }
                response = requests.request(
                    method, 
                    url, 
                    headers=headers,
                    timeout=5,
                    allow_redirects=True,
                    verify=False
                )
                parsed = urlparse(response.url)
                ips.update(self.get_ip_from_host(parsed.netloc))
            except Exception:
                pass

        protocols = ['http', 'https']
        methods = ['GET', 'HEAD', 'OPTIONS']
        
        with ThreadPoolExecutor(max_workers=len(protocols) * len(methods)) as executor:
            futures = []
            for protocol in protocols:
                for method in methods:
                    url = f"{protocol}://{domain}"
                    futures.append(
                        executor.submit(try_http_method, url, method)
                    )
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    continue
                    
        return ips

    def enumerate_subdomains(self, domain: str) -> Set[str]:
        """Enumerate possible subdomains"""
        subdomains = set()
        
        def check_subdomain(pattern):
            subdomain = f"{pattern}.{domain}"
            try:
                if self.get_ip_from_host(subdomain):
                    subdomains.add(subdomain)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_subdomain, self.subdomain_patterns)
            
        return subdomains

    def get_reverse_dns(self, ip: str) -> Set[str]:
        """Get reverse DNS records"""
        try:
            return set([socket.gethostbyaddr(ip)[0]])
        except Exception:
            return set()

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_provider_info(self, ip: str) -> str:
        """Identify if IP belongs to a known provider"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for provider, ranges in self.providers.items():
                for range_str in ranges:
                    try:
                        if ip_obj in ipaddress.ip_network(range_str):
                            return provider
                    except ValueError:
                        continue
        except ValueError:
            pass
        return None

    def resolve_all(self, domain: str, verbose: bool = False) -> Dict[str, Set[str]]:
        """Exhaustively resolve all possible IPs for a domain"""
        results = {
            'direct_ips': set(),
            'subdomain_ips': set(),
            'cdn_ips': set(),
            'alt_ips': set()
        }
        
        if verbose:
            print(f"\nResolving {domain}...")

        # Get all DNS records
        dns_records = self.get_all_dns_records(domain)
        results['direct_ips'].update(dns_records['A'])
        results['direct_ips'].update(dns_records['AAAA'])
        
        if verbose:
            print(f"Found {len(results['direct_ips'])} direct IPs")

        # Get IPs from socket methods
        results['direct_ips'].update(self.get_ip_from_host(domain))
        
        # Get IPs from HTTP methods
        results['alt_ips'].update(self.get_http_ips(domain))
        
        if verbose:
            print("Checking subdomains...")
            
        # Check subdomains
        subdomains = self.enumerate_subdomains(domain)
        for subdomain in subdomains:
            results['subdomain_ips'].update(self.get_ip_from_host(subdomain))
            
        if verbose:
            print(f"Found {len(subdomains)} subdomains")

        # Get IPs from SSL certificate SANs
        sans = self.get_ssl_sans(domain)
        for san in sans:
            results['alt_ips'].update(self.get_ip_from_host(san))
            
        if verbose:
            print(f"Found {len(sans)} SSL alternative names")

        # Follow CNAME records
        for cname in dns_records['CNAME']:
            results['cdn_ips'].update(self.get_ip_from_host(str(cname)))

        # Validate all IPs
        for category in results:
            results[category] = {ip for ip in results[category] if self.is_valid_ip(ip)}

        return results

def main():
    parser = argparse.ArgumentParser(description='Exhaustive Domain IP Resolver')
    parser.add_argument('domain', help='Domain to resolve')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    resolver = ExhaustiveIPResolver()
    
    print(f"\nPerforming exhaustive IP resolution for: {args.domain}")
    print("-" * 60)
    
    try:
        results = resolver.resolve_all(args.domain, args.verbose)
        
        # Aggregate and deduplicate results
        all_ips = set()
        for category, ips in results.items():
            all_ips.update(ips)
        
        print(f"\nFound {len(all_ips)} unique IPs:")
        for ip in sorted(all_ips):
            provider = resolver.get_provider_info(ip)
            provider_info = f" ({provider})" if provider else ""
            print(f"  - {ip}{provider_info}")
            
        # Print summary
        print("\nSummary:")
        print(f"  Direct IPs: {len(results['direct_ips'])}")
        print(f"  Subdomain IPs: {len(results['subdomain_ips'])}")
        print(f"  CDN IPs: {len(results['cdn_ips'])}")
        print(f"  Alternative IPs: {len(results['alt_ips'])}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)

if __name__ == "__main__":
    main()