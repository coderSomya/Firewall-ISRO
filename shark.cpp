#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>

// Function to perform reverse DNS lookup
std::string reverse_dns_lookup(const char* ip) {
    struct hostent* host = gethostbyaddr((const void*)ip, strlen(ip), AF_INET);
    if (host != nullptr) {
        return std::string(host->h_name);
    }
    std::cerr << "Reverse DNS lookup failed for IP: " << ip << std::endl;
    return "Unknown Domain";
}

// Packet capture handler function
void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14);  // Skip Ethernet header (14 bytes)
    struct in_addr src_ip = ip_header->ip_src;
    struct in_addr dest_ip = ip_header->ip_dst;
    
    // Convert the source and destination IP addresses to string
    std::string src_ip_str = inet_ntoa(src_ip);
    std::string dest_ip_str = inet_ntoa(dest_ip);

    // Perform reverse DNS lookup for destination IP
    std::string dest_domain = reverse_dns_lookup(dest_ip_str.c_str());
    
    // Print information
    std::cout << "Source IP: " << src_ip_str << " | Destination IP: " << dest_ip_str << std::endl;
    std::cout << "Destination Domain: " << dest_domain << std::endl;
    
    // You can add further processing here (e.g., capturing port, application, etc.)
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the network device for packet capture (replace "en0" with the correct interface name)
    pcap_t* handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening pcap: " << errbuf << std::endl;
        return 1;
    }

    // Start capturing packets
    if (pcap_loop(handle, 0, packet_handler, nullptr) < 0) {
        std::cerr << "Error capturing packets: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    // Close the capture handle after we're done
    pcap_close(handle);

    return 0;
}
