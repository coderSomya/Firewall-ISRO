#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <fstream>

// Define a log file to capture the source and destination IP addresses
std::ofstream logFile("logs.txt", std::ios::out | std::ios::app);

// Callback function for each captured packet
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Parse the IP header from the captured packet
    struct ip *ip_header = (struct ip *)(packet + 14);  // Skip Ethernet header (14 bytes)
    struct in_addr src_ip = ip_header->ip_src;
    struct in_addr dest_ip = ip_header->ip_dst;

    // Log the source and destination IP addresses to the file
    logFile << "Source: " << inet_ntoa(src_ip) << ", Destination: " << inet_ntoa(dest_ip) << std::endl;
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the network device for packet capture
    // You can replace "en0" with the interface you want to use (e.g., "eth0" or "wlan0")
    handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == nullptr) {
        std::cerr << "Error opening device for capture: " << errbuf << std::endl;
        return 1;
    }
    
    // Set the packet capture filter (optional, to capture only IP packets)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    
    // Start capturing packets and call packet_handler for each packet
    pcap_loop(handle, 0, packet_handler, nullptr);
    
    // Close the pcap handle and the log file when done
    pcap_close(handle);
    logFile.close();
    
    return 0;
}
