#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <iostream>
#include <fstream>
#include <map>

// Define a log file to capture the information
std::ofstream logFile("logs.txt", std::ios::out | std::ios::app);

// Function for reverse DNS lookup to get the domain name from IP address
std::string reverse_dns_lookup(const char *ip) {
    struct hostent *host = gethostbyaddr((const void *)ip, strlen(ip), AF_INET);
    if (host != nullptr) {
        return std::string(host->h_name);
    }
    return "Unknown Domain";
}

// Function to map source port to application (using netstat/ss or predefined port list)
std::string get_application_from_port(int port) {
    // Simple mapping for known ports (Example: HTTP, HTTPS, FTP)
    std::map<int, std::string> port_map;
    port_map[80] = "HTTP";
    port_map[443] = "HTTPS";
    port_map[21] = "FTP";
    port_map[22] = "SSH";
    port_map[53] = "DNS";


    if (port_map.find(port) != port_map.end()) {
        return port_map[port];
    }
    return "Unknown Application";
}

// Callback function for each captured packet
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Parse the IP header from the captured packet
    struct ip *ip_header = (struct ip *)(packet + 14);  // Skip Ethernet header (14 bytes)
    struct in_addr src_ip = ip_header->ip_src;
    struct in_addr dest_ip = ip_header->ip_dst;

    // Perform reverse DNS lookup for the destination IP
    std::string dest_domain = reverse_dns_lookup(inet_ntoa(dest_ip));

    // Parse the transport layer (TCP/UDP)
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));  // Skip IP header
        int src_port = ntohs(tcp_header->th_sport);
        int dest_port = ntohs(tcp_header->th_dport);

        // Get application names for the source and destination ports
        std::string src_app = get_application_from_port(src_port);
        std::string dest_app = get_application_from_port(dest_port);

        // Log the information
        logFile << "Protocol: TCP | "
                << "Source IP: " << inet_ntoa(src_ip) << " | " << "Dest IP: " << inet_ntoa(dest_ip)
                << " | Source Port: " << src_port << " | Dest Port: " << dest_port
                << " | Src App: " << src_app << " | Dest Domain: " << dest_domain << std::endl;

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl << 2));  // Skip IP header
        int src_port = ntohs(udp_header->uh_sport);
        int dest_port = ntohs(udp_header->uh_dport);

        // Get application names for the source and destination ports
        std::string src_app = get_application_from_port(src_port);
        std::string dest_app = get_application_from_port(dest_port);

        // Log the information
        logFile << "Protocol: UDP | "
                << "Source IP: " << inet_ntoa(src_ip) << " | " << "Dest IP: " << inet_ntoa(dest_ip)
                << " | Source Port: " << src_port << " | Dest Port: " << dest_port
                << " | Src App: " << src_app << " | Dest Domain: " << dest_domain << std::endl;

    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        logFile << "Protocol: ICMP | "
                << "Source IP: " << inet_ntoa(src_ip) << " | " << "Dest IP: " << inet_ntoa(dest_ip)
                << " | Type: " << (int)(packet[14 + (ip_header->ip_hl << 2)]) << std::endl;  // ICMP Type
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the network device for packet capture (replace "en0" with your interface)
    handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == nullptr) {
        std::cerr << "Error opening device for capture: " << errbuf << std::endl;
        return 1;
    }

    // Set a packet capture filter (capture all IP packets)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    // Start packet capture and call packet_handler for each packet
    pcap_loop(handle, 0, packet_handler, nullptr);

    // Close pcap handle and log file
    pcap_close(handle);
    logFile.close();

    return 0;
}
