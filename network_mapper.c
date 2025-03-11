#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>   
#include <netinet/tcp.h>   
#include <sys/time.h>
#include <fcntl.h>

// Pseudo header needed for TCP checksum calculation
struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

// Compute checksum (RFC 1071)
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;

    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if(nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }
    // Add carry bits
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;
    return answer;
}

// Helper function to determine our source IP address by creating a temporary UDP socket.
void get_source_ip(char *buffer, size_t buflen) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in temp;
    memset(&temp, 0, sizeof(temp));
    temp.sin_family = AF_INET;
    temp.sin_addr.s_addr = inet_addr("8.8.8.8"); 
    temp.sin_port = htons(53);

    if(connect(sock, (struct sockaddr *)&temp, sizeof(temp)) < 0) {
        perror("connect");
        close(sock);
        exit(1);
    }
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if(getsockname(sock, (struct sockaddr *)&local, &len) < 0) {
        perror("getsockname");
        close(sock);
        exit(1);
    }
    inet_ntop(AF_INET, &local.sin_addr, buffer, buflen);
    close(sock);
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printf("Usage: %s <target IP> <start port> [end port]\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = (argc == 4) ? atoi(argv[3]) : start_port;

    // Get the source IP address automatically.
    char source_ip[20];
    get_source_ip(source_ip, sizeof(source_ip));
    printf("Using source IP: %s\n", source_ip);

    // Create a raw socket for sending TCP packets.
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(send_sock < 0) {
        perror("Send socket");
        exit(1);
    }
    // Tell the kernel that headers are included in the packet.
    int one = 1;
    if(setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    // Create a raw socket for receiving TCP responses.
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(recv_sock < 0) {
        perror("Receive socket");
        exit(1);
    }
    // Set the receiving socket to non-blocking mode.
    fcntl(recv_sock, F_SETFL, O_NONBLOCK);

    // Setup destination address structure.
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(target_ip);

    // Loop through each port in the specified range.
    for (int port = start_port; port <= end_port; port++) {
        char datagram[4096];
        memset(datagram, 0, 4096);

        // IP header pointer
        struct iphdr *iph = (struct iphdr *)datagram;
        // TCP header pointer (immediately after IP header)
        struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));

        // Fill in the IP header.
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->id = htons(54321); 
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0; 
        iph->saddr = inet_addr(source_ip);
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)datagram, sizeof(struct iphdr));

        // Fill in the TCP header.
        tcph->source = htons(12345);  
        tcph->dest = htons(port);
        tcph->seq = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff = 5; // Data offset (5 x 4 = 20 bytes)
        tcph->syn = 1;  // Set the SYN flag
        tcph->window = htons(5840); // Default window size
        tcph->check = 0; // Initialize checksum to 0
        tcph->urg_ptr = 0;

        // Calculate the TCP checksum using a pseudo header.
        struct pseudo_header psh;
        psh.source_address = inet_addr(source_ip);
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);
        if (!pseudogram) {
            perror("malloc");
            exit(1);
        }
        memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
        tcph->check = checksum((unsigned short *)pseudogram, psize);
        free(pseudogram);

        // Send the crafted SYN packet.
        if (sendto(send_sock, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),
                   0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("sendto");
        } else {
            printf("Sent SYN to port %d\n", port);
        }

        // Wait for a response (timeout = 1 second).
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(recv_sock, &readfds);

        int rv = select(recv_sock + 1, &readfds, NULL, NULL, &tv);
        if (rv > 0) {
            // Receive packet from the raw socket.
            char buffer[4096];
            ssize_t data_size = recvfrom(recv_sock, buffer, sizeof(buffer), 0, NULL, NULL);
            if (data_size < 0) {
                perror("recvfrom");
            } else {
                // Parse the received IP header.
                struct iphdr *recv_iph = (struct iphdr *)buffer;
                if (recv_iph->protocol == IPPROTO_TCP) {
                    unsigned short iphdrlen = recv_iph->ihl * 4;
                    struct tcphdr *recv_tcph = (struct tcphdr *)(buffer + iphdrlen);
                    // Check if this packet is from our target and matches the ports we expect.
                    if (recv_iph->saddr == dest.sin_addr.s_addr &&
                        recv_tcph->dest == tcph->source && recv_tcph->source == tcph->dest) {
                        // If SYN and ACK flags are set, the port is open.
                        if (recv_tcph->syn && recv_tcph->ack) {
                            printf("[+] Port %d is open (SYN-ACK received)\n", port);
                        }
                        // If RST flag is set, the port is closed.
                        else if (recv_tcph->rst) {
                            printf("[-] Port %d is closed (RST received)\n", port);
                        }
                        else {
                            printf("[*] Port %d received unexpected flags\n", port);
                        }
                    }
                }
            }
        } else {
            // No response within the timeout period.
            printf("[*] No response for port %d (filtered or dropped)\n", port);
        }
        // Small delay between probes to avoid flooding the network.
        usleep(100000);
    }

    close(send_sock);
    close(recv_sock);
    return 0;
}



