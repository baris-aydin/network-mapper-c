# Network Mapper

Network Mapper is a lightweight TCP SYN scanner implemented in C that uses raw sockets to craft and send custom SYN packets for network mapping. 

## Features

- **Platform Support:** Works on Linux.
- **Raw Socket Packet Crafting:** Constructs custom IP and TCP headers to perform SYN scans.
- **Port Scanning:** Sends SYN packets to a specified port range and interprets responses (SYN-ACK, RST) to determine port status.
- **Minimal Dependencies:** Built in standard C with minimal external dependencies.

## Requirements

- A C compiler (e.g., `gcc`)
- Root or administrative privileges (required for raw sockets)
- Linux 

## Usage

1. **Compile the Scanner:**

   ```bash
   gcc -o network_mapper network_mapper.c

2. **Run the Scanner:**
   
   ```bash
   sudo ./network_mapper <target IP> <start port> [end port]
