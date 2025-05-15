This program is a simple network packet sniffer written in Python using the Scapy library. Here’s what it does:

Monitors network traffic in real time by capturing packets on the local machine.
Processes each packet to check if it is an IP packet, and further identifies if it is TCP or UDP.
Tracks statistics such as:
Total number of packets seen
Number of TCP and UDP packets
Destination ports used
TCP connection attempts (by detecting SYN packets)
Prints a summary of these statistics when you stop the program (with Ctrl+C).
Prints each TCP and UDP packet as it is captured, showing source and destination addresses and ports.
Usage:
Run the script with root privileges (required for sniffing), e.g.:

py
Typical use cases:

```python
sudo python3 src/sniffer.py
```

Basic network monitoring
Learning about network protocols
Debugging or analyzing local network traffic