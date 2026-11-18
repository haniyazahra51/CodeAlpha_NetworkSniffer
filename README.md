# CodeAlpha_NetworkSniffer

A basic Python network sniffer built with Scapy for the CodeAlpha Cyber Security internship (Task 1).

## Features
- Captures live packets and shows source/destination IP, protocol, ports, TCP flags
- Decodes TCP, UDP, ICMP, ARP and DNS queries
- Shows a printable payload preview
- BPF filters, packet count limit, optional .pcap export (open in Wireshark)
- Protocol summary on exit

## Setup
```
pip install scapy
```
Windows also needs [Npcap](https://npcap.com).

## Usage
```
sudo python3 sniffer.py                      # capture until Ctrl+C
sudo python3 sniffer.py -c 50 -f "tcp port 80"
sudo python3 sniffer.py -i eth0 -w capture.pcap
```

## How it works
Scapy reads frames from the network interface and parses each layer
(Ethernet > IP > TCP/UDP/ICMP > payload). Each packet is passed to a handler
that extracts the fields and prints them.

## Disclaimer
For educational use only. Capture traffic only on networks you own or have permission to monitor.
