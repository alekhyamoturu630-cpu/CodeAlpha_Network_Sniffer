# CodeAlpha Internship - Task 1: Basic Network Sniffer

A Python-based network sniffer built using **Scapy** to capture, inspect, and analyze live network traffic.

## Features
- Captures IPv4 network packets in real-time.
- Identifies transport layer protocols: TCP, UDP, and ICMP.
- Displays Source IP and Destination IP addresses.
- Extracts and prints a snippet of the raw payload data.

## Prerequisites & Installation
- Python 3.x
- Npcap (Windows) with WinPcap compatibility mode enabled
- Scapy library:
  ```bash
  pip install scapy
