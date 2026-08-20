from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Step 1: Check if the packet has an IP layer (IPv4)
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto

        # Step 2: Identify the higher-level protocol
        protocol_name = "Other"
        if packet.haslayer(TCP):
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"

        # Step 3: Print basic header details
        print(f"\n[+] Packet Captured:")
        print(f"    Source IP:      {src_ip}")
        print(f"    Destination IP: {dst_ip}")
        print(f"    Protocol:       {protocol_name} (Code {proto_num})")

        # Step 4: Display Payload (Raw Data inside the packet)
        if packet.haslayer(TCP) and packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
            print(f"    Payload Snippet: {payload[:50]}")
        elif packet.haslayer(UDP) and packet[UDP].payload:
            payload = bytes(packet[UDP].payload)
            print(f"    Payload Snippet: {payload[:50]}")

def main():
    print("--- Starting Basic Network Sniffer ---")
    print("Press Ctrl+C to stop capturing.\n")
    
    # Capture packets continuously, passing each one to packet_callback
    # count=0 means run infinitely until stopped
    sniff(prn=packet_callback, store=False, count=0)

if __name__ == "__main__":
    main()