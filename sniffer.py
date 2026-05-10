from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Determine the protocol name
        protocol_name = "Other"
        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"
        elif proto == 1:
            protocol_name = "ICMP"

        print(f"\n[+] New Packet: {src_ip} -> {dst_ip} | Protocol: {protocol_name}")

        # Check for Transport Layer Payloads
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload)
            if payload:
                # Display first 50 characters of the payload
                print(f"    Payload Snippet: {payload[:50].hex()}")

def main():
    print("Starting Network Sniffer... (Press Ctrl+C to stop)")
    # 'sniff' monitors the network. 'prn' defines the function to run on each packet.
    # 'store=0' prevents the script from keeping all packets in memory.
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
