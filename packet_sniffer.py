from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "N/A")
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "N/A")
        
        print(f"Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} | Protocol: {protocol}")

        # Print payload if available
        if packet.haslayer(Raw):
            print(f"Payload Data: {packet[Raw].load}\n")

print("Starting packet sniffer... Press CTRL+C to stop.")
sniff(prn=packet_handler, store=False)
