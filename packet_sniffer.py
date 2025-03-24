from scapy.all import sniff

# Function to process packets
def packet_handler(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        print(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol}")

# Sniff packets on the network (Ctrl+C to stop)
print("Starting packet sniffer... Press CTRL+C to stop.")
sniff(prn=packet_handler, store=False)
