from scapy.all import sniff, TCP, IP, UDP, DNS, Raw, conf
from collections import Counter

# Ensure scapy uses the right network interface
conf.use_pcap = True

# Initialize counters for various types of packets
packet_counts = Counter()

def analyze_packet(packet):
    # Increment total packet count
    packet_counts['total'] += 1

    # Check for IP layer
    if packet.haslayer(IP):
        packet_counts['IP'] += 1

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Check for TCP layer
        if packet.haslayer(TCP):
            packet_counts['TCP'] += 1

            # Check for Raw payload (HTTP data)
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors='ignore')
                
                # Check for HTTP POST requests
                if "POST" in payload:
                    packet_counts['HTTP POST'] += 1
                    print(f"[HTTP POST] {ip_src} -> {ip_dst}")
                    print(payload)
                    print("------------------------------------------------------")
                
                # Check for HTTP GET requests
                elif "GET" in payload:
                    packet_counts['HTTP GET'] += 1
                    print(f"[HTTP GET] {ip_src} -> {ip_dst}")
                    print(payload)
                    print("------------------------------------------------------")

        # Check for UDP layer
        if packet.haslayer(UDP):
            packet_counts['UDP'] += 1

            # Check for DNS layer
            if packet.haslayer(DNS):
                packet_counts['DNS'] += 1
                print(f"[DNS] {ip_src} -> {ip_dst} : {packet[DNS].qd.qname}")

def print_packet_summary():
    print("Packet Summary:")
    for key, count in packet_counts.items():
        print(f"{key}: {count}")

def packet_callback(packet):
    try:
        analyze_packet(packet)
    except Exception as e:
        print(f"Error analyzing packet: {e}")

# Start the packet sniffing process
print("Starting network sniffer...")
sniff(prn=packet_callback, filter="tcp or udp", store=0)

# Print packet summary (will be called manually or on termination signal)
print_packet_summary()
