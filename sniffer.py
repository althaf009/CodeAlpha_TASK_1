from scapy.all import sniff, IP, TCP, UDP, DNS

# Callback function to process each captured packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        print(f"IP Packet - Src: {ip_src}, Dst: {ip_dst}, Protocol: {protocol}")

        if UDP in packet:
            udp_src_port = packet[UDP].sport
            udp_dst_port = packet[UDP].dport
            print(f"UDP Packet - Src Port: {udp_src_port}, Dst Port: {udp_dst_port}")

        elif TCP in packet:
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            print(f"TCP Packet - Src Port: {tcp_src_port}, Dst Port: {tcp_dst_port}")

        if DNS in packet:
            dns = packet[DNS]
            if dns.qr == 0:
                print(f"DNS Query - {dns.qd.qname.decode('utf-8')}")
            elif dns.qr == 1:
                if dns.an:
                    print(f"DNS Answer - {dns.an.rdata}")

# Function to start packet sniffing
def start_sniffing():
    print("Starting packet capture...")
    sniff(prn=packet_callback, filter="ip", store=0)  # Remove `count` to capture indefinitely

if __name__ == "__main__":
    start_sniffing()
