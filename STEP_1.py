from scapy.all import *
from scapy.layers.inet import IP, TCP


def process_packet(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 21: 
        if packet.haslayer(Raw):
            raw_load = packet[Raw].load
            try:
                raw_load_decoded = raw_load.decode()
                if raw_load_decoded.startswith('USER') or raw_load_decoded.startswith('PASS'):
                    print(packet.sprintf(raw_load_decoded) )
            except UnicodeDecodeError:
                print(f"Cannot decode raw load: {raw_load}")

pcap_file = "PYTHON_CYBER_Challenge_2024_mars.pcapng"  
packets = rdpcap(pcap_file)
for packet in packets:
    process_packet(packet)