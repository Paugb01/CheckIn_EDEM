from scapy.all import *

# Define a packet callback function
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

# Start sniffing packets
sniff(prn=packet_callback, store=0)
