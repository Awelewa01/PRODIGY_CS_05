from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

#Function to process captured packets
def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = 'unknown'

        #Check if the packet has a TCP or UDP layer
        if TCP in packet:
            protocol = 'TCP'
        elif UDP in packet:
            protocol = 'UDP'

        #Extracts payload (if any)
        payload = bytes(packet[TCP].payload).decode(errors="ignore") if TCP in packet else ""

        #Print captured details
        print(f"[{protocol}]: {src_ip} ➡️  {dst_ip} | Payload: {payload[:50]}...")

#Start capturing the packet
print("Starting Packet Capture. Press (CTRl + C) to stop...")
sniff(prn=packet_handler, store=False)
#sniff captures packet in real time, prn calls the packet_handler function, store prevents storing in memory (saves resources)