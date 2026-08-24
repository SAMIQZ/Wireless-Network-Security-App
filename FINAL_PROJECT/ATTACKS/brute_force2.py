from scapy.all import IP, TCP, send

def suspicious_tcp(target_ip):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=10,dport=22,flags='S')
    packet = ip / tcp
    for _ in range(10):
        send(packet, verbose=False)
        print(f"send TCP Packet to dst {target_ip} port 22 with flag S")

# Example usage
suspicious_tcp("192.168.1.1")