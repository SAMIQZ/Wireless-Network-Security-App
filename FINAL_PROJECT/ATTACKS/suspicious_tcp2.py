from scapy.all import IP, TCP, send

def suspicious_tcp(target_ip, target_port):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=target_port,flags='S')
    packet = ip / tcp

    send(packet, verbose=False)
    print(f"send TCP Packet to dst {target_ip} port {target_port} with flag S")

# Example usage
suspicious_tcp("192.168.1.1",60)
