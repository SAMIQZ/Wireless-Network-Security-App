from scapy.all import IP, TCP, send

def suspicious_tcp(target_ip, target_port):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=target_port)
    packet = ip / tcp

    send(packet, verbose=False)
    print(f"send TCP Packet to dst {target_ip} port {target_port}")

# Example usage
target_ip=input("ENTER YOUR TARGET IP\n")
suspicious_tcp(target_ip,4444)
