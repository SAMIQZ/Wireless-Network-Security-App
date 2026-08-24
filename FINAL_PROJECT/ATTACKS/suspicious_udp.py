from scapy.all import IP, UDP, send

def suspicious_udp(target_ip, target_port):
    ip = IP(dst=target_ip)
    udp = UDP(sport=target_port)
    packet = ip / udp

    send(packet, verbose=False)
    print(f"send UDP Packet to dst {target_ip} port {target_port}")

# Example usage
target_ip=input("ENTER YOUR TARGET IP\n")
suspicious_udp(target_ip,4444)
