from scapy.all import IP, TCP, send

def suspicious_tcp(target_ip, target_port):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=target_port,flags=0x01)
    for x in range(1600):
        packet = ip / tcp

        send(packet, verbose=False)
        print(f"Send TCP Packet {x} TIMES")

# Example usage
target_ip=input("ENTER YOUR TARGET IP\n")
suspicious_tcp(target_ip,60)
