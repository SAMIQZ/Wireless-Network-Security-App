from scapy.all import IP, TCP, send

def custom_tcp_packet(target_ip, target_port):
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port, flags='A', seq=1000, ack=2000)  # Acknowledgment flag
    packet = ip / tcp
    send(packet, verbose=True)

# Example usage
custom_tcp_packet("192.168.43.153", 80)
