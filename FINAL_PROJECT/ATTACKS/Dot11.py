from scapy.all import IP, Dot11, send

def custom_tcp_packet(target_ip):
    ip = IP(dst=target_ip)
    Dot = Dot11(type=0,subtype=12)
    packet = ip / Dot
    while True:
        send(packet, verbose=False)

# Example usage
custom_tcp_packet("192.168.43.1")



# dot = Dot11()

# dot.show()