import threading
import subprocess
import psutil
import speedtest
import socket
import re
from scapy.all import sr1, IP, ICMP,ARP,send,Ether,srp
import time
from .sniffer import *


class Network_d:
    def get_network_data_usage(self,interface="Wi-Fi"):
        net_io = psutil.net_io_counters(pernic=True)[interface]
        net_connections = psutil.net_connections()
        bytes_sent = net_io.bytes_sent
        bytes_recv = net_io.bytes_recv

        return bytes_sent, bytes_recv

    def display_network_data_usage(self,interface="Wi-Fi", interval=1):

        while True:
            bytes_sent, bytes_recv = self.get_network_data_usage(interface)
            total_bytes = bytes_sent + bytes_recv
            B=(f" {total_bytes / (1024 * 1024):.2f} MB")
            # Iterate over the connections
            for connection in psutil.net_connections():
                # Print the connection information
                C=(f"Connection: {connection.status} {connection.laddr} -> {connection.raddr}")
            time.sleep(interval)
            return [B,self.get_network_data_usage(interface)]

        display_network_data_usage(interface, interval=1)


N = Network_d()

def D_N():
    N.display_network_data_usage()
N_thread = threading.Thread(target=D_N)
N_thread.daemon = True
N_thread.start()

class Network_D_P:
    def get_wifi_interface(self):
    # Return the name of the Wi-Fi interface (common names on Windows)
    # You may need to adjust this depending on your system
        wifi_keywords = ['wi-fi', 'wifi', 'wireless', 'wlan']
        for iface in psutil.net_if_stats():
            if any(keyword in iface.lower() for keyword in wifi_keywords):
                return iface
        return None

    def monitor_wifi_usage(self,duration=0,interval=0,path=''):
        iface = self.get_wifi_interface()
        if not iface:
            return

        timestamps = []
        bytes_sent = []
        bytes_recv = []

        prev_counters = psutil.net_io_counters(pernic=True)[iface]

        start_time = time.time()
        while time.time() - start_time < duration:
            time.sleep(interval)
            counters = psutil.net_io_counters(pernic=True)[iface]

            sent = counters.bytes_sent - prev_counters.bytes_sent
            recv = counters.bytes_recv - prev_counters.bytes_recv

            prev_counters = counters

            timestamps.append(time.time() - start_time)
            bytes_sent.append(sent)
            bytes_recv.append(recv)


P = Network_D_P()

def D_N():
    try:
        P.monitor_wifi_usage(duration, interval)
    except Exception:
        pass
N_thread = threading.Thread(target=D_N)
N_thread.daemon = True
N_thread.start()



class Network_Speed:
    def check_internet_speed(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1_000_000
            upload_speed = st.upload() / 1_000_000
            ping = st.results.ping
            return download_speed, upload_speed, ping
        except :
            download_speed = 0 
            upload_speed = 0
            ping = 0
            return download_speed,upload_speed,ping

    def main(self):
        download_speed, upload_speed, ping = self.check_internet_speed()
        Download_Speed = (f" {download_speed:.2f} Mbps")
        Upload_Speed = (f"{upload_speed:.2f} Mbps")
        Ping_Speed = (f"{ping} ms")
        return [Download_Speed,Upload_Speed,Ping_Speed]

Speed = Network_Speed()

def S_N():
    Speed.main()
Speed_thread = threading.Thread(target=S_N)
Speed_thread.daemon = True
Speed_thread.start()


class Network_Performance:

    def network_performance_analysis(self,target_ip='', packet_count=20, packet_size=64, timeout=2):
        latencies = []
        lost_packets = 0
        total_bytes_received = 0

        for i in range(packet_count):
            packet = IP(dst=target_ip)/ICMP()/("X"*(packet_size - 28))
            start_time = time.time()
            reply = sr1(packet, timeout=timeout, verbose=0)
            end_time = time.time()

            if reply is None:
                lost_packets += 1
            else:
                latency = (end_time - start_time) * 1000 
                latencies.append(latency)
                total_bytes_received += len(reply)

            time.sleep(0.1)
        received_packets = packet_count - lost_packets
        packet_loss_rate = (lost_packets / packet_count) * 100
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        total_time = sum(latencies)/1000 if latencies else 1
        throughput = total_bytes_received / total_time if total_time > 0 else 0
        return [packet_count,received_packets,lost_packets,f"{packet_loss_rate:.2f}%",f"{avg_latency:2f}",f"{throughput:2f}"]

Perform = Network_Performance()

def Per_N():
    try:
        Perform.network_performance_analysis(target_ip)
    except Exception:
        pass
Per_thread = threading.Thread(target=Per_N)
Per_thread.daemon = True
Per_thread.start()



class Network_Devices:

    def Device(self,gateway):
        self.devices = []
        arp_packet = ARP(pdst=f"{gateway}/24")
        ether_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_packet / arp_packet
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            device_ip = received.psrc
            device_mac = received.hwsrc
            ATsniffer.known_macs.add(device_mac)
            try:
                hostname = socket.gethostbyaddr(device_ip)[0]
            except:
                hostname = "Unknown"
            device = Device(ip_address=device_ip, mac_address=device_mac,hostname=hostname)
            self.devices.append(device)

Dev = Network_Devices()

def Dev_D():
    try:
        Dev.Device(gateway)
    except Exception:
        pass
Dev_thread = threading.Thread(target=Dev_D)
Dev_thread.daemon = True
Dev_thread.start()