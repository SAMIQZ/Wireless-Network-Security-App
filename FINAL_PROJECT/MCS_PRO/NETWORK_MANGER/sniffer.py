import threading
from scapy.all import *
import datetime
from collections import defaultdict
import nmap
import ssl
from OpenSSL import SSL
import tkinter as tk
from tkinter import messagebox
from reportlab.lib.pagesizes import LETTER
import os
from reportlab.pdfgen import canvas
import getpass
from .models import *
import subprocess
import re
import sys
from . import views
import socket
from .models import Settings
from django.contrib.auth.models import User



def run_command(command):
    """Run a shell command and return the output as a list of lines."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip().split('\n')
    except subprocess.CalledProcessError as e:
        print(f"Error running command '{command}': {e}", file=sys.stderr)
        return []

def get_default_gateway_ip():
    """Extract the default gateway IP from ipconfig output."""
    output = run_command('ipconfig')
    gateway_pattern = re.compile(r'Default Gateway .*? : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE)
    for line in output:
        match = gateway_pattern.search(line)
        if match:
            return match.group(1)
    return None

def get_gateway_mac(gateway_ip):
    """Extract the MAC address for the given IP from ARP table."""
    if not gateway_ip:
        return None
    output = run_command(f'arp -a "{gateway_ip}"')
    # ARP output on Windows looks like: '  Internet Address      Physical Address      Type'
    # Then: '  192.168.1.1        aa-bb-cc-dd-ee-ff    dynamic'
    mac_pattern = re.compile(r'([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})')
    for line in output:
        match = mac_pattern.search(line)
        if match:
            return match.group(1).upper()  # Standardize to uppercase
    return None

def get_local_mac(interface_name=None):
    """Get the MAC address of the local interface (defaults to first Ethernet/Wi-Fi)."""
    output = run_command('getmac')
    # getmac output example:
    # Network Connection Name: "Ethernet"
    # Physical Address: AA-BB-CC-DD-EE-FF
    for line in output:
        if 'Tcpip' in line:
            return line.split(" ")[0]
        elif 'Media disconnected' in line:
            return line.split(" ")[0]



try:
    local_mac = get_local_mac().replace('-',':').lower()
    gateway_mac = get_gateway_mac(get_default_gateway_ip()).replace('-',':').lower()
except:
    gateway_mac = "None"

output = subprocess.check_output('echo %USERNAME%',shell=True)
USERNAME = output.decode('utf-8')
class PacketSniffer:
    def __init__(self):
        self.Packet_Sniffer = AsyncSniffer(prn=self.process_packet, store=0)
        self.packets = []

    def Psniffer_Switching(self,Status):
        if Status == "PStart":
            self.start_sniffing()
        elif Status == "PStop":
            self.stop_sniffing()


    def start_sniffing(self):
        Packet_Sniffer = AsyncSniffer(prn=self.process_packet, store=0)
        self.Packet_Sniffer.start()

    def stop_sniffing(self):
        self.Packet_Sniffer.stop()

    def process_packet(self, packet):
        self.packets.append(packet.summary())
        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            self.packets.append(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")
        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            self.packets.append(f"Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
        self.packets.append("-" * 50)

    def get_packets(self):
        return self.packets

Psniffer = PacketSniffer()

def run_sniffer():
    try:
        Psniffer.Psniffer_Switching(Status="PStop")
    except Exception:
        pass

Psniffer_thread = threading.Thread(target=run_sniffer)
Psniffer_thread.daemon = True
Psniffer_thread.start()

class DnsSniffer:
    def __init__(self):
        self.Dns_Sniffer = AsyncSniffer(filter="port 53",prn=self.process_packet, store=0)
        self.packets = []

    def Dsniffer_Switching(self,Status):
        if Status == "DStart":
            self.start_sniffing()
        elif Status == "DStop":
            self.stop_sniffing()

    def start_sniffing(self):
        self.Dns_Sniffer.start()

    def stop_sniffing(self):
        self.Dns_Sniffer.stop()

    def process_packet(self,packet):
        if packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode('utf-8')
            self.packets.append(f"DNS Query: {dns_query}")

    def get_dns_packets(self):
        return self.packets
# Start sniffing DNS packets


Dsniffer = DnsSniffer()

def run_sniffer():
    try:
        Dsniffer.Dsniffer_Switching(Status="DStop")
    except Exception:
        pass

Dsniffer_thread = threading.Thread(target=run_sniffer)
Dsniffer_thread.daemon = True
Dsniffer_thread.start()

class ArpSniffer:
    def __init__(self):
        self.Arp_Sniffer = AsyncSniffer(filter="arp",prn=self.process_packet, store=0)
        self.packets = []

    def Asniffer_Switching(self,Status):
        if Status == "AStart":
            self.start_sniffing()
        elif Status == "AStop":
            self.stop_sniffing()

    def start_sniffing(self):
        self.Arp_Sniffer.start()

    def stop_sniffing(self):
        self.Arp_Sniffer.stop()


    def process_packet(self,packet):
        if packet.haslayer(ARP):
            arp_info = packet[ARP].psrc
            self.packets.append(f"ARP Packet: {arp_info}")
            
    def get_arp_packets(self):
        return self.packets



Asniffer = ArpSniffer()

def run_sniffer():
    try:
        Asniffer.Asniffer_Switching(Status="AStop")
    except Exception:
        pass

Asniffer_thread = threading.Thread(target=run_sniffer)
Asniffer_thread.daemon = True
Asniffer_thread.start()


class IcmpSniffer:
    def __init__(self):
        self.Icmp_Sniffer = AsyncSniffer(filter="icmp",prn=self.process_packet, store=0)
        self.packets = []

    def Isniffer_Switching(self,Status):
        if Status == "IStart":
            self.start_sniffing()
        elif Status == "IStop":
            self.stop_sniffing()

    def start_sniffing(self):
        self.Icmp_Sniffer.start()

    def stop_sniffing(self):
        self.Icmp_Sniffer.stop()


    def process_packet(self,packet):
        # Check if the packet has an ICMP layer
        if packet.haslayer(ICMP):
            # Extract relevant information
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Print the details of the ICMP packet
            self.packets.append(f"ICMP Packet: Type={icmp_type}, Code={icmp_code}, Source={src_ip}, Destination={dst_ip}")

    def get_icmp_packets(self):
        return self.packets


Isniffer = IcmpSniffer()

def run_sniffer():
    try:
        Isniffer.Isniffer_Switching(Status="IStop")
    except Exception:
        pass

Isniffer_thread = threading.Thread(target=run_sniffer)
Isniffer_thread.daemon = True
Isniffer_thread.start()



class UrlSniffer:
    # Dictionary to store visited URLs by IP address
    def __init__(self):
        self.Url_Sniffer = AsyncSniffer(filter="tcp port 80", prn=self.process_packet, store=0)
        self.visited_urls = defaultdict(list)


    def Usniffer_Switching(self,Status):
        if Status == "UStart":
            self.start_sniffing()
        elif Status == "UStop":
            self.stop_sniffing()

    def start_sniffing(self):
        self.Url_Sniffer.start()

    def stop_sniffing(self):
        self.Url_Sniffer.stop()

    def process_packet(self,packet):
        if packet.haslayer(HTTP):
            # Extract the HTTP request
            http_layer = packet[HTTP]
            if http_layer.Method == b'GET':
                # Get the source IP address
                src_ip = packet[IP].src
                url = http_layer.Host.decode() + http_layer.Path.decode()
                self.visited_urls[src_ip].append(url)

    def get_url_packets(self):
        return self.visited_urls

Usniffer = UrlSniffer()

def run_sniffer():
    Usniffer.Usniffer_Switching(Status="Ustop")

Usniffer_thread = threading.Thread(target=run_sniffer)
Usniffer_thread.daemon = True
Usniffer_thread.start()


class AttackSniffer():

    def __init__(self,Path=fr'C:\Users\{USERNAME.strip()}\Documents',known_macs={local_mac,gateway_mac,'00:00:00:00:00:00'},THRESHOLD=1000,MAC_FLOOD_THRESHOLD=100,IP_FLOOD_THRESHOLD=1000,TIME_WINDOW=60,BRUTE_FORCE_THRESHOLD=2,ICMP_REPLY_THRESHOLD=100,REQUEST_LIMIT=1000):
        try:
            self.U = self.Request_R(User)
            lip = self.Get_Ip(ip)
        except:
            pass
        self.ARP_Sniffer = AsyncSniffer(filter='arp',prn=self.detect_arp_spoof, store=0)
        self.IP_Sniffer = AsyncSniffer(filter='arp',prn=self.detect_ip_spoof, store=0)
        self.TCP_Sniffer = AsyncSniffer(filter='tcp',prn=self.detect_suspicious_traffic, store=0)
        self.TCP_THRESHOLD = AsyncSniffer(filter='tcp',prn=self.Tcp_threshold, store=0)
        self.ICMP_Sniffer = AsyncSniffer(filter='icmp',prn=self.detect_deauth_Ping, store=0)
        self.SUSPICIOUS_Sniffer = AsyncSniffer(prn=self.is_suspicious_packet, store=0)
        self.BRUTE_FORCE = AsyncSniffer(prn=self.detect_brute_force, store=0)
        self.MAC_FLOODING = AsyncSniffer(prn=self.detect_mac_flood, store=0)
        self.IP_FLOODING = AsyncSniffer(prn=self.detect_dos, store=0)
        self.SUSPICIOUS_PORTS = {4444, 5555, 6666}  # Common ports used by malware/backdoors
        self.SUSPICIOUS_PAYLOAD_PATTERNS = [
            b"malware",
            b"exploit",
            b"attack",
            b"virus",
        ]
        self.result = set()
        self.Detect = set()
        self.Source = set()
        self.known_macs = known_macs
        self.known_ips = {socket.gethostbyname(socket.gethostname()),"127.0.0.1"}
        self.THRESHOLD = THRESHOLD
        self.MAC_FLOOD_THRESHOLD = MAC_FLOOD_THRESHOLD
        self.path = Path
        self.IP_FLOOD_THRESHOLD = IP_FLOOD_THRESHOLD
        self.TIME_WINDOW = TIME_WINDOW
        self.BRUTE_FORCE_THRESHOLD = BRUTE_FORCE_THRESHOLD
        self.ICMP_REPLY_THRESHOLD = ICMP_REPLY_THRESHOLD
        self.REQUEST_LIMIT = REQUEST_LIMIT
        self.COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995]
        self.PORT_PROTOCOLS = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "SMTP (TLS)",
            993: "IMAPS",
            995: "POP3S"
        }
        self.open_ports = []
        self.WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
        self.INSECURE_PROTOCOLS = ["FTP", "Telnet", "HTTP"]

        # Data stores
        self.TCP_PACKETS = []
        self.mac_addresses_seen = []
        self.ip_packet_counts = []
        self.packet_log = []
        self.ip_mac_mapping = defaultdict(set)
        self.arp_packet_counts = []
        self.icmp_reply_counts = []
        self.ip_last_time = []
        self.failed_login_attempts=[]
        self.DATE = str((((f"{datetime.datetime.date(datetime.datetime.now())}_{datetime.datetime.time(datetime.datetime.now())}").replace('.','-'))).replace(':','-'))
        self.start_time = time.time()
        self.file_to_touch = "./NETWORK_MANGER/sniffer.py"

    def Get_Ip(self,IP):
        return IP


    def write_pdf(self):
        # Ensure the directory exists
        os.makedirs(os.path.dirname(f'{self.path}\\ATTACK_DETECT_{self.DATE}.pdf'), exist_ok=True)
        c = canvas.Canvas(f'{self.path}\\ATTACK_DETECT_{self.DATE}.pdf', pagesize=LETTER)
        set_str = ", ".join(str(item) for item in self.Detect)
        width, height = LETTER
        x = 67  # 1 inch margin
        y = height - 72
        c.setFont("Helvetica", 10)
        lines = set_str.split('\n')
        for line in lines:
            c.drawString(x, y, line)
            y -= 15
        c.save()
        print(f"PDF file saved at: {f'{self.path}\\ATTACK_DETECT_{self.DATE}.pdf'}")

    def show_popup(self,message):
        messagebox.showinfo("Attack Detect",message)

    def Request_R(self, U):
        try:
            if isinstance(U, int):
                user_obj = User.objects.filter(pk=U).first()
            elif isinstance(U,User):
                user_obj = U
            else:
                return None

            if user_obj is None:
                return None
                
            PP = Settings.get_or_create_for_user(user_obj)
            known = PP.known_macs_set()
            
            try:
                known = known | {local_mac, gateway_mac, '00:00:00:00:00:00'}
            except Exception:
                pass
            self.__init__(
                PP.Default_Report_path,
                known if known else {local_mac, gateway_mac, '00:00:00:00:00:00'},
                PP.THRESHOLD,
                PP.Mac_Threshold,
                PP.Ip_Threshold,
                PP.Time_Window,
                PP.Brute_Force_Threshold,
                PP.Icmp_Threshold,
                PP.Request_Limit,
            )
            return PP
        except Exception as e:
            print(f'[AttackSniffer.Request_R] fallback to defaults: {e} ')
            return None



    def RET(self):
        return [self.path,"true",self.THRESHOLD,self.MAC_FLOOD_THRESHOLD,self.IP_FLOOD_THRESHOLD,self.TIME_WINDOW,self.BRUTE_FORCE_THRESHOLD,self.ICMP_REPLY_THRESHOLD,self.REQUEST_LIMIT]

    
    def touch_file(self,path):
        """
        Update the modification time of the file to trigger Django auto-reload.
        """
        with open(path, 'a'):
            os.utime(path, None)
        if os.path.exists(self.file_to_touch):
            print(f"Touching {self.file_to_touch} to trigger Django server reload...")
            
            print("Done.")
        else:
            print(f"File {self.file_to_touch} not found.")


    def detect_suspicious_traffic(self,packet):
        if packet.haslayer(TCP) and packet[TCP].flags & 0x02:
            if len(self.TCP_PACKETS) > self.THRESHOLD:
                # ip_layer = packet['IP']
                tcp_layer = packet['TCP']
                self.result.add(f"Suspicious packet detected: {packet.summary()} Time {datetime.datetime.now()}\n\n ")
                self.Detect.add(f"Suspicious packet detected Time {datetime.datetime.now()} \n\n")
                for x in range(len(self.Detect)):
                    self.write_pdf()
                root = tk.Tk()
                root.withdraw()
                self.show_popup(f"Suspicious packet detected: {packet.summary()} Time {datetime.datetime.now()} ")
                self.touch_file(self.file_to_touch)


    def Tcp_threshold(self,packet):
        if packet.haslayer(TCP) and packet[TCP].flags & 0x01:
            self.TCP_PACKETS.append(packet)
            if len(self.TCP_PACKETS) > self.THRESHOLD:
                self.result.add(f"Traffic rate exceeded threshold! ({len(self.TCP_PACKETS)} packets per second) Time {datetime.datetime.now()}\n\n")
                self.Detect.add(f"Traffic rate exceeded threshold! ({len(self.TCP_PACKETS)} packets per second) Time {datetime.datetime.now()}\n\n")
                for x in range(len(self.Detect)):
                    self.write_pdf()
                root = tk.Tk()
                root.withdraw()
                self.show_popup(f"Traffic rate exceeded threshold! ({len(self.TCP_PACKETS)} packets per second) Time {datetime.datetime.now()}")
                self.touch_file(self.file_to_touch)


    def detect_ip_spoof(self,packet):
        if packet.haslayer(ARP):
            if packet.src not in self.known_macs and packet.src not in self.known_ips:
                arp = packet[ARP]
                ip = arp.psrc
                mac = arp.hwsrc
                self.ip_mac_mapping[ip].add(mac)
                # # print(ip)
                if len(self.ip_mac_mapping[ip]) > 1:
                    self.result.add(f" IP Spoofing detected for MAC {mac}! {datetime.datetime.now()}\n\n \n\n")
                    self.Detect.add(f" IP Spoofing detected for MAC {mac}! {datetime.datetime.now()}\n\n")
                    # print(f"    MAC addresses: {self.ip_mac_mapping[ip]}")
                    for x in range(len(self.Detect)):
                        self.write_pdf()
                    root = tk.Tk()
                    root.withdraw()
                    # self.
                    self.show_popup(f" IP Spoofing detected for MAC {mac} ! {datetime.datetime.now()}")
                    self.touch_file(self.file_to_touch)


    def detect_arp_spoof(self,packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            if packet.src not in self.known_macs and packet.src not in self.known_ips:
                arp = packet.hwsrc
                self.arp_packet_counts.append(arp)
                count = len(self.arp_packet_counts)
                current_time = time.time()
                if len(self.arp_packet_counts) > 1:
                    ARP_MASSAGE = f"""[!] ARP Spoofing detected! Sender: {packet.src} Time {datetime.datetime.now()}\n\n"""
                    self.result.add(ARP_MASSAGE)
                    self.Detect.add(ARP_MASSAGE)
                    self.Source.add(packet.psrc)
                    for x in range(len(self.Detect)):
                        self.write_pdf()
                    root = tk.Tk()
                    root.withdraw()
                    self.show_popup(f"[!] ARP Spoofing detected! Sender: {packet.src} Time {datetime.datetime.now()}")
                    self.touch_file(self.file_to_touch)
            

    def is_suspicious_packet(self,packet):
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport in self.SUSPICIOUS_PORTS or dport in self.SUSPICIOUS_PORTS:
                # print(packet[IP].src)
                self.result.add(f"""[!] Suspicious packet detected! Source Port: {sport}, Destination Port: {dport} Time {datetime.datetime.now()}\n\n""")
                self.Detect.add(f"""[!] Suspicious packet detected! Source Port: {sport}, Destination Port: {dport} Time {datetime.datetime.now()}\n\n""")
                for x in range(len(self.Detect)):
                    self.write_pdf()
                root = tk.Tk()
                root.withdraw()
                self.show_popup(f"[!] Suspicious tcp packet detected! Source Port: {sport}, Destination Port: {dport} Time {datetime.datetime.now()}")
                self.touch_file(self.file_to_touch)

        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            # # print(f"UDP SRC {sport}")
            # print(packet[IP].src)
            if sport in self.SUSPICIOUS_PORTS or dport in self.SUSPICIOUS_PORTS:
                self.result.add(f"""[!] Suspicious udp packet detected! Source Port: {sport}, Destination Port: {dport} Time {datetime.datetime.now()}\n\n""")
                self.Detect.add(f"""[!] Suspicious udp packet detected! Source Port: {sport}, Destination Port: {dport} Time {datetime.datetime.now()}\n\n""")
                for x in range(len(self.Detect)):
                    self.write_pdf()
                root = tk.Tk()
                root.withdraw()
                self.show_popup(f"[!] Suspicious udp packet detected! Source Port: {sport}, Destination Port: {dport} Time {datetime.datetime.now()}")
                self.touch_file(self.file_to_touch)


        if packet.haslayer(Raw):
            payload = packet[Raw].load.lower()
            for pattern in self.SUSPICIOUS_PAYLOAD_PATTERNS:
                if pattern in payload:
                    # print(packet[IP].src)
                    self.result.add(f"[!] Suspicious packet detected: {packet.src} with Raw {payload.decode('utf-8')} Time {datetime.datetime.now()}\n\n ")
                    self.Detect.add(f"Suspicious packet detected:{packet.src} with Raw {payload.decode('utf-8')} Time {datetime.datetime.now()} \n\n")
                    for x in range(len(self.Detect)):
                        self.write_pdf()
                    root = tk.Tk()
                    root.withdraw()

                    self.show_popup(f"[!] Suspicious packet detected: {packet.src} with Raw {payload.decode('utf-8')} Time {datetime.datetime.now()}")
                    self.touch_file(self.file_to_touch)

    def detect_mac_flood(self,packet):
        if packet.haslayer(Ether):
            if packet.src not in self.known_macs and packet.src not in self.known_ips:
                mac = packet[Ether].src
                self.mac_addresses_seen.append(mac)
                # print(len(self.mac_addresses_seen))
                current_time = time.time()
                if current_time - self.start_time < self.TIME_WINDOW:
                    if len(self.mac_addresses_seen) > self.MAC_FLOOD_THRESHOLD:
                        self.result.add(f"""[ALERT] Possible MAC flooding interface Wi-Fi: {len(self.mac_addresses_seen)} unique MACs in {self.TIME_WINDOW} seconds Time {datetime.datetime.now()}\n\n""")
                        self.Detect.add(f"""[ALERT] Possible MAC flooding interface Wi-Fi: {len(self.mac_addresses_seen)} unique MACs in {self.TIME_WINDOW} seconds Time {datetime.datetime.now()}\n\n""")
                        for x in range(len(self.Detect)):
                            self.write_pdf()
                        root = tk.Tk()
                        root.withdraw()

                        self.show_popup(f"[ALERT] Possible MAC flooding on interface Wi-Fi: {len(self.mac_addresses_seen)} unique MACs in {self.TIME_WINDOW} seconds Time {datetime.datetime.now()}")
                        self.touch_file(self.file_to_touch)

    def detect_dos(self,packet):
        if packet.haslayer(UDP):
            src_ip = packet[IP].src
            # print(src_ip)
            current_time = time.time()
            self.packet_log.append(src_ip)
            # print(len(self.packet_log))
            if current_time - self.start_time < self.TIME_WINDOW:
                if len(self.packet_log) > self.REQUEST_LIMIT:
                    self.result.add(f" DoS attack detected {len(self.packet_log)} packets in last {self.TIME_WINDOW} from {src_ip} seconds Time {datetime.datetime.now()}\n\n")
                    self.Detect.add(f" DoS attack detected {len(self.packet_log)} packets in last {self.TIME_WINDOW} from {src_ip} seconds Time {datetime.datetime.now()}\n\n")
                    for x in range(len(self.Detect)):
                        self.write_pdf()
                    root = tk.Tk()
                    root.withdraw()
                    self.show_popup(f" DoS attack detected {len(self.packet_log)} packets in last {self.TIME_WINDOW} seconds Time {datetime.datetime.now()}")
                    self.touch_file(self.file_to_touch)
                    


    def detect_deauth_Ping(self,packet):
        if packet.haslayer(ICMP):
            target_ip = packet[IP].src
            self.icmp_reply_counts.append(target_ip)
            # print(len(self.icmp_reply_counts))
            current_time = time.time()
            if current_time - self.start_time < self.TIME_WINDOW:
                if len(self.icmp_reply_counts) > self.ICMP_REPLY_THRESHOLD:
                    # print(packet[IP].src)
                    self.result.add(f"""ICMP Smurf detected {target_ip} - {len(self.icmp_reply_counts)} ICMP replies in {self.TIME_WINDOW} seconds Time {datetime.datetime.now()}\n\n""")
                    self.Detect.add(f"""ICMP Smurf detected {target_ip} - {len(self.icmp_reply_counts)} ICMP replies in {self.TIME_WINDOW} seconds Time {datetime.datetime.now()}\n\n""")
                    for x in range(len(self.Detect)):
                        self.write_pdf()
                    root = tk.Tk()
                    root.withdraw()

                    self.show_popup(f"""ICMP Smurf detected {target_ip} - {len(self.icmp_reply_counts)} ICMP replies in {self.TIME_WINDOW} seconds Time {datetime.datetime.now()} """)
                    self.touch_file(self.file_to_touch)
            
    def detect_brute_force(self,packet):
        if packet.haslayer(TCP) and packet[TCP].dport == 22 and packet[TCP].flags == 'S':
            ip = packet[IP].src
            self.failed_login_attempts.append(ip)
            print(f"FALID {self.failed_login_attempts}")
            current_time = time.time()
            if current_time - self.start_time < self.TIME_WINDOW:
                if len(self.failed_login_attempts) > self.BRUTE_FORCE_THRESHOLD:
                    self.result.add(f"""[ALERT] Possible brute force attack IP {ip}: {len(self.failed_login_attempts)} failed login attempts in {self.TIME_WINDOW} seconds Time {datetime.datetime.now()}\n\n""")
                    self.Detect.add(f"""brute force attack IP {ip}: {int(len(self.failed_login_attempts))} failed login attempts in {self.TIME_WINDOW} seconds Time {datetime.datetime.now()}\n\n""")
                    for x in range(len(self.Detect)):
                        self.write_pdf()
                    root = tk.Tk()
                    root.withdraw()
                    self.show_popup(f"[ALERT] Possible brute force attack from IP {ip}: {int(len(self.failed_login_attempts))} failed login attempts in {self.TIME_WINDOW} seconds Time {datetime.datetime.now()}")
                    self.touch_file(self.file_to_touch)
                    



    def scan_open_ports(self,target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sT')  # TCP connect scan

        if target not in nm.all_hosts():
            self.result.add(f"No information found for {target}")
        for proto in nm[target].all_protocols():
            ports = nm[target][proto].keys()
            for port in sorted(ports):
                if port in self.COMMON_PORTS:
                    self.open_ports.append(port)
                    state = nm[target][proto][port]['state']
                    self.check_tls_version(target, port)
                    self.check_version(target,port)

    def wifi_cryptography(self,wifi_Authentication):
        try:
            strong_auth = ['WPA2-Personal', 'WPA3-Personal', 'WPA2-Enterprise', 'WPA3-Enterprise']
            weak_auth = ['WPA-Personal', 'WEP', 'Open']

            if wifi_Authentication in strong_auth:
                self.result.add("""Your Wi-Fi have Strong Encryption\n\n""")
            elif wifi_Authentication in weak_auth:
                self.result.add(""" Your Wi-Fi have Weak Encryption\n\n""")
            else:
                self.result.add(' ')
        except:
            pass


    def check_tls_version(self,host, port):
        # Try to connect and get TLS version
        context = ssl.create_default_context()
        # Allow all TLS versions for testing
        context.options &= ~ssl.OP_NO_SSLv2
        context.options &= ~ssl.OP_NO_SSLv3
        context.options &= ~ssl.OP_NO_TLSv1
        context.options &= ~ssl.OP_NO_TLSv1_1
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    protocol_version = ssock.version()
                    return protocol_version
        except Exception as e:
            return None

    def check_version(self,target,port):
        for port in self.open_ports:
            proto_name = self.PORT_PROTOCOLS.get(port, "Unknown")
            self.result.add(f"Port {port} ({proto_name}) Open\n\n ")

            if proto_name in self.INSECURE_PROTOCOLS:
                self.result.add(f"  [WARNING] Insecure protocol detected: {proto_name}\n\n")

            if proto_name in ["HTTPS", "SMTPS", "SMTP (TLS)", "IMAPS", "POP3S"]:
                tls_version = self.check_tls_version(target, port)
                if tls_version is None:
                    self.result.add("  Could not determine TLS version.\n\n")
                else:
                    self.result.add(f"  TLS version: {tls_version}")
                    if tls_version in self.WEAK_PROTOCOLS:
                        self.result.add("  [WARNING] Weak TLS/SSL protocol detected!\n\n")


    def Start_Sniffer(self):
        self.ARP_Sniffer.start()
        self.TCP_Sniffer.start()
        self.ICMP_Sniffer.start()
        self.SUSPICIOUS_Sniffer.start()
        self.BRUTE_FORCE.start()
        self.MAC_FLOODING.start()
        self.IP_FLOODING.start()
        self.IP_Sniffer.start()
        self.TCP_THRESHOLD.start()
        self.scan_open_ports(target_host)
        self.wifi_cryptography(wifi_Authentication)
        self.scan_ports(target_host)
        self.scan_ports(target_host)


    def Attack_List(self):
        return self.result

    def Detect_List(self):
        return self.Detect

ATsniffer = AttackSniffer()

def run_sniffer():
    try:
        ATsniffer.Start_Sniffer()
        run()
    except Exception:
        pass

ATsniffer_thread = threading.Thread(target=run_sniffer)
ATsniffer_thread.daemon = True
ATsniffer_thread.start()