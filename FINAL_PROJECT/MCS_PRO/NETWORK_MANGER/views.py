from .forms import *
import socket
from reportlab.lib.pagesizes import LETTER
import os
from reportlab.pdfgen import canvas
import csv
import sys
import random
from ping3 import ping
from docx import Document
import string
from django.contrib.auth.models import User
import paramiko
import re
import requests
from datetime import datetime
from openpyxl import Workbook
import qrcode
import pandas as pd
from scapy.all import *
from io import StringIO
from scapy.all import traceroute,UDP
from django.urls import reverse
from django.contrib.auth import login , logout
from django.contrib.auth.decorators import login_required
from collections import defaultdict
from .models import *
from .sniffer import *
from .network import *
from django.shortcuts import render,redirect
from django.contrib import messages
from . import urls
from django.http import HttpResponseRedirect , Http404
from cryptography.fernet import Fernet
from .forms import SettingsForm
from .models import Settings
from .sniffer import ATsniffer

Detect = ATsniffer.Detect_List()


def ssh_connect(request,hostname, port, username, password, command):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            decrypted_password = fernet.decrypt(password.encode()).decode()
            client.connect(hostname, port=port, username=username, password=decrypted_password)
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            client.close()
            statistics = {}
            for line in output.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    statistics[key] = value
            return statistics
        except:
            logout(request)
            return HttpResponseRedirect(reverse('log-page'))
            ATsniffer.touch_file(ATsniffer.file_to_touch)

def get_wifi_info(request,hostname, port, username, password, command):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        decrypted_password = fernet.decrypt(password.encode()).decode()
        client.connect(hostname, port=port, username=username, password=decrypted_password)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode() 
        client.close()
        statistics = {}
        for line in output.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                statistics[key] = value
        return statistics
    except:
        logout(request)
        return HttpResponseRedirect(reverse('log-page'))
        ATsniffer.touch_file(ATsniffer.file_to_touch)

def get_gateway(request,hostname, port, username, password, command):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        decrypted_password = fernet.decrypt(password.encode()).decode()
        client.connect(hostname, port=port, username=username, password=decrypted_password)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode()
        client.close()
        gateways = re.findall(r"Default Gateway[ .]*: ([\d\.]+)", output)
        gateways = [g for g in gateways if g and g != '0.0.0.0']
        if gateways:
            return gateways[0]
        else:
            return None
    except:
        logout(request)
        return HttpResponseRedirect(reverse('log-page'))
        ATsniffer.touch_file(ATsniffer.file_to_touch)

def is_valid_windows_path(path_string):
    windows_path_pattern = r'^(?:[A-Za-z]:\\|\\\\)[^\\/:*?"<>|\r\n]+(?:\\[^\\/:*?"<>|\r\n]+)*$'
    # If comma-separated, split and validate each
    if ',' in path_string:
        paths = [p.strip() for p in path_string.split(',')]
        valid_paths = []
        for p in paths:
            if re.match(windows_path_pattern, p):
                valid_paths.append(p)
        return valid_paths  # Returns list of valid paths (empty if none)
    
    # Single path
    return bool(re.match(windows_path_pattern, path_string))

def is_windows(hostname, port, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        decrypted_password = fernet.decrypt(password.encode()).decode()
        client.connect(hostname, port=port, username=username, password=decrypted_password)
        stdin, stdout, stderr = client.exec_command('ver')
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode()
        client.close()
        if 'Microsoft Windows' in output:
            return True
        return False
    except Exception:
        False




def upload_file_via_ssh(hostname, port, username, password, local_path, remote_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {hostname}...")
    decrypted_password = fernet.decrypt(password.encode()).decode()
    client.connect(hostname, port=port, username=username, password=decrypted_password)
    print("Connected.")
    sftp = ssh.open_sftp()
    remote_dir = os.path.dirname(remote_path)
    try:
        sftp.stat(remote_dir)
    except FileNotFoundError:
        print(f"Remote directory {remote_dir} does not exist. Creating it...")
        mkdir_p(sftp, remote_dir)
    print(f"Uploading {local_path} to {remote_path} ...")
    sftp.put(local_path, remote_path)
    print("Upload complete.")
    sftp.close()
    ssh.close()

def run_as_administrator():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    sys.exit(0)

def Welcome_Page(request):
    return render(request,"Welcome_Page.html")

def Login_Page(request):
    logout(request)
    if request.method == 'POST':
        form = Log()
        HOST= request.POST['HOSTNAME']
        USERNAME = request.POST['USERNAME']
        PASSWORD = request.POST['PASSWORD']
        US = User.objects.filter(username=HOST)
        print(US)
        if US:
            try:
                US.delete()
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=HOST,port=22,username=USERNAME,password=PASSWORD)
                encrypted_password = fernet.encrypt(PASSWORD.encode()).decode()
                U=User.objects.create(username=HOST,first_name=USERNAME,last_name=encrypted_password)
                decrypted_password = fernet.decrypt(U.last_name.encode()).decode()
                print(decrypted_password)
                gateway = get_gateway(request,U.username,22, U.first_name,decrypted_password,'ipconfig')
                Dev.Device(gateway)
                FL = FailLogin.objects.filter(User=HOST)
                FL.delete()
                U=User.objects.get(username=HOST)
                login(request,U)
                client.close()
                return HttpResponseRedirect(reverse('hom-page'))
            except Exception:
                F = FailLogin.objects.create(User=HOST,Fail=1)
                F.save()
                print("SAVE")
                messages.error(request, 'There was an error with your submission.')
                FL = FailLogin.objects.filter(User=HOST)
                FC = FL.count()
                print(FC)
                if int(FC) == 3:
                    FL = FailLogin.objects.filter(User=HOST)
                    ATsniffer.result.add(f"HOST {HOST}: 3 failed login attempts Time {datetime.datetime.now()}\n\n")
                    ATsniffer.Detect.add(f"HOST {HOST}: 3 failed login attempts Time {datetime.datetime.now()}\n\n")
                    ATsniffer.show_popup(f"HOST {HOST}: 3 failed login attempts Time {datetime.datetime.now()}\n\n")
                    FL.delete()
                    ATsniffer.touch_file(ATsniffer.file_to_touch)
                    return HttpResponseRedirect(reverse('wel-page'))
                return HttpResponseRedirect(reverse('log-page'))

        elif is_windows(HOST,22,USERNAME,PASSWORD) == False:
            messages.error(request, 'This app on Windows only')
            return HttpResponseRedirect(reverse('log-page'))

        else:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=HOST,port=22,username=USERNAME,password=PASSWORD)
                encrypted_password = fernet.encrypt(PASSWORD.encode()).decode()
                U=User.objects.create(username=HOST,first_name=USERNAME,last_name=encrypted_password)
                decrypted_password = fernet.decrypt(U.last_name.encode()).decode()
                print(decrypted_password)
                gateway = get_gateway(request,U.username,22, U.first_name,decrypted_password,'ipconfig')
                Dev.Device(gateway)
                FL = FailLogin.objects.filter(User=HOST)
                FL.delete()
                login(request,U)
                U.save()
                client.close()
                return HttpResponseRedirect(reverse('hom-page'))
            except Exception as e:
                print(e)
                F = FailLogin.objects.create(User=HOST,Fail=1)
                F.save()
                print("SAVE")
                messages.error(request, 'There was an error with your submission.')
                FL = FailLogin.objects.filter(User=HOST)
                FC = FL.count()
                print(FC)
                if int(FC) == 3:
                    FL = FailLogin.objects.filter(User=HOST)
                    ATsniffer.result.add(f"HOST {HOST}: 3 failed login attempts Time {datetime.datetime.now()}\n\n")
                    ATsniffer.Detect.add(f"HOST {HOST}: 3 failed login attempts Time {datetime.datetime.now()}\n\n")
                    ATsniffer.show_popup(f"HOST {HOST}: 3 failed login attempts Time {datetime.datetime.now()}\n\n")
                    FL.delete()
                    ATsniffer.touch_file(ATsniffer.file_to_touch)
                    return HttpResponseRedirect(reverse('wel-page'))
                return HttpResponseRedirect(reverse('log-page'))
    elif request.method == 'GET':
        form = Log()
        f={'form':form}
        return render(request,'Login_Page.html',context=f)

@login_required(login_url='log-page')
def Home(request):
    print(request.user.id)
    FL = FailLogin.objects.filter(User=request.user)
    print(FL.count())
    U = User.objects.get(username=request.user)
    print(f"Windows {is_windows(U.username,22,U.first_name,U.last_name)}")
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    wifi_info = get_wifi_info(request,U.username,22, U.first_name,U.last_name,'netsh wlan show interface').items()
    i={'INFO':wifi_info}
    return render(request,'Home_Page.html',context=i)

@login_required(login_url='log-page')
def Scanner(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    wifi_info = get_wifi_info(request,U.username,22, U.first_name,U.last_name,'netsh wlan show interface').items()
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    gateway = get_gateway(request,U.username,22, U.first_name,U.last_name,'ipconfig')
    devices = []
    arp_packet = ARP(pdst=f"{gateway}/24")
    ether_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_packet / arp_packet
    result = srp(packet, timeout=3, verbose=0)[0]
    for sent, received in result:
        device_ip = received.psrc
        device_mac = received.hwsrc
        try:
            hostname = socket.gethostbyaddr(device_ip)[0]
        except:
            hostname = "Unknown"
        device = Device(ip_address=device_ip, mac_address=device_mac,hostname=hostname)
        devices.append(device)
    return render(request, 'List_Page.html', {'devices':devices})

@login_required(login_url='log-page')
def NetworkUse(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    O = subprocess.check_output("netsh wlan show interface",shell=True).decode('utf-8')
    def wifi():
        statistics = {}
        for line in O.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                statistics[key] = value
        return statistics
    wifi_i = wifi()
    Usage = N.display_network_data_usage(wifi_i['Name'])
    SE=(f"{Usage[1][0]} KB")
    R=(f"{Usage[1][1]} KB")
    return render(request,'NETWORK_USAGE.html',context={'USAGE':Usage[0:1][0],'SENT':SE,'RESEVE':R})

@login_required(login_url='log-page')
def NetworkSpeed(request):
    print(request.user.id)
    UR=User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(UR.id))
    except:
        pass
    try:
        S = Speed.main()
        D = S[0]
        U = S[1]
        P = S[2]
    except:
        pass
    return render(request,'NETWORK_SPEED.html',context={'Download_Speed':D,'Upload_Speed':U,'Ping_Speed':P})

@login_required(login_url='log-page')
def Network_Performance(request):
    UR=User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(UR.id))
    except:
        pass
    def get_ip(hostname, port, username, password, command):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            decrypted_password = fernet.decrypt(password.encode()).decode()
            client.connect(hostname, port=port, username=username, password=decrypted_password)
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode()
            client.close()
            lines = output.splitlines()
            ipv4 = None
            for line in lines:
                line = line.strip()
                if line.startswith("IPv4 Address"):
                    ipv4 = line.split(":")[-1].strip()
                    break
            if ipv4:
                print(f"Wi-Fi IPv4 Address: {ipv4}")
                return ipv4
            else:
                print("IPv4 address not found in output.")
                return None
        except Exception as e:
            pass
            return None
            return output
    try:
        ip = get_ip(UR.username,22, UR.first_name,UR.last_name,'ipconfig | findstr /C:"Wireless LAN adapter Wi-Fi" /C:"IPv4 Address"')
        print(ip)
    except Exception as e:
        print(e)
    try:
        P = Perform.network_performance_analysis(ip)
        PC = P[0]
        RP = P[1]
        LP = P[2]
        PLR = P[3]
        AL = P[4]
        THR = P[5]
    except:
        pass
    return render(request,'Network_Performance.html',context={'IP':ip,'Packet_Count':PC,'Received_Packets':RP,'Loss_Packets':LP,'Loss_Packet_Rate':PLR,'Avg_Latency':AL,'Throughput':THR})

@login_required(login_url='log-page')
def DeviceInfo(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    interface = 'Wi-Fi'
    default_gateway=get_gateway(request,U.username,22, U.first_name,U.last_name,'ipconfig')
    devices = []
    def scan_windows_devices():
        arp_packet = ARP(pdst=f"{default_gateway}/24")
        ether_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_packet / arp_packet
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            device_ip = received.psrc
            device_mac = received.hwsrc
            try:
                hostname = socket.gethostbyaddr(device_ip)[0]
            except:
                hostname = "Unknown"
            device_info = {
                'ip_address': device_ip,
                'mac_address': device_mac,
                'hostname': hostname,
                'vendor': get_vendor_from_mac(device_mac),
                'status': 'Online'
            }
            devices.append(device_info)
        return devices
    def get_vendor_from_mac(mac_address):
        mac_clean = mac_address.replace(':', '').upper()
        vendor_ouis = {
            '001CDF': 'Cisco',
            '001E65': 'LG Electronics',
            '0021D1': 'Samsung',
            '0022CF': 'Intel',
            '0023EB': 'Apple',
            '0024E9': 'Huawei',
            '0026B0': 'Dell',
            '0026BB': 'Apple',
            '0026C7': 'TP-Link',
            '0026F2': 'Microsoft',
            '002710': 'Cisco',
            '001A2B': 'Sony',
            '001B63': 'Apple',
            '001D4F': 'Cisco',
            '001E4C': 'Dell',
            '001F3A': 'Dell',
            '001FF3': 'Netgear',
            '0021D1': 'Samsung',
            '008701': 'Samsung',
            '0022CF': 'Intel',
            '0023EB': 'Apple',
            '0024E9': 'Huawei',
            '0026B0': 'Dell',
            'E20A0F': 'Lenovo',
        }
        oui = mac_clean[:6]
        print(oui)
        return vendor_ouis.get(oui, 'Unknown Vendor')
    devices = scan_windows_devices()
    print(devices)
    f={'info':devices}
    inf={'info':devices}
    return render(request,'Device_Info.html',context=inf)

@login_required(login_url='log-page')
def SSID_D(request):
    command = "netsh wlan show networks mode=bssid"
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    def info(request,hostname, port, username, password, command):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            decrypted_password = fernet.decrypt(password.encode()).decode()
            client.connect(hostname, port=port, username=username, password=decrypted_password)
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode()
            client.close()
            networks = []
            current_network = {}
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("SSID "):
                    if current_network:
                        networks.append(current_network)
                        current_network = {}
                    ssid_match = re.match(r"SSID \d+ : (.*)", line)
                    ssid = ssid_match.group(1) if ssid_match else ""
                    current_network['SSID'] = ssid
                elif line.startswith("Network type"):
                    current_network['Network type'] = line.split(":",1)[1].strip()
                elif line.startswith("Authentication"):
                    current_network['Authentication'] = line.split(":",1)[1].strip()
                elif line.startswith("Encryption"):
                    current_network['Encryption'] = line.split(":",1)[1].strip()
                elif line.startswith("BSSID "):
                    bssid = line.split(":",1)[1].strip()
                    current_network.setdefault('BSSIDs', []).append(bssid)
                elif line.startswith("Signal"):
                    signal = line.split(":",1)[1].strip()
                    current_network.setdefault('Signals', []).append(signal)
                ssid = line.get('SSID', '')
                if ssid == '':
                    ssid = "<Hidden SSID>"
                networks.append(f"SSID: {ssid}")
                networks.append(f"  Network type: {net.get('Network type', 'N/A')}")
                networks.append(f"  Authentication: {net.get('Authentication', 'N/A')}")
                networks.append(f"  Encryption: {net.get('Encryption', 'N/A')}")
                bssids = net.get('BSSIDs', [])
                signals = net.get('Signals', [])
                for i, bssid in enumerate(bssids):
                    signal = signals[i] if i < len(signals) else "N/A"
                    networks.append(f"  BSSID: {bssid}  Signal: {signal}")
            if current_network:
                networks.append(current_network)
            return networks
        except:
            pass
        return output
        ATsniffer.touch_file(ATsniffer.file_to_touch)
    try:
        get_wifi_networks = info(request,U.username,22, U.first_name,U.last_name,command)
    except:
        logout(request)
        return HttpResponseRedirect(reverse('log-page'))
        ATsniffer.touch_file(ATsniffer.file_to_touch)
    return render(request,'SSID_DETECTOR.html',context={'ssids':get_wifi_networks})

@login_required(login_url='log-page')
def About(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    return render(request,'About.html')

@login_required(login_url='log-page')
def UrlSniffer(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
        visited_url = Usniffer.get_url_packets()
        f={'urls':visited_url}
    return render(request, "Url_Sniffer.html", {'urls': visited_url})

@login_required(login_url='log-page')
def NAAD(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    server = False
    try:
        admin_url = f'http://{U.username}:6060/admin/login/'.rstrip('/')
        response = requests.get(admin_url,timeout=5)
        if response.status_code == 200:
            server = True
    except:
        pass
    print(server)
    def get_ip(hostname, port, username, password, command):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            decrypted_password = fernet.decrypt(password.encode()).decode()
            client.connect(hostname=hostname, port=port, username=username, password=decrypted_password)
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode()
            client.close()
            lines = output.splitlines()
            ipv4 = None
            for line in lines:
                line = line.strip()
                if line.startswith("IPv4 Address"):
                    ipv4 = line.split(":")[-1].strip()
                    break
            if ipv4:
                print(f"Wi-Fi IPv4 Address: {ipv4}")
                return ipv4
            else:
                print("IPv4 address not found in output.")
                return None
        except Exception as e:
            print(f"Exception occurred: {e}")
            logout(request)
            return HttpResponseRedirect(reverse('log-page'))
            ATsniffer.touch_file(ATsniffer.file_to_touch)

    wifi_info = get_wifi_info(request,U.username,22, U.first_name,U.last_name,'netsh wlan show interface')
    ip = get_ip(U.username,22, U.first_name,U.last_name,'ipconfig | findstr /C:"Wireless LAN adapter Wi-Fi" /C:"IPv4 Address"')
    result = ATsniffer.Attack_List()
    print(f"Detect {len(Detect)}")
    def write_word(text_lines, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        doc = Document()
        doc.add_paragraph(text_lines)

        doc.save(filepath)
        print(f"Word document saved at: {filepath}")

    content = [
        result
    ]

    def write_csv(data, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            if data and isinstance(data[0], dict):
                header = data[0].keys()
                writer.writerow(header)
                for row in data:
                    writer.writerow(row.values())
            else:
                for row in data:
                    writer.writerow(row)
        print(f"CSV file saved at: {filepath}")

    data = [
        result
    ]

    def write_pdf(text, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        c = canvas.Canvas(filepath, pagesize=LETTER)
        width, height = LETTER
        x = 67
        y = height - 72
        c.setFont("Helvetica", 10)
        lines = text.split('\n')
        for line in lines:
            c.drawString(x, y, line)
            y -= 15
        c.save()
        print(f"PDF file saved at: {filepath}")
    content = set_str = ", ".join(str(item) for item in result)

    def mkdir_p(sftp, remote_directory):
        dirs = []
        while len(remote_directory) > 1:
            dirs.append(remote_directory)
            remote_directory, _ = os.path.split(remote_directory)
        dirs = dirs[::-1]
        for directory in dirs:
            try:
                sftp.stat(directory)
            except FileNotFoundError:
                print(f"Creating directory {directory}")
                sftp.mkdir(directory)

    hostname = U.username
    port = 22
    username = U.first_name
    password = U.last_name

    if request.method == 'POST':
        try:
            FILEPATH = request.POST['FileName']
            EXPORT = request.POST["Export"]
            print(FILEPATH)
            print(EXPORT)
            remote_dir = FILEPATH
            local_file = FILEPATH
            local_path = FILEPATH
            remote_file_path = os.path.join(remote_dir, local_file)
            if EXPORT == 'Word':
                if not FILEPATH.lower().endswith(".docx"):
                    messages.error(request,"Error: The file path must end with '.docx'.")
                    return HttpResponseRedirect(reverse('atc-page'))
                elif not is_valid_windows_path(FILEPATH):
                    messages.error(request,"Error: Please Enter Correct and Valid Path.")
                    return HttpResponseRedirect(reverse('atc-page'))
                elif os.path.exists(FILEPATH):
                    messages.error(request,"Error: File already exists at the specified path.")
                    return HttpResponseRedirect(reverse('atc-page'))
                elif FILEPATH.lower().endswith(".docx"):
                    write_word(content, FILEPATH)
                    if server == False:
                        upload_file_via_ssh(hostname, port, username, password, local_file, remote_file_path)
                        os.remove(local_file)
            elif EXPORT == 'CSV':
                if not FILEPATH.lower().endswith(".csv"):
                    messages.error(request,"Error: The file path must end with '.csv'.")
                    return HttpResponseRedirect(reverse('atc-page'))
                elif not is_valid_windows_path(FILEPATH):
                    messages.error(request,"Error: Please Enter Correct and Valid Path.")
                    return HttpResponseRedirect(reverse('atc-page'))
                elif os.path.exists(FILEPATH):
                    messages.error(request,"Error: File already exists at the specified path.")
                    return HttpResponseRedirect(reverse('atc-page'))
                elif FILEPATH.lower().endswith(".csv"):
                    write_csv(data, FILEPATH)
                    if server == False:
                        upload_file_via_ssh(hostname, port, username, password, local_file, remote_file_path)
                        os.remove(local_file)
            elif EXPORT == 'PDF':
                if not FILEPATH.lower().endswith(".pdf"):
                    messages.error(request,"Error: The file path must end with '.pdf'.")
                    return HttpResponseRedirect(reverse('atc-page'))
                elif not is_valid_windows_path(FILEPATH):
                    messages.error(request,"Error: Please Enter Correct and Valid Path.")
                    return HttpResponseRedirect(reverse('atc-page'))
                elif os.path.exists(FILEPATH):
                    messages.error(request,"Error: File already exists at the specified path.")
                    return HttpResponseRedirect(reverse('atc-page'))
                elif FILEPATH.lower().endswith(".pdf"):
                    write_pdf(content, FILEPATH)
                    if server == False:
                        upload_file_via_ssh(hostname, port, username, password, local_file, remote_file_path)
                        os.remove(local_file)
            massage = f"THE File Saved ON The Path: {FILEPATH} ON  HOST {U.username}"
        except:
            massage = ' '
        return render(request,'Network_Auto_Attack_Detector.html',context={"result":result,'D':Detect,'P':massage})
    try:
        if wifi_info['State']=='disconnected':
            pass
        elif wifi_info['State']=='connected':
            ATsniffer.wifi_cryptography(wifi_info['Authentication'])
            ATsniffer.scan_open_ports(ip)
    except:
        pass
    if request.method == 'GET':
        return render(request,'Network_Auto_Attack_Detector.html',context={"result":result,'D':Detect})

@login_required(login_url='log-page')
def SAC(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    command = f"netstat -n"
    def SSH_connect(request,hostname, port, username, password, command):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            decrypted_password = fernet.decrypt(password.encode()).decode()
            client.connect(hostname, port=port, username=username, password=decrypted_password)
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            client.close()
        except:
            ATsniffer.touch_file(ATsniffer.file_to_touch)
        return output
    Active_Connections = SSH_connect(request,U.username,22, U.first_name,U.last_name,command)
    f={'a':Active_Connections}
    return render(request,'Active_connections.html',context=f)

@login_required(login_url='log-page')
def LM(request):
    ASG = ATsniffer.Detect
    print(ASG)
    print(request.user.id)
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    wifi_info = get_wifi_info(request,U.username,22, U.first_name,U.last_name,'netsh wlan show interface')
    MASSAGE = []
    MASSAGE1 = []
    try:
        MSO = NET.objects.filter(MsgId=wifi_info['BSSID'])
        for MSS in MSO:
            if MSS.FNAME == U.username:
                decrypted_Msg = fernet.decrypt(MSS.Msg.encode()).decode()
                MSS.Msg = decrypted_Msg
                MASSAGE.append(MSS)
                print(f"Y: {MASSAGE}")
            elif MSS.FNAME != U.username:
                decrypted_Msg = fernet.decrypt(MSS.Msg.encode()).decode()
                MSS.Msg = decrypted_Msg
                MASSAGE1.append(MSS)
                print(MSS)
                print(f"N: {MASSAGE1}")
    except:
        pass
    try:
        MSG = request.POST['Text']
        encrypted_msg = fernet.encrypt(MSG.encode()).decode()
        M=NET(FNAME=request.user,Msg=encrypted_msg,USER=request.user,MsgId=wifi_info['BSSID'])
        M.save()
        print(M.MsgId)
        print(M)
    except:
        pass
    print(MASSAGE)
    f={'masc':MASSAGE,'masc1':MASSAGE1}
    return render(request,'Local_M.html',context=f)
    if request.method == 'GET':
        f={'masc':MASSAGE,'masc1':MASSAGE1}
        return render(request,'Local_M.html',context=f)

@login_required(login_url='log-page')
def LMID(request,id):
    M = NET.objects.get(id=id)
    M.delete()
    return HttpResponseRedirect(reverse('lm-page'))

@login_required(login_url='log-page')
def Gentate_PU(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    if request.method == 'POST':
        form = GPU(request.POST)
        
        try:
            ULENGTH = int(request.POST['Username_Length'])
            PLENGTH = int(request.POST['Password_Length'])

            def generate_username(length=12):
                if length < 3:
                    return "Username length should be at least 3 characters."
                elif length > 10:
                    return "Username too long."
                else:
                    characters = string.ascii_letters  + "_"
                    username = ''.join(random.choice(characters) for _ in range(length))
                    return f"{username}_{random.randint(1,100000)}"
            def generate_password(length=16):
                if length < 8:
                    return "Password length should be at least 8 characters."
                if length > 20:
                    return "Password to long."
                else:
                    lowercase = string.ascii_lowercase
                    uppercase = string.ascii_uppercase
                    digits = string.digits
                    special_characters = string.punctuation
                    password = [
                        random.choice(lowercase),
                        random.choice(uppercase),
                        random.choice(digits),
                        random.choice(special_characters)
                    ]
                    all_characters = lowercase + uppercase + digits + special_characters
                    password += random.choices(all_characters, k=length - 4)
                    random.shuffle(password)
                return ''.join(password)
            username = generate_username(ULENGTH)
            password = generate_password(PLENGTH)
        except:
            username = "None "
            password = "None "
        f={'form':form,'USERNAME':f"Generated Username: {username}",'PASSWORD':f"Generated Password: {password}"}
        return render(request,'GUsername_Password.html',context=f)
    elif request.method == 'GET':
        form = GPU()
        f={'form':form}
        return render(request,'GUsername_Password.html',context=f)

@login_required(login_url='log-page')
def Check_PU(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    if request.method == 'POST':
        form = CPU(request.POST)
        try:
            USERNAME = request.POST['Username']
            PASSWORD = request.POST['Password']
            def check_username_strength(username):
                if len(username) < 3:
                    return "Username is too short. It should be at least 3 characters long."
                if len(username) > 20:
                    return "Username is too long. It should be no more than 20 characters."
                if not re.match("^[A-Za-z0-9_]+$", username):
                    return "Username can only contain letters, digits, and underscores."
                if not re.search(r"[A-Z]", username):
                    return "Username should contain at least one uppercase letter."
                if not re.search(r"[a-z]", username):
                    return "Username should contain at least one lowercase letter."
                if not re.search(r"\d{4}", username):
                    return "Username should contain at least Four digit."
                return "Username is strong."

            def check_password_strength(password):
                if len(password) < 8:
                    return "Password is too short. It should be at least 8 characters long."
                if len(password) > 20:
                    return "Password is too long. It should be no more than 20 characters."
                if not re.search(r"[A-Z]", password):
                    return "Password should contain at least one uppercase letter."
                if not re.search(r"[a-z]", password):
                    return "Password should contain at least one lowercase letter."
                if not re.search(r"\d", password):
                    return "Password should contain at least one digit."
                if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
                    return "Password should contain at least one special character."
                return "Password is strong."

            username = USERNAME
            password = PASSWORD
            username_strength = check_username_strength(username)
            password_strength = check_password_strength(password)
        except:
            username_strength = "None"
            password_strength = "None"
        f = {'form':form,'URESULT':f"{username_strength}",'PRESULT': f"{password_strength}"}
        return render(request,'CUsername_Password.html',context=f)
    elif request.method == 'GET':
        form = CPU()
        f={'form':form}
        return render(request,'CUsername_Password.html',context=f)

@login_required(login_url='log-page')
def PING(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    if request.method == 'POST':
        form = Ping(request.POST)
        if form.is_valid():
            try:
                HOST = request.POST['host']
                def ping_lookup(host):
                    response = ping(host)
                    return response
                host = HOST
                f={'form':form,'RESULT':f"Ping Lookup: {host} -> {ping_lookup(host)} ms"}
                return render(request,'Ping.html',context=f)
            except:
                pass
    elif request.method == 'GET':
        form = Ping()
        f={'form':form}
        return render(request,'Ping.html',context=f)

@login_required(login_url='log-page')
def TR(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    if request.method == 'POST':
        form = TRA(request.POST)
        if form.is_valid():
            THOST = request.POST['host']
            target = THOST.strip()

            try:
                res, unans = traceroute(
                    target,
                    maxttl=30,
                    l4=UDP(dport=53),
                    timeout=3,
                    verbose=0
                )
                old_stdout = sys.stdout
                sys.stdout = mystdout = StringIO()
                res.show()
                sys.stdout = old_stdout
                result_text = mystdout.getvalue()

            except Exception as e:
                result_text = f"{str(e)}"

            f = {
                'form': form,
                'RESULT': result_text
            }
            return render(request,'Trace.html',context=f)
    elif request.method == 'GET':
        form = TRA()
        f={'form':form}
        return render(request,'Trace.html',context=f)

@login_required(login_url='log-page')
def ASI(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    packets = Asniffer.get_arp_packets()     
    return render(request,'ArpSniffer.html',context={"packets":packets})

@login_required(login_url='log-page')
def DSI(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    packets = Dsniffer.get_dns_packets()
    return render(request,'DnsSniffer.html',context={"packets":packets})

@login_required(login_url='log-page')
def PSI(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    packets = Psniffer.get_packets()
    return render(request,'Packet_Sniffer.html',context={"packets":packets})

@login_required(login_url='log-page')
def ISI(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    packets = Isniffer.get_icmp_packets()
    return render(request,'IcmpSniffer.html',context={"packets":packets})

@login_required(login_url='log-page')
def PAK(request):
    print(f'{request.user.id}')
    U = User.objects.get(username=request.user)
    form = PSK()
    f={'form':form}
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    wifi_info = ssh_connect(request,U.username,22, U.first_name,U.last_name,'netsh wlan show interface')
    if request.method == "POST":
       form = PSK(request.POST)
       if form.is_valid():
        urls = request.POST['URLS']
        title = request.POST['TITLE']
        username = request.POST['USERNAME']
        password = request.POST['PASSWORD']
        encrypted_username = fernet.encrypt(username.encode()).decode()
        encrypted_url = fernet.encrypt(urls.encode()).decode()
        encrypted_password = fernet.encrypt(password.encode()).decode()
        P=PK(USERNAME=encrypted_username,PASSWORD=encrypted_password,USER=request.user,URLS=encrypted_url,TITLE=title,PKId=wifi_info['BSSID'])
        P.save()
        return HttpResponseRedirect(reverse('passkd-page'))
    elif request.method == "GET":
        return render(request,'Password_Keeper.html',context=f)
    return render(request,'Password_Keeper.html',context=f)

@login_required(login_url='log-page')
def PAKD(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    wifi_info = get_wifi_info(request,U.username,22, U.first_name,U.last_name,'netsh wlan show interface')
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    PAL = []
    try:
        P=PK.objects.filter(PKId=wifi_info['BSSID'])
        print(P)
        for PA in P:
            PAL.append(PA)
    except Exception as e:
        print(e)
    f={'U':PAL}
    return render(request,'Password_Keep.html',context=f)

@login_required(login_url='log-page')
def PAKDID(request,id):
    PAS = PK.objects.get(id=id)
    PAS.delete()
    return HttpResponseRedirect(reverse('passkd-page'))

@login_required(login_url='log-page')
def PAKD_ID_INFO(request,id):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
    PAS = PK.objects.get(id=id)
    print(PAS.TITLE)
    PAS.URLS = decrypted_password = fernet.decrypt(PAS.URLS.encode()).decode()
    PAS.USERNAME = decrypted_password = fernet.decrypt(PAS.USERNAME.encode()).decode()
    PAS.PASSWORD = decrypted_password = fernet.decrypt(PAS.PASSWORD.encode()).decode()
    print(PAS.URLS)
    f={'KEEP':PAS}
    return render(request,'Password_Keep_Info.html',context={'KEEP':PAS})

@login_required(login_url='log-page')
def CS(request):
    print(request.user.id)
    U = User.objects.get(username=request.user)
    try:
        ATsniffer.Request_R(int(U.id))
    except:
        pass
        try:
            Status = request.POST['Status']
            print(Status)
            match(Status):
                case ("PStart") | ("PStop"):
                    packets = Psniffer.Psniffer_Switching(Status)
                case ("IStart") | ("IStop"):
                    packets = Isniffer.Isniffer_Switching(Status)
                case ("AStart") | ("AStop"):
                    packets = Asniffer.Asniffer_Switching(Status)
                case ("DStart") | ("DStop"):
                    packets = Dsniffer.Dsniffer_Switching(Status)
                case ("UStart") | ("UStop"):
                    packets = Usniffer.Usniffer_Switching(Status)
        except:
            pass
    return render(request,'Control_Sniffer.html')


@login_required(login_url='log-page')
def App_Settings(request):
    """
    صفحة إعدادات التطبيق:
    - عتبات الكشف (Detection)
    - ألوان وخطوط الواجهة (Theme)
    عند الحفظ يتم تحديث كائن AttackSniffer فوراً عبر Request_R.
    """
    user = request.user
    settings_obj = Settings.get_or_create_for_user(user)

    if request.method == 'POST':
        form = SettingsForm(request.POST, instance=settings_obj)
        if form.is_valid():
            form.save()
            # تطبيق عتبات الكشف على sniffer فوراً
            try:
                ATsniffer.Request_R(user.id)
            except Exception:
                # لا نكسر الصفحة لو sniffer فشل (مثلاً على لينكس بدون واجهة)
                pass
            messages.success(request, 'Settings saved successfully. Detection thresholds updated.')
            return redirect(reverse('settings-page'))
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = SettingsForm(instance=settings_obj)

    # قيم افتراضية للمعاينة في القالب
    context = {
        'theme_css': get_user_theme_css(user),
        'form': form,
        'settings_obj': settings_obj,
    }
    return render(request, 'Settings.html', context)


def get_user_theme_css(user):
    """
    يُرجع CSS variables مخصصة للمستخدم (لحقنها في <style>).
    يمكن استدعاؤها من أي view أو context processor.
    """
    if not user or not user.is_authenticated:
        return ''
    try:
        s = Settings.objects.get(User=user)
    except Settings.DoesNotExist:
        return ''

    # وضع فاتح: تعديلات بسيطة
    if s.theme_mode == 'light':
        bg = s.bg_primary if s.bg_primary != '#0a0e17' else '#f1f5f9'
        card = s.bg_card if s.bg_card != '#1a2332' else '#ffffff'
        text = s.text_primary if s.text_primary != '#e2e8f0' else '#0f172a'
    else:
        bg, card, text = s.bg_primary, s.bg_card, s.text_primary

    return f"""
:root {{
  --bg-primary: {bg};
  --bg-card: {card};
  --bg-secondary: {card};
  --bg-sidebar: {bg};
  --accent-cyan: {s.accent_color};
  --accent-green: {s.secondary_color};
  --text-primary: {text};
  --font-main: {s.font_family};
  --radius: {s.border_radius}px;
  --radius-sm: {max(4, s.border_radius - 4)}px;
}}
html, body {{
  font-size: {s.font_size_base}px;
  font-family: {s.font_family};
}}
"""
