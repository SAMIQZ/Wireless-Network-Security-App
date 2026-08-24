Wireless Network Security App (MCS Pro)


A comprehensive Django-based web application for real-time wireless network monitoring, threat detection, and security analysis.
Developed as a graduation project in Communications Technology.



Python
Django
Scapy
License
Platform
Status



Overview

Wireless Network Security App is a full-stack security tool designed to monitor, analyze, and protect wireless (Wi-Fi) networks in real time.


It combines packet sniffing, anomaly detection, network diagnostics, and reporting into a single web-based dashboard. The application focuses on practical defensive capabilities against common Layer 2 / Layer 3 attacks while providing useful network management features.



Primary Goal: Detect and alert on suspicious network activity (ARP spoofing, MAC flooding, DoS, brute-force attempts, etc.) with configurable thresholds and automatic PDF report generation.




Key Features

Real-Time Threat Detection

Attack Type	Detection Method
ARP Spoofing	MAC–IP mapping inconsistency
IP Spoofing	Source IP validation
MAC Flooding	Rapid unique MAC address count
DoS / Flooding	Packet rate thresholds (TCP / IP / ICMP)
Brute-Force Attempts	Failed login pattern detection
Suspicious Traffic	Known malware ports + payload signatures
Deauthentication / ICMP	Abnormal ICMP reply rates

Network Monitoring & Analysis


Live packet sniffers (ARP, DNS, ICMP, TCP, HTTP/URL)

Device discovery via ARP scanning


Internet speed test (download / upload / ping)

Latency, packet loss & throughput analysis

Active connections listing


Security Utilities


Strong password generator

Password strength checker

Local password vault

Automatic PDF attack reports

Failed login tracking with lockout logic


Additional Tools


Traceroute

DNS query monitoring




Technology Stack

Layer	Technologies
Backend	Python 3.10+, Django 6.0
Packet Analysis	Scapy 2.7
Network Tools	python-nmap, ping3, psutil, speedtest-cli
Reporting	ReportLab, python-docx, openpyxl, matplotlib
Authentication	Django Auth + Paramiko (SSH)
Frontend	HTML / CSS  (custom templates)
Security Libraries	pyOpenSSL, Requests


Project Structure

Wireless-Network-Security-App/
├── FINAL_PROJECT/
│   ├── ATTACKS/                      # Educational attack simulation scripts
│   │   ├── arp-spoof.py
│   │   ├── mac-flooding.py
│   │   ├── DOS-Attack.py
│   │   ├── brute_force2.py
│   │   └── ...
│   └── MCS_PRO/                      # Main Django application
│       ├── MCS_PRO/                  # Project settings (urls, settings, wsgi)
│       ├── NETWORK_MANGER/           # Core app (legacy name – see Improvements)
│       │   ├── models.py
│       │   ├── views.py              # Main views (to be split – see docs/)
│       │   ├── sniffer.py            # Real-time attack detection engine
│       │   ├── network.py            # Network utilities
│       │   ├── forms.py
│       │   └── urls.py
│       ├── templates/
│       ├── static/
│       ├── manage.py
│       └── requirements.txt
├── LICENSE
└── README.md


Note: A recommended cleaner structure is documented in docs/IMPROVEMENTS.md.




Installation & Setup

Prerequisites


Windows OS (primary target platform)

Python 3.10 or higher

Npcap (required by Scapy for packet capture)

Administrator privileges (recommended for packet sniffing)


Steps

# 1. Clone the repository
git clone https://github.com/SAMIQZ/Wireless-Network-Security-App.git
cd Wireless-Network-Security-App/FINAL_PROJECT/MCS_PRO

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Apply database migrations
python manage.py migrate

# 5. (Optional) Create a Django superuser for the admin panel
python manage.py createsuperuser

# 6. Run the development server
python manage.py runserver

Open your browser at: http://127.0.0.1:8000



Usage Highlights


Login using SSH credentials of a Windows host (hostname + username + password).

Configure protection thresholds from the Home dashboard.

Start individual sniffers or the full Attack Detection engine.

View live alerts, generate PDF reports, and monitor network performance.

Use the built-in password tools and local password vault.



Educational Attack Scripts

The ATTACKS/ folder contains scripts used for testing the detection engine in a controlled lab environment:



ARP Spoofing

MAC Flooding

ICMP Smurf

DoS / Flooding

Brute-force simulations

Suspicious TCP / UDP traffic generators



Warning: These scripts are for educational and authorized testing purposes only. Unauthorized use against networks you do not own or have explicit permission to test is illegal.




Security Notes & Limitations

This project was built for educational and research purposes. Please be aware of the following:

Author

SAMIQZ
Graduation Project – Communications Technology



License

This project is licensed under the MIT License. See the LICENSE file for details.



Disclaimer

This software is provided for educational and research purposes only.
The author is not responsible for any misuse of the tools or scripts included in this repository.
Related: [Malware Analysis Reports](https://github.com/USERNAME/malware-analysis-reports)
Always obtain proper authorization before testing security tools on any network.