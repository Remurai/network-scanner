import re
import nmap
import socket
import logging
import scapy_p0f
from typing import List
from time import strftime
from datetime import datetime
from ipaddress import IPv4Network
from scapy.all import ICMP, IP, TCP, DNS, DNSQR, UDP, ARP, Ether, srp, sr, sr1, sniff, wrpcap, RandShort
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
start_clock = datetime.now

print(r"""
     __     _                      _        _               _                    
  /\ \ \___| |___      _____  _ __| | __   /_\  _ __   __ _| |_   _ _______ _ __ 
 /  \/ / _ \ __\ \ /\ / / _ \| '__| |/ /  //_\\| '_ \ / _` | | | | |_  / _ \ '__|
/ /\  /  __/ |_ \ V  V / (_) | |  |   <  /  _  \ | | | (_| | | |_| |/ /  __/ |   
\_\ \/ \___|\__| \_/\_/ \___/|_|  |_|\_\ \_/ \_/_| |_|\__,_|_|\__, /___\___|_|   
                                                              |___/              
""")
print("\n*********************************************************************************")
print("\n|         Created by Ong Yong Quan                                              |")
print("\n|         Student of UOW KDU Penang College University                          |")
print("\n*********************************************************************************\n")

def main():
    command = 0
    while command != '8':
        menu()
        command = input("\n[-]Which options (1-8): ")
        match command:
            #Hostname
            case '1':
                hostname = socket.gethostname()
                ip_address = get_ip()
                print(f"\nHostname: {hostname}")
                print(f"IP Address: {ip_address}")
                input("\n[-]Press Enter to continue...")

            #IP Scanner
            case '2':
                ip_scan()
                input("\n[-]Press Enter to continue...")

            #Port Scanner
            case '3':
                port_scan()
                input("\nPress Enter to continue...")

            #DNS Search
            case '4':
                dns_search()
                input("\n[-]Press Enter to continue...")

            #Traceroute
            case '5':
                trace_route()
                input("\n[-]Press Enter to continue...")

            #Traffic Analysis
            case '6':
                capture_traffic()
                input("\n[-]Press Enter to continue...")

            #OS detection
            case '7':
                os_detect()
                input("\n[-]Press Enter to continue...")

            #Exiting Program
            case '8':
                print("\n[-]Exit Successfully.\n")
            
            #Help Command
            case 'help':
                helpCommand()
                input("\n[-]Press Enter to continue...")

            case _:
                option_check()

#Display start scan time
def scan_start(user_input: str):
    global start_clock
    print(f"[-]Scanning {user_input}")
    print("[-]Scanning started at: " + strftime("%H:%M:%S") + "\n")
    start_clock = datetime.now()

#Display end scan time
def scan_end():
    global start_clock
    stop_clock = datetime.now()
    total_time = stop_clock - start_clock
    print("\n[-]Scanning Finished")
    print("[-]Total Duration: " +  str(total_time))

#Check IP address and range format
def ip_input():
    # Regular Expression pattern
    ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    # Get the address
    while True:
        ip_address = input("\n[-]Enter Target IP address (eg. 192.168.0.1): ")
        if ip_pattern.search(ip_address):
            scan_start(ip_address)
            break
    return ip_address

#Check IP address format
def ip_range_input():
    # Regular Expression pattern
    ip_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")

    # Get the address range
    while True:
        ip_range_address = input("\n[-]Enter Target IP address and range (eg. 192.168.0.0/24): ")
        if ip_range_pattern.search(ip_range_address):
            scan_start(ip_range_address)
            break
    return ip_range_address

#Check URL address format
def url_input():
    url_pattern = re.compile("[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)")
    ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    # Get the address
    while True:
        url = input("\n[-]Please enter URL or IP address (eg. www.google.com or 192.168.101.1): ")
        if url_pattern.search(url) or ip_pattern.search(url):
            scan_start(url)
            break
    return url

#Get Wireless IP address
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

#Check the option dialog
def option_check():
    print("\n[-]Please choose the available options.")
    input("[-]Press Enter to try again...")

#Host Discovery function
def ip_scan():
    command = 0
    while command != '8':
        #Menu
        print("\n1. ARP Ping")
        print("2. Ping Sweep (ICMP)")
        print("3. ICMP Echo Ping")
        print("4. TCP SYN Ping")
        print("5. TCP ACK Ping")
        print("6. UDP Ping")
        print("7. IP Protocol Ping")
        print("8. Exit")

        command = input("\n[-]Which options (1-8): ")
        match command:
            #ARP to ping all available host
            case '1':
                arp = ARP(pdst=ip_range_input())
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                result = srp(packet, timeout=2, verbose=0)[0]

                clients = []
                for sent, received in result:
                    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

                print("Available devices in the network:")
                print("IP" + " "*18+"MAC")
                for client in clients:
                    print("{:16}    {}".format(client['ip'], client['mac']))
                scan_end()

            case '2':
                ping_sweep()
            case '3':
                ping("ICMP")
            case '4':
                ping("TCP_SYN")
            case '5':
                ping("TCP_ACK")
            case '6':
                ping("UDP")
            case '7':
                ping("IP")
            case '8':
                break
            case _:
                option_check()

#Ping one host
def ping(type: str):
    host = ip_input()
    match type:
        case 'ICMP':
            result = sr1(IP(dst=host)/ICMP(),timeout=1,verbose=0,)
        case 'TCP_SYN':
            result = sr1(IP(dst=host)/TCP(dport=80,flags="S"),timeout=1,verbose=0,)
        case 'TCP_ACK':
            result = sr1(IP(dst=host)/TCP(dport=80,flags="A"),timeout=1,verbose=0,)
        case 'UDP':
            result = sr1(IP(dst=host)/UDP(dport=0),timeout=1,verbose=0,)
        case 'IP':
            result,unans = sr(IP(dst=host,proto=(0,70)),timeout=3,verbose=0)

    if not (result is None):
        print(f"{host} is responding.")
        print(result.summary())
    else:
        print(f"{host} is not responding.")
    scan_end()

#Ping multiple host
def ping_sweep():
    # make list of addresses out of network, set live host counter
    addresses = IPv4Network(ip_range_input())
    live_count = 0

    for host in addresses:
        if (host in (addresses.network_address, addresses.broadcast_address)):
            # Skip network and broadcast addresses
            continue

        result = sr1(IP(dst=str(host))/ICMP(),timeout=1,verbose=0,)

        if not (result is None):
            print(f"{host} is responding.")
            print(result.summary())
            live_count += 1
        
    print(f"{live_count}/{addresses.num_addresses} hosts are up.")
    scan_end()

#Port scanning function
def port_scan():
    # Define common TCP/UDP port range
    ports = [21,22,23,25,53,80,110,111,135,139,143,156,443]
    command = 0
    while command != '8':
        #Menu
        print("\n1. TCP Connect Scan")
        print("2. TCP Stealth Scan")
        print("3. TCP ACK Scan")
        print("4. TCP Window Scan")
        print("5. XMAS Scan")
        print("6. FIN Scan")
        print("7. NULL Scan")
        print("8. Exit")
        command = input("\n[-]Which options (1-8): ")
        
        match command:
            case '1':
                connect_scan(ip_input(), ports)
            case '2':
                stealth_scan(ip_input(), ports)
            case '3':
                ack_scan(ip_input(), ports)
            case '4':
                window_scan(ip_input(), ports)
            case '5':
                xmas_scan(ip_input(), ports)
            case '6':
                fin_scan(ip_input(), ports)
            case '7':
                null_scan(ip_input(), ports)
            case '8':
                break
            case _:
                option_check()

#TCP Connect Scan function
def connect_scan(host: str, ports: List[int]):
    for dst_port in ports:
        src_port = RandShort()
        resp = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"), timeout=1, verbose=0)
        service = socket.getservbyport(dst_port)
        if resp is None:
            print(f"Port {dst_port}: {service} is Closed")

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                send_rst = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="AR"), timeout=1, verbose=0)
                print(f"Port {dst_port}: {service} is Open")

            elif (resp.getlayer(TCP).flags == 0x14):
                print(f"Port {dst_port}: {service} is Closed")
    scan_end()

#TCP Stealth Scan function
def stealth_scan(host: str, ports: List[int]):
    for dst_port in ports:
        src_port = RandShort()
        resp = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"), timeout=1, verbose=0)
        service = socket.getservbyport(dst_port)
        if resp is None:
            print(f"Port {dst_port}: {service} is Filtered")

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                send_rst = sr1(IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'), timeout=1, verbose=0)
                print(f"Port {dst_port}: {service} is Open")

            elif (resp.getlayer(TCP).flags == 0x14):
                print(f"Port {dst_port}: {service} is Closed")

        elif(resp.haslayer(ICMP)):
            if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)):
                print(f"Port {dst_port}: {service} is Filtered")
    scan_end()

#TCP ACK Scan function
def ack_scan(host: str, ports: List[int]):
    for dst_port in ports:
        resp = sr1(IP(dst=host)/TCP(dport=dst_port,flags="A"), timeout=1, verbose=0)
        service = socket.getservbyport(dst_port)
        if resp is None:
            print(f"Port {dst_port}: {service} is Filtered (Stateful Firewall)")

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x4):
                print(f"Port {dst_port}: {service} is Unfiltered (No Firewall)")

        elif(resp.haslayer(ICMP)):
            if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)):
                print(f"Port {dst_port}: {service} is Filtered (Stateful Firewall)")
    scan_end()

#TCP Window Scan function
def window_scan(host: str, ports: List[int]):
    for dst_port in ports:
        resp = sr1(IP(dst=host)/TCP(dport=dst_port,flags="A"), timeout=1, verbose=0)
        service = socket.getservbyport(dst_port)
        if resp is None:
            print(f"Port {dst_port}: {service} is not responding")

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).window == 0):
                print(f"Port {dst_port}: {service} is Closed")

            elif (resp.getlayer(TCP).window > 0):
                print(f"Port {dst_port}: {service} is Open")
    scan_end()

#XMAS Scan function
def xmas_scan(host: str, ports: List[int]):
    for dst_port in ports:
        resp = sr1(IP(dst=host)/TCP(dport=dst_port,flags="FPU"), timeout=1, verbose=0)
        service = socket.getservbyport(dst_port)
        if resp is None:
            print(f"Port {dst_port}: {service} is Open | Filtered")

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x14):
                print(f"Port {dst_port}: {service} is Closed")

        elif(resp.haslayer(ICMP)):
            if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)):
                print(f"Port {dst_port}: {service} is Filtered")
    scan_end()

#FIN Scan function
def fin_scan(host: str, ports: List[int]):
    for dst_port in ports:
        resp = sr1(IP(dst=host)/TCP(dport=dst_port,flags="F"), timeout=1, verbose=0)
        service = socket.getservbyport(dst_port)
        if resp is None:
            print(f"Port {dst_port}: {service} is Open | Filtered")

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x14):
                print(f"Port {dst_port}: {service} is Closed")

        elif(resp.haslayer(ICMP)):
            if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)):
                print(f"Port {dst_port}: {service} is Filtered")
    scan_end()

#NULL Scan function
def null_scan(host: str, ports: List[int]):
    for dst_port in ports:
        resp = sr1(IP(dst=host)/TCP(dport=dst_port,flags=""), timeout=1, verbose=0)
        service = socket.getservbyport(dst_port)
        if resp is None:
            print(f"Port {dst_port}: {service} is Open | Filtered")

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x14):
                print(f"Port {dst_port}: {service} is Closed")

        elif(resp.haslayer(ICMP)):
            if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)):
                print(f"Port {dst_port}: {service} is Filtered")
    scan_end()

#DNS Search function
def dns_search():
    packet = IP(dst='8.8.8.8')/UDP()/DNS(rd=1, qd=DNSQR(qname=url_input()))
    result = sr1(packet, verbose=0)
    print(result[DNS].summary())
    scan_end()

#Traceroute function
def trace_route():
    command = 0
    while command != '4':
        #Menu
        print("\n1. ICMP Trace")
        print("2. TCP Trace")
        print("3. IP Fragment Trace")
        print("4. Exit")
        command = input("\n[-]Which options (1-4): ")
        match command:
            case '1':
                ans, unans = sr(IP(dst=url_input(),ttl=(1,20))/ICMP(), timeout=2)
                for s, r in ans:
                    if isinstance(r.payload, ICMP):
                        type = "ICMP"
                    else:
                        type = "None"
                    print(s.ttl, r.src, type)
                scan_end()

            case '2':
                ans, unans = sr(IP(dst=url_input(), ttl=(1,20),id=RandShort())/TCP(flags=0x2), timeout=3)
                for s, r in ans:
                    if isinstance(r.payload, TCP):
                        type = "TCP"
                    else:
                        type = "None"
                    print(s.ttl, r.src, type)
                scan_end()

            case '3':
                ans, unans = sr(IP(dst=url_input(), ttl=(1,20), flags="MF")/UDP(sport=RandShort(), dport=53), timeout=1)
                for s, r in ans:
                    if isinstance(r.payload, IP):
                        type = "IP"
                    elif isinstance(r.payload, UDP):
                        type = "UDP"
                    else:
                        type = "None"
                    print(s.ttl, r.src, type)
                scan_end()

            case '4':
                break

            case _:
                option_check()
    
#Traffic Analysis function
def capture_traffic():
    command = 0
    capture = ""
    while command != '5':
        #Menu
        print("\n1. Continuous/Limited Capture")
        print("2. Specific Capture (Host, Protocol, Port)")
        print("3. Save Current Captured file")
        print("4. Load Previous Captured file")
        print("5. Exit")

        command = input("\n[-]Which options (1-5): ")
        match command:
            #Capture continously or limited network traffic
            case '1':
                while True:
                    try:
                        num = int(input("\n[-]How many packets you want to capture (0=continous): "))
                    except ValueError:
                        print("Please, enter a valid integer")
                    else:
                        break
                    
                scan_start(get_ip())
                capture = sniff(count=num,prn=lambda x:x.summary())
                scan_end()

            #Capture specific network traffic
            case '2':
                filter_result = ""

                while True:
                    try:
                        num = int(input("\n[-]How many packets you want to capture (0=continous): "))
                    except ValueError:
                        print("Please, enter a valid integer")
                    else:
                        break

                host = input("\n[-]Enter a host (Blank = None): ")
                protocol = input("\n[-]Enter a protocol (Blank = None): ")
                port = input("\n[-]Enter a port (Blank = None): ")
                
                if host:
                    filter_result += f"host {host} "
                if protocol:
                    if host:
                        filter_result += "and "
                    filter_result += f"{protocol} "
                if port:
                    if protocol:
                        filter_result += "and "
                    filter_result += f"port {port} "

                scan_start(get_ip())
                capture = sniff(count=num,filter=filter_result,prn=lambda x:x.summary())
                scan_end()

            #Save current pcap file
            case '3':
                if capture:
                    wrpcap("captured.pcap", capture)
                    print("Successfully saved")
                else:
                    print("Cannot save without sniffing")

            #Load previous pcap file
            case '4':
                sniff(offline="captured.pcap",prn=lambda x:x.summary())

            case '5':
                break

            case _:
                option_check()

#Operating System Detection function
def os_detect():
    command = 0
    while command != '5':
        print("\n1. Active (nmap)")
        print("2. Passive (p0f)")
        print("3. Exit")

        command = input("\n[-]Which options (1-3): ")
        match command:
            #Active fingerprinting
            case '1':
                host = ip_input()
                nm = nmap.PortScanner()
                result = nm.scan(host, arguments="-O")
                try:
                    state = result["scan"][host]["status"]["state"]
                except:
                    state = "down"
                print(f"Host state: {state}")

                try:
                    print(f'Operating System: {result["scan"][host]["osmatch"][0]["name"]}')
                except:
                    print("Operating System not found")
                scan_end()

            #Passive fingerprinting
            case '2':
                scan_start(get_ip())
                sniff(prn=scapy_p0f.prnp0f)
                scan_end()

            case '3':
                break

            case _:
                option_check()

#Display help commands
def helpCommand():
    print("\nCurrent Hostname - Get current hostname and IP address of Wifi interface")
    print("\nHost Discovery - Scan all active host's IP address")
    print("   ARP Ping - Discover the host devices in the same network (Note: Not visible due to firewall filtering)")
    print("   Ping Sweep (ICMP) - Discovers on the basis the host is powered on")
    print("   ICMP Echo Ping - Sends ICMP packets to the available host")
    print("   TCP_SYN Ping - Checks whether a host is online")
    print("   TCP_ACK Ping - Checks whether the host is responding")
    print("   UDP Ping - Sends the UDP packets to the targeted port")
    print("   IP Protocol Ping - Send different packets using different protocols")
    print("\nPort Scanner - Scan the open, closed or filtered ports on specifc IP address")
    print("   TCP Connect Scan - Three-way handshake between the client and the server")
    print("   TCP Stealth Scan - Similar to TCP Connect Scan but client sends a RST flag in a TCP packet")
    print("   TCP ACK Scan - Find if a stateful firewall is present on the server or not")
    print("   TCP Window Scan - Similar to TCP ACK Scan but find the state of the port on the server")
    print("   XMAS Scan - Sends TCP packet with the PSH, FIN, and URG flags set")
    print("   FIN Scan - Sends TCP packet with only FIN flag")
    print("   NULL Scan - Sends TCP packet with no flag")
    print("\nDNS Search - Search the IP address of the Domain Name System")
    print("\nTraceroute - Discover the hops or routes to the targeted host.")
    print("   ICMP Trace - Trace the route by sending ICMP packets")
    print("   TCP Trace - Trace the route by sending TCP packets")
    print("   IP Fragment Trace - Trace the route by breaking IP packets into smaller fragments")
    print("\nTraffic Analysis - Captures all of the network packet traffic")
    print("   Continuous/Limited Capture - Captures the network packets continously or limited number")
    print("   Specific Capture - Captures the network packers by host, port and protocol")
    print("   Save Captured file - Save the captured packets into a file in pcap format")
    print("   Load Captured file - Load the pcap file from previous captured packets")
    print("\nOS detection - Analyze and detects the operating system of the specific host's IP address")
    print("   Active - Sends TCP and UDP packets to remote host and examines to compare against the behaviour of OS for a match.")
    print("   Passive - Analyze network traffic to detect what OS the client/server are running")

#Display Home Menu
def menu():
    print("\n1. Current Hostname")
    print("2. Host Discovery")
    print("3. Port Scanner")
    print("4. DNS Search")
    print("5. Traceroute")
    print("6. Traffic Analysis")
    print("7. OS Detection")
    print("8. Exit")
    print("\nType help to get the descriptions of the menu and functions")

if __name__ == '__main__':
    main()