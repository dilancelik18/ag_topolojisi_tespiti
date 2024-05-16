from scapy.all import rdpcap, IP, TCP,ICMP,UDP,ICMPv6ND_RS,DNS,IPv6,ICMPv6ND_RA,ARP,Ether,DNSQR
from scapy.all import *
from pyvis.network import Network
import networkx as nx
import matplotlib.pyplot as plt
import pyvis
from flask import Flask, render_template

from scapy.all import *




import networkx as nx
import matplotlib.pyplot as plt

app = Flask(__name__)



    
   

def extract_ip_addresses(pcap_file):
    ip_pairs = []

    # PCAP dosyasını aç
    packets = rdpcap(pcap_file)

    # Her paketi incele
    for packet in packets:
        # IP paketlerini filtrele
        if IP in packet:
            # Kaynak ve hedef IP adreslerini al
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            # IP çiftini listeye ekle
            ip_pairs.append((source_ip, destination_ip))

    return ip_pairs

def extract_arp_table(pcap_file):
    arp_table = {}

    # PCAP dosyasını aç
    packets = rdpcap(pcap_file)

    # Her paketi incele
    for packet in packets:
        # ARP paketlerini filtrele
        if ARP in packet:
            arp_packet = packet[ARP]
            # Cihazın IP adresi ve MAC adresini ekle
            arp_table[arp_packet.psrc] = arp_packet.hwsrc
            
    return arp_table

def list_dns_response_packets_with_ips(pcap_file):
    dns_response_packets_with_ips = set()
    pkts = rdpcap(pcap_file)
    for pkt in pkts:
        if DNS in pkt and IP in pkt:
            dns_response = pkt[DNS]
            if dns_response.qr == 1:  # DNS response paketi
                src_ip = pkt[IP].src
                dns_response_packets_with_ips.add(src_ip)
    return dns_response_packets_with_ips

def analyze_tls_traffic(pcap_file):
    client_ips = set()
    server_ips = set()
    pkts = rdpcap(pcap_file)
    for pkt in pkts:
        if TCP in pkt and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            # TLS trafiği genellikle 443 numaralı portta gerçekleşir
            if src_port == 443:
                server_ips.add(src_ip)
            elif dst_port == 443:
                client_ips.add(dst_ip)
    return client_ips, server_ips


# PCAP dosyası adı
pcap_file = "C:\\Users\\Dilce\\OneDrive\\Masaüstü\\sanal1.pcap"





# Kaynak ve hedef IP adreslerini çıkar
ip_pairs = extract_ip_addresses(pcap_file)

# Sonuçları yazdır
print("Kaynak IP adresleri\tHedef IP adresleri")
for source_ip, destination_ip in ip_pairs:
    print(f"{source_ip}\t\t{destination_ip}")
print("hey")



dns_response_packets_with_ips = list_dns_response_packets_with_ips(pcap_file)
print("DNS Response Döndüren Paketlerin IP Adresleri:")
for ip in dns_response_packets_with_ips:
        print(ip)

client_ips, server_ips = analyze_tls_traffic(pcap_file)
    
print("Client Devices:")
for ip in client_ips:
        print(ip)
    
print("\nServer Devices:")
for ip in server_ips:
     print(ip)



arp_table = extract_arp_table(pcap_file)
print("ARP Tablosu")
print(arp_table)


def extract_dns_ips(pcap_file):
    dns_ips = set()  # Tekrarlanan IP adreslerini önlemek için küme kullanılıyor

    # PCAP dosyasını oku
    packets = rdpcap(pcap_file)

    # Her paketi incele
    for packet in packets:
        # DNS isteklerini filtrele
        if DNS in packet and packet.haslayer(UDP) and packet[UDP].dport == 53:  # UDP/53 portundan gelen DNS istekleri
            dns_ip = packet[IP].dst  # Paketin hedef IP adresini al
            dns_ips.add(dns_ip)  # IP adresini kümeye ekle

    return list(dns_ips)  # Küme içeriğini bir listeye dönüştürerek döndür



def find_mac_without_ip(pcap_file):
    mac_without_ip = set()

    # PCAP dosyasını oku
    packets = rdpcap(pcap_file)

    # Her paketi incele
    for packet in packets:
        if Ether in packet:  # Paket Ethernet çerçevesi içeriyorsa
            if IP not in packet:  # Ancak IP paketi içermiyorsa
                src_mac = packet[Ether].src  # Kaynak MAC adresini al
                dst_mac = packet[Ether].dst  # Hedef MAC adresini al
                mac_without_ip.add(src_mac)  # Kaynak MAC adresini kümeye ekle
                mac_without_ip.add(dst_mac)  # Hedef MAC adresini kümeye ekle

    return list(mac_without_ip)  # Küme içeriğini bir listeye dönüştürerek döndür




dns_ips =extract_dns_ips(pcap_file)
print("Default Gateway ::" )
print(dns_ips)
mac_addresses = find_mac_without_ip(pcap_file)

print(mac_addresses)

def find_switch(mac_addresses, arp_table):
    switch_mac = None
    
    # MAC adreslerini ARP tablosundaki MAC adresleriyle karşılaştır
    for mac in mac_addresses:
        if mac not in arp_table.values() and mac != "ff:ff:ff:ff:ff:ff":  
            switch_mac = mac
            break
    
    return switch_mac

def switch_cihazi():
 switch_mac = find_switch(mac_addresses, arp_table)
 return switch_mac

def default_gate():
    addr = extract_dns_ips(pcap_file)
    return addr[0]



def draw_arp_network(arp_table, pcap_file):
    net = Network(notebook=False)
    for ip, mac in arp_table.items():
        net.add_node(ip, label=ip + "\n" + mac)
    
    switch_ip = None
    switch = switch_cihazi()
    default_gateway = default_gate()
    
    net.add_node('switch', switch, shape='square', color="red", title="switch")
    net.add_node("default_gateway", default_gateway, color="green", title="default gateway")
    net.add_node("cloud", shape="rectangle", color="yellow", title="cloud")
    
    for ip1, mac1 in arp_table.items():
        if ip1 != switch:
            net.add_edge(ip1, 'switch')
    net.add_edge("switch", "default_gateway")
    net.add_edge("cloud", "default_gateway")
    
    packets = rdpcap(pcap_file)
    for packet in packets:
        if IP in packet:
            dest_ip = packet[IP].dst
            if dest_ip not in arp_table:
                net.add_node(dest_ip)
                net.add_edge("cloud", dest_ip)
    
    # ARP tablosunu HTML tablosunda göstermek için ekleyelim
    arp_table_html = "<h2>ARP Table</h2>"
    arp_table_html += "<table border='1'>"
    arp_table_html += "<tr><th>IP Address</th><th>MAC Address</th></tr>"
    for ip, mac in arp_table.items():
        arp_table_html += f"<tr><td>{ip}</td><td>{mac}</td></tr>"
    arp_table_html += "</table>"
    net.html += arp_table_html
    
    net.save_graph("static/arp_table.html")




@app.route('/')
def show_arp_network():
    pcap_file = "C:\\Users\\Dilce\\OneDrive\\Masaüstü\\sanal1.pcap"
    arp_table = extract_arp_table(pcap_file)
    draw_arp_network(arp_table, pcap_file)
    return render_template('index.html')
    

@app.route('/arp')
def show_arp_table():
    arp_table = extract_arp_table(pcap_file)
    return render_template('arp_table.html', arp_table=arp_table)

if __name__ == '__main__':
    app.run(debug=True)

