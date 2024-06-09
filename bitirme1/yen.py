from flask import Flask, render_template, request, redirect, url_for, send_file
from scapy.all import rdpcap, IP, TCP, ICMP, UDP, DNS, ARP, Ether
from pyvis.network import Network
from datetime import datetime
import os
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('agg')
import scapy.all as scapy
import networkx as nx
from collections import Counter
from dpkt.compat import compat_ord
from flask import Flask, render_template, request, redirect, url_for, send_file, g
import time
import psutil

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])



@app.before_request
def start_timer():
    g.start_time = time.time()
    g.cpu_start = psutil.cpu_percent(interval=None)

@app.after_request
def log_request(response):
    if hasattr(g, 'start_time') and hasattr(g, 'cpu_start'):
        elapsed_time = time.time() - g.start_time
        cpu_usage = psutil.cpu_percent(interval=None) - g.cpu_start
        print(f"İstek süresi {elapsed_time:.4f} sn ve kullanılan  {cpu_usage:.2f}% CPU")
    return response


def extract_ip_addresses(packets):
    return [(packet[IP].src, packet[IP].dst) for packet in packets if IP in packet]

def extract_arp_table(packets):
    return {packet[ARP].psrc: packet[ARP].hwsrc for packet in packets if ARP in packet}

def analyze_tls_traffic(packets):
    client_ips = set()
    server_ips = set()
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            if src_port == 443:
                server_ips.add(src_ip)
            elif dst_port == 443:
                client_ips.add(dst_ip)
    return client_ips, server_ips

def convert_time(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def protokoller(packets):
    # TCP paketlerini filtrele
    tcp_packets = [pkt for pkt in packets if TCP in pkt]

    # HTTP paketlerini filtrele
    http_packets = [pkt for pkt in tcp_packets if pkt[TCP].dport == 80 or pkt[TCP].sport == 80]

    # HTTPS paketlerini filtrele
    https_packets = [pkt for pkt in tcp_packets if pkt[TCP].dport == 443 or pkt[TCP].sport == 443]

    # Diğer TCP paketleri (HTTP ve HTTPS dışındakiler)
    other_tcp_packets = [pkt for pkt in tcp_packets if pkt not in http_packets and pkt not in https_packets]

    # UDP paketlerini filtrele
    udp_packets = [pkt for pkt in packets if UDP in pkt]

    # ICMP paketlerini filtrele
    icmp_packets = [pkt for pkt in packets if ICMP in pkt]

    # Diğer protokollerin paket sayılarını hesapla
    total_other = len(other_tcp_packets) + len(udp_packets) + len(icmp_packets)

    # Tüm protokol sayılarını hesapla
    total_tcp = len(tcp_packets)
    total_udp = len(udp_packets)
    total_icmp = len(icmp_packets)
    total_http = len(http_packets)
    total_https = len(https_packets)
    total_others = total_other

    # Bar grafiği oluştur
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'Others']
    packet_counts = [total_tcp, total_udp, total_icmp, total_http, total_https, total_others]

    plt.bar(protocols, packet_counts, color=['blue', 'green', 'red', 'orange', 'purple', 'cyan'])
    plt.xlabel('Protokol')
    plt.ylabel('Toplam Paket')
    plt.title('Protokol Dağılımı')

    # Grafiği kaydet
    graph_path = os.path.join('static', 'protocol_distribution.png')
    plt.savefig(graph_path)
    plt.close()



def plot_packet_count_by_time(packets):
    # Zaman damgalarını datetime formatına dönüştür
    timestamps = [datetime.fromtimestamp(float(packet.time)) for packet in packets]
    time_counter = Counter(timestamps)

    # Zaman damgalarına göre paket sayılarını ayrıştır
    sorted_timestamps = sorted(time_counter.keys())
    packet_counts = [time_counter[timestamp] for timestamp in sorted_timestamps]

    plt.figure(figsize=(10, 5))
    plt.plot(sorted_timestamps, packet_counts, marker='o', linestyle='-')
    plt.xlabel('Zaman')
    plt.ylabel('Paket Sayısı')
    plt.title('Zamana Göre Paket Sayısı Analizi')
    plt.grid(True)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('static/analys.png')
    plt.close()

def plot_ip_connections(packets):
    # NetworkX graph objesi oluştur
    G = nx.DiGraph()

    # Kaynak ve hedef IP adresleri arasındaki bağlantıları ekle
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            G.add_edge(src_ip, dst_ip)

    # Grafik çizim boyutlarını belirle
    plt.figure(figsize=(12, 8))

    # Düğümleri ve kenarları çiz
    pos = nx.spring_layout(G, k=0.5)  # Kümelenme düzenini ayarla, k değerini artırarak düğümler arasındaki mesafeyi artırın
    nx.draw(G, pos, with_labels=True, node_size=3000, node_color='skyblue', font_size=10, font_weight='bold', edge_color='gray', arrows=True)

    # Grafiği kaydet
    plt.title('Kaynak ve Hedef IP Adresleri Arasındaki Bağlantılar')
    plt.savefig('static/ip_connections.png')
    plt.close()

def count_tcp_flags(packets):
    # TCP bayrak türlerini saymak için bir sözlük oluştur
    flag_counts = {
        'SYN': 0,
        'ACK': 0,
        'FIN': 0,
        'RST': 0,
        'PSH': 0,
        'URG': 0,
        'ECE': 0,
        'CWR': 0
    }

    # Her paketi incele ve TCP bayraklarını say
    for packet in packets:
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            if tcp_flags & 0x02:  # SYN bayrağı
                flag_counts['SYN'] += 1
            if tcp_flags & 0x10:  # ACK bayrağı
                flag_counts['ACK'] += 1
            if tcp_flags & 0x01:  # FIN bayrağı
                flag_counts['FIN'] += 1
            if tcp_flags & 0x04:  # RST bayrağı
                flag_counts['RST'] += 1
            if tcp_flags & 0x08:  # PSH bayrağı
                flag_counts['PSH'] += 1
            if tcp_flags & 0x20:  # URG bayrağı
                flag_counts['URG'] += 1
            if tcp_flags & 0x40:  # ECE bayrağı
                flag_counts['ECE'] += 1
            if tcp_flags & 0x80:  # CWR bayrağı
                flag_counts['CWR'] += 1

    return flag_counts

def plot_tcp_flags(flag_counts):
    # Bayrak türlerini ve sayıları listelere ayır
    flags = list(flag_counts.keys())
    counts = list(flag_counts.values())

    # Grafik oluştur
    plt.figure(figsize=(10, 5))
    bars = plt.bar(flags, counts, color='skyblue')
    plt.xlabel('TCP Bayrak Türleri')
    plt.ylabel('Sayı')
    plt.title('TCP Bayrak Türlerinin Dağılımı')
    plt.grid(True)

    # Her çubuğun üstüne sayıları ekle
    plt.bar_label(bars, labels=counts, label_type='edge')

    # Grafiği kaydet
    plt.savefig('static/tcp_flags.png')
    plt.close() 

def find_syn_ack_pairs(packets):
    syn_ack_pairs = set()

    for packet in packets:
        if IP in packet and TCP in packet:
            tcp_flags = packet[TCP].flags
            if tcp_flags & 0x12:  # SYN+ACK bayrakları
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                syn_ack_pairs.add((src_ip, dst_ip))

    return syn_ack_pairs

def extract_dns_ips(packets):
    return list({packet[IP].dst for packet in packets if DNS in packet and UDP in packet and packet[UDP].dport == 53})

def find_mac_without_ip(packets):
    return list({packet[Ether].src for packet in packets if Ether in packet and IP not in packet} |
                {packet[Ether].dst for packet in packets if Ether in packet and IP not in packet})



def find_gateway(pcap_file):
    """
    Bir pcap dosyasından yönlendirme yapan cihazın ağ geçidini bulur.

    Args:
        pcap_file: Pcap dosyasının yolu.

    Returns:
        Ağ geçidinin IP adresi veya None.
    """
    packets = scapy.rdpcap(pcap_file)
    arp_table = extract_arp_table(packets)
    possible_gateways = {}

    # ARP isteklerini işle
    for packet in packets:
        if ARP in packet and packet[ARP].op == 1:  # ARP request
            if packet[ARP].pdst in possible_gateways:
                possible_gateways[packet[ARP].pdst] += 1
            else:
                possible_gateways[packet[ARP].pdst] = 1

    # TCP trafiğini işle
    for packet in packets:
        if IP in packet and TCP in packet:
            if packet[IP].dst in possible_gateways:
                possible_gateways[packet[IP].dst] += 1
            else:
                possible_gateways[packet[IP].dst] = 1

    if possible_gateways:
        gateway_ip = max(possible_gateways, key=possible_gateways.get)
        return gateway_ip

    return None

def extract_ips_and_domains(packets):
    ip_domain_pairs = []
    for packet in packets:
        if IP in packet:
            ip_address = packet[IP].dst
            domain_name = None
            if DNS in packet and packet[DNS].qr == 0:
                if hasattr(packet[DNS], 'qd') and hasattr(packet[DNS].qd, 'qname'):
                    domain_name = packet[DNS].qd.qname.decode()
            # Eğer domain_name değeri yoksa veya boş bir string ise, paketi ekleme
            if domain_name:
                ip_domain_pairs.append((ip_address, domain_name))
    return ip_domain_pairs

def find_switch(mac_addresses, arp_table):
    switch_mac = None
    
    # MAC adreslerini ARP tablosundaki MAC adresleriyle karşılaştır
    for mac in mac_addresses:
        if mac not in arp_table.values() and mac != "ff:ff:ff:ff:ff:ff":  
            switch_mac = mac
            break
    
    return switch_mac



def draw_arp_network(arp_table, packets, mac_addresses, dns_ips):
    net = Network(notebook=False)
    for ip, mac in arp_table.items():
        net.add_node(ip, label=ip + "\n" + mac)

    switch = find_switch(mac_addresses, arp_table)
    default_gateway = dns_ips[0] if dns_ips else "Unknown"

    # Switch için pembe renk kullanılıyor
    net.add_node('switch', switch, shape='square', color="pink", title="switch")
    # Default gateway için mor renk kullanılıyor
    net.add_node("default_gateway", label=default_gateway, color="purple", title="default gateway")
    # Bulut cihazı için sarı renk kullanılıyor
    net.add_node("internet", shape="rectangle", color="yellow", title="internet")

    for ip1 in arp_table.keys():
        if ip1 != switch:
            net.add_edge(ip1, 'switch')
    net.add_edge("switch", "default_gateway")
    net.add_edge("internet", "default_gateway")

    for packet in packets:
        if IP in packet:
            dest_ip = packet[IP].dst
            if dest_ip not in arp_table:
                if DNS in packet:
                    if hasattr(packet[DNS], 'qd') and hasattr(packet[DNS].qd, 'qname'):
                        domain_name = packet[DNS].qd.qname.decode()
                        net.add_node(dest_ip, title=domain_name, label=dest_ip + "\n" + domain_name)
                    else:
                        net.add_node(dest_ip)
                else:
                    net.add_node(dest_ip)
                net.add_edge("internet", dest_ip)

    output_path = os.path.join('static', 'index.html')
    net.save_graph(output_path)

    # Navbar için HTML kodu
    navbar_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ARP Network Graph</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
        <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
    </head>
    <body>

        <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">Anasayfa</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
      
        <div class="collapse navbar-collapse" id="navbarSupportedContent">
          <ul class="navbar-nav mr-auto">
            <li class="nav-item active">
              <a class="nav-link">Ağ Topolojisi <span class="sr-only"></span></a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="/arp">Analizler</a>
            </li>
           
              
            </li>
           
          </ul>
          
        </div>
      </nav>
        <div class="container">
    """

    with open(output_path, "r") as file:
        graph_html = file.read()

    # Navbar ve grafiğin birleşimi
    final_html = navbar_html + graph_html + "</div></body></html>"

    with open(output_path, "w") as file:
        file.write(final_html)

    print(f"Graph saved to {output_path}")

def is_tls_handshake(tcp_data):
    """Check if TCP data contains a TLS handshake."""
    if len(tcp_data) > 0 and TCP in tcp_data:
        record_type = tcp_data[TCP].flags
        # TLS handshake record type is 0x16
        return record_type == 0x16
    return False

def is_server_hello(tcp_data):
    """Check if TCP data contains a ServerHello message."""
    if len(tcp_data) > 5 and TCP in tcp_data:  # Check if it is a handshake
        handshake_type = tcp_data[TCP].flags
        # ServerHello handshake type is 0x02
        return handshake_type == 0x02
    return False

def find_servers(packets):
    servers = set()

    for packet in packets:
        if IP in packet and TCP in packet:
            tcp_data = packet.payload
            if is_tls_handshake(tcp_data) and is_server_hello(tcp_data):
                src_ip = '.'.join(map(str, packet[IP].src))
                dst_ip = '.'.join(map(str, packet[IP].dst))
                servers.add(dst_ip)

    return servers
@app.route('/')
def pcap_cek():
    return render_template('pcap.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'pcap_file' not in request.files:
        return 'No file part'
    file = request.files['pcap_file']
    if file.filename == '':
        return 'No selected file'
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        global packets, dns_ips, mac_addresses, arp_table
        packets = rdpcap(file_path)
        dns_ips = extract_dns_ips(packets)
        mac_addresses = find_mac_without_ip(packets)
        arp_table = extract_arp_table(packets)
        return redirect(url_for('show_arp_network'))
    
def count_ports(packets):
    port_counts = {}

    for packet in packets:
        if TCP in packet:
            port = packet[TCP].sport
            if port in port_counts:
                port_counts[port] += 1
            else:
                port_counts[port] = 1

            port = packet[TCP].dport
            if port in port_counts:
                port_counts[port] += 1
            else:
                port_counts[port] = 1

        elif UDP in packet:
            port = packet[UDP].sport
            if port in port_counts:
                port_counts[port] += 1
            else:
                port_counts[port] = 1

            port = packet[UDP].dport
            if port in port_counts:
                port_counts[port] += 1
            else:
                port_counts[port] = 1

    return port_counts

def plot_ports(port_counts):
    # Portları ve sayıları al
    ports = sorted(port_counts.keys())
    counts = [port_counts[port] for port in ports]

    # Grafik boyutunu ayarla
    plt.figure(figsize=(12, 6))  
    
    # Barları oluştur
    bars = plt.bar(ports, counts, color='skyblue', edgecolor='black', width=0.8)
    
    # Ekseni etiketle
    plt.xlabel('Port Numaraları')
    plt.ylabel('Sayı')
    plt.title('Kullanılan Portların Dağılımı')
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Bar etiketlerini ekle (yan çevrilmiş)
    for bar, count in zip(bars, counts):
        plt.text(bar.get_x() + bar.get_width()/2, 
                 bar.get_height(), 
                 count,
                 ha='center', va='center', fontsize=8, rotation=90)

    # X eksenindeki port etiketlerinin sayısını sınırlamak için adım belirle
    max_labels = 20
    step = max(1, len(ports) // max_labels)
    plt.xticks(ports[::step], rotation=45, ha='right', fontsize=8)
    
    # Grafik alanını sıkıştır
    plt.tight_layout()

    # Grafiği kaydet
    if not os.path.exists('static'):
        os.makedirs('static')
    plt.savefig('static/port_counts.png')
    plt.close()

@app.route('/index')
def show_arp_network():
    global packets, dns_ips, mac_addresses, arp_table
    draw_arp_network(arp_table, packets, mac_addresses, dns_ips)
    return redirect('static/index.html')

@app.route('/arp')
def show_arp_table():
    global packets, dns_ips, mac_addresses, arp_table
    protocol_graph_path = protokoller(packets)
    ip_domain_pairs = extract_ips_and_domains(packets)
    pack =plot_packet_count_by_time(packets)
    son=plot_ip_connections(packets)
    flag_counts = count_tcp_flags(packets)
    tcpflag =plot_tcp_flags(flag_counts)
    servers = find_servers(packets)
    baglanti =find_syn_ack_pairs(packets)

    return render_template('tables.html', arp_table=arp_table, protocol_graph=protocol_graph_path, ip_domain_pairs=ip_domain_pairs,pack=pack,son=son,tcpflag=tcpflag, servers=servers,baglanti=baglanti)
   
@app.route('/protocol_graph')
def show_protocol_graph():
    return send_file('static/protocol_distribution.png', mimetype='image/png')

@app.route('/data_transfer_graph')
def show_data_transfer_graph():
    return send_file('static/analys.png', mimetype='image/png')

@app.route('/connections_graph')
def show_connections_graph():
    return send_file('static/ip_connections.png', mimetype='image/png')

@app.route('/flags_graph')
def show_flags_graph():
    return send_file('static/tcp_flags.png', mimetype='image/png')

@app.route('/ports')
def show_ports():
    # Portları say
    port_counts = count_ports(packets)
    
    # Port grafiğini oluştur
    plot_ports(port_counts)

    return send_file('static/port_counts.png', mimetype='image/png')

if __name__ == '__main__':
     app.run(debug=True)

