
from scapy.all import sniff, IP, TCP, UDP
from scapy.all import get_if_addr


def process_data(data):
    print(data)


def func_invoker(packet):
    get_all_ports_and_IP(packet)
    get_packet_sizes(packet)


def get_all_ports_and_IP(packet):
    if not packet.haslayer(IP):
        return

    data = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "proto": "IP",
        "sport": None,
        "dport": None
    }

    if packet.haslayer(TCP):
        data["proto"] = "TCP"
        data["sport"] = packet[TCP].sport
        data["dport"] = packet[TCP].dport

    elif packet.haslayer(UDP):
        data["proto"] = "UDP"
        data["sport"] = packet[UDP].sport
        data["dport"] = packet[UDP].dport

    process_data(data)


def get_packet_sizes(packet):
    my_ip = get_if_addr(interface)
    if not packet.haslayer(IP):
        return

    if packet[IP].src == my_ip:
        data = {
            "in_bytes": len(packet),
            "out_bytes": None
        }

    if packet[IP].dst == my_ip:
        data = {
            "in_bytes": None,
            "out_bytes": len(packet)
        }
    process_data(data)


interface = "wlan0"






sniff(
    iface=interface,
    prn=func_invoker,
    store=False
)
