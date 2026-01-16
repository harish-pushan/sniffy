from scapy.all import sniff 
from scapy.all import PcapWriter 
import os 

class Sniffer:
    def __init__(self,iface):
        self.iface = iface
    
    
    def tcp_process_packet(self,pkt):

        pkts_writer = PcapWriter('tcp_packet.pcap', append=True, sync=True)
        """Callback function to write each packet to the file."""
        try:
            pkts_writer.write(pkt)
        except Exception as e:
            print(f"Error writing packet: {e}")


    def udp_process_packet(self,pkt):

        pkts_writer = PcapWriter('udp_packet.pcap', append=True, sync=True)
        """Callback function to write each packet to the file."""
        try:
            pkts_writer.write(pkt)
        except Exception as e:
            print(f"Error writing packet: {e}")
    def arp_process_packet(self,pkt):

        pkts_writer = PcapWriter('arp_packet.pcap', append=True, sync=True)
        """Callback function to write each packet to the file."""
        try:
            pkts_writer.write(pkt)
        except Exception as e:
            print(f"Error writing packet: {e}")
    def icmp_process_packet(self,pkt):

        pkts_writer = PcapWriter('icmp_packet.pcap', append=True, sync=True)
        """Callback function to write each packet to the file."""
        try:
            pkts_writer.write(pkt)
        except Exception as e:
            print(f"Error writing packet: {e}")

    # This function creates the object and we start the sniffing with something else.....
    def create_sniffer_obj(self):
        # Start sniffing
        # store=0 prevents packets from being stored in memory, 
        # which is essential for long-running captures
        sniff(iface = self.iface,prn = self.tcp_process_packet, filter= "tcp",store = 0 )
        sniff(iface = self.iface,prn = self.udp_process_packet,filter= "udp",store = 0)
        sniff(iface = self.iface,prn = self.arp_process_packet, filter= "arp", store = 0)
        sniff(iface = self.iface,prn = self.icmp_process_packet,filter= "icmp", store = 0 )



