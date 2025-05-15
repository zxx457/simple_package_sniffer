from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import datetime
from utils import check_environment
class PacketSniffer:
    def __init__(self):
        self.connections = defaultdict(dict)
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int)
        }

    def packet_handler(self, packet):
        if IP in packet:
            self.stats['total_packets'] += 1
            src = f"{packet[IP].src}:{packet.sport}"
            dst = f"{packet[IP].dst}:{packet.dport}"
            
            if TCP in packet:
                self._process_tcp(packet, src, dst)
                print(f"[TCP] {src} -> {dst}")
            elif UDP in packet:
                self._process_udp(packet, src, dst)
                print(f"[UDP] {src} -> {dst}")

    def _process_tcp(self, packet, src, dst):
        self.stats['protocols']['tcp'] += 1
        self.stats['ports'][packet.dport] += 1
        
        if packet[TCP].flags == 'S':
            self.connections[src][dst] = {
                'start': datetime.datetime.now(),
                'status': 'SYN_SENT'
            }

    def _process_udp(self, packet, src, dst):
        self.stats['protocols']['udp'] += 1
        self.stats['ports'][packet.dport] += 1

if __name__ == "__main__":
    check_environment()

    sniffer = PacketSniffer()
    try:
        sniff(prn=sniffer.packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n--- Packet Sniffer Summary ---")
        print("Total packets:", sniffer.stats['total_packets'])
        print("Protocols:", dict(sniffer.stats['protocols']))
        print("Ports:", dict(sniffer.stats['ports']))
        print("Connections:", dict(sniffer.connections))