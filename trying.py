from collections import defaultdict
import time

# Akış bilgilerini tutacak sınıf
class PacketFlow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = []
        self.start_time = None
        self.end_time = None
        self.total_data = 0
        self.packet_lengths = []

    def add_packet(self, packet):
        if self.start_time is None:
            self.start_time = packet.time
        self.end_time = packet.time
        self.total_data += len(packet.data)
        self.packet_lengths.append(len(packet.data))
        self.packets.append(packet)

    def get_flow_duration(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0

    def get_avg_packet_length(self):
        if self.packet_lengths:
            return sum(self.packet_lengths) / len(self.packet_lengths)
        return 0

    def get_max_packet_length(self):
        if self.packet_lengths:
            return max(self.packet_lengths)
        return 0

    def get_min_packet_length(self):
        if self.packet_lengths:
            return min(self.packet_lengths)
        return 0

    def __str__(self):
        return (f"Flow ({self.src_ip}, {self.dst_ip}, {self.src_port}, {self.dst_port}, {self.protocol}) "
                f"Duration: {self.get_flow_duration()}s, "
                f"Total Data: {self.total_data} bytes, "
                f"Avg Packet Length: {self.get_avg_packet_length()} bytes, "
                f"Max Packet Length: {self.get_max_packet_length()} bytes, "
                f"Min Packet Length: {self.get_min_packet_length()} bytes")

# Akışları takip etmek için bir dictionary oluşturuyoruz
flows = defaultdict(lambda: None)

# Paket sınıfı
class Packet:
    def __init__(self, time, data):
        self.time = time
        self.data = data

# Akış ekleme fonksiyonu
def add_flow(src_ip, dst_ip, src_port, dst_port, protocol, packet_data):
    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
    if flows[flow_key] is None:
        flows[flow_key] = PacketFlow(src_ip, dst_ip, src_port, dst_port, protocol)
    packet = Packet(time.time(), packet_data)
    flows[flow_key].add_packet(packet)

# Örnek veri: Paketleri ekliyoruz
add_flow('192.168.1.178', '35.186.224.28', 61242, 443, 'TCP', b'exampledata1')
add_flow('192.168.1.178', '35.186.224.28', 61242, 443, 'TCP', b'exampledata2')
add_flow('192.168.1.178', '35.186.224.28', 61242, 443, 'TCP', b'exampledata3')

# Akışları yazdırmak
for flow_key, flow in flows.items():
    print(flow)
