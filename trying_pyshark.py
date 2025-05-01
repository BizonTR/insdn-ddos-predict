import pyshark
import time
from collections import defaultdict
import numpy as np
import json

# config.json dosyasını oku
with open('config.json', 'r') as f:
    config = json.load(f)

class PacketFlow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = []       # Liste: Scapy Packet nesneleri
        self.timestamps = []    # Liste: time.time() zamanları

    def add_packet(self, packet):
        self.packets.append(packet)
        self.timestamps.append(time.time())

    def calculate_features(self):
        if not self.packets:
            return {}

        packet_lengths = [len(pkt) for pkt in self.packets]
        flow_duration = self.timestamps[-1] - self.timestamps[0] if len(self.timestamps) > 1 else 0

        fwd_pkts = [pkt for pkt in self.packets if hasattr(pkt, 'ip') and pkt.ip.src == self.src_ip]
        bwd_pkts = [pkt for pkt in self.packets if hasattr(pkt, 'ip') and pkt.ip.src == self.dst_ip]


        # Forward packet lengths
        fwd_lengths = [len(pkt) for pkt in fwd_pkts]
        bwd_lengths = [len(pkt) for pkt in bwd_pkts]

        # Dummy header length extraction (Scapy varsayımı)
        fwd_hdr_len = sum([int(pkt.ip.hdr_len) for pkt in fwd_pkts if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'hdr_len')])
        bwd_hdr_len = sum([int(pkt.ip.hdr_len) for pkt in bwd_pkts if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'hdr_len')])

        # Inter-arrival times
        flow_iat = np.diff(self.timestamps) if len(self.timestamps) > 1 else []
        fwd_iat = np.diff([float(pkt.frame_info.time_epoch) for pkt in fwd_pkts]) if len(fwd_pkts) > 1 else []
        bwd_iat = np.diff([float(pkt.frame_info.time_epoch) for pkt in bwd_pkts]) if len(bwd_pkts) > 1 else []

        # Idle times (naive: zaman aralıklarının 95. percentil üstü)
        idle_threshold = np.percentile(flow_iat, 95) if len(flow_iat) > 1 else 0
        idle_times = [iat for iat in flow_iat if iat > idle_threshold] if idle_threshold > 0 else [0]

        return {
            'Flow Duration': flow_duration,
            'Tot Fwd Pkts': len(fwd_pkts),
            'Tot Bwd Pkts': len(bwd_pkts),
            'TotLen Fwd Pkts': sum(fwd_lengths),
            'TotLen Bwd Pkts': sum(bwd_lengths),
            'Fwd Pkt Len Max': max(fwd_lengths, default=0),
            'Fwd Pkt Len Min': min(fwd_lengths, default=0),
            'Fwd Pkt Len Mean': np.mean(fwd_lengths) if fwd_lengths else 0,
            'Fwd Pkt Len Std': np.std(fwd_lengths) if fwd_lengths else 0,
            'Bwd Pkt Len Max': max(bwd_lengths, default=0),
            'Bwd Pkt Len Min': min(bwd_lengths, default=0),
            'Bwd Pkt Len Mean': np.mean(bwd_lengths) if bwd_lengths else 0,
            'Bwd Pkt Len Std': np.std(bwd_lengths) if bwd_lengths else 0,
            'Flow Byts/s': (sum(fwd_lengths) + sum(bwd_lengths)) / flow_duration if flow_duration > 0 else 0,
            'Flow Pkts/s': len(self.packets) / flow_duration if flow_duration > 0 else 0,
            'Flow IAT Mean': np.mean(flow_iat) if len(flow_iat) > 0 else 0,
            'Flow IAT Std': np.std(flow_iat) if len(flow_iat) > 0 else 0,
            'Flow IAT Max': np.max(flow_iat) if len(flow_iat) > 0 else 0,
            'Flow IAT Min': np.min(flow_iat) if len(flow_iat) > 0 else 0,
            'Fwd IAT Tot': sum(fwd_iat),
            'Fwd IAT Mean': np.mean(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Fwd IAT Std': np.std(fwd_iat) if len(fwd_iat) > 0 else 0,
            'Fwd IAT Max': max(fwd_iat, default=0) if len(fwd_iat) > 0 else 0,
            'Fwd IAT Min': min(fwd_iat, default=0) if len(fwd_iat) > 0 else 0,
            'Bwd IAT Tot': sum(bwd_iat),
            'Bwd IAT Mean': np.mean(bwd_iat) if bwd_iat else 0,
            'Bwd IAT Std': np.std(bwd_iat) if bwd_iat else 0,
            'Bwd IAT Max': max(bwd_iat, default=0),
            'Bwd IAT Min': min(bwd_iat, default=0),
            'Fwd Header Len': fwd_hdr_len,
            'Bwd Header Len': bwd_hdr_len,
            'Fwd Pkts/s': len(fwd_pkts) / flow_duration if flow_duration > 0 else 0,
            'Bwd Pkts/s': len(bwd_pkts) / flow_duration if flow_duration > 0 else 0,
            'Pkt Len Min': min(packet_lengths, default=0),
            'Pkt Len Max': max(packet_lengths, default=0),
            'Pkt Len Mean': np.mean(packet_lengths),
            'Pkt Len Std': np.std(packet_lengths),
            'Pkt Len Var': np.var(packet_lengths),
            'Pkt Size Avg': np.mean(packet_lengths),
            'Active Mean': np.mean(flow_iat) if len(flow_iat) > 0 else 0,
            'Active Std': np.std(flow_iat) if len(flow_iat) > 0 else 0,
            'Active Max': max(flow_iat, default=0) if len(flow_iat) > 0 else 0,
            'Active Min': min(flow_iat, default=0) if len(flow_iat) > 0 else 0,
            'Idle Mean': np.mean(idle_times),
            'Idle Std': np.std(idle_times),
            'Idle Max': max(idle_times),
            'Idle Min': min(idle_times),
        }


# Akışları saklayacak bir sözlük
flows = defaultdict(PacketFlow)

# Interface adını belirleyin (örneğin 'eth0', 'wlan0' veya 'en0', sisteminize göre)
interface = config.get('interface', None)

# PyShark ile canlı paket yakalama
cap = pyshark.LiveCapture(interface=interface)
print("Listening on:", interface)

# Sonsuz döngü ile sürekli paket yakalama
try:
    for packet in cap.sniff_continuously():
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'None'

            # TCP/UDP portlarına yalnızca TCP ve UDP paketlerinde eriş
            if protocol in ['TCP', 'UDP']:
                try:
                    src_port = packet[protocol].srcport
                    dst_port = packet[protocol].dstport
                except AttributeError:
                    continue  # Eğer port bilgisi yoksa geç

                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

                if flow_key not in flows:
                    flows[flow_key] = PacketFlow(src_ip, dst_ip, src_port, dst_port, protocol)

                flows[flow_key].add_packet(packet)

                features = flows[flow_key].calculate_features()
                print(f"Flow ({src_ip}, {dst_ip}, {src_port}, {dst_port}, {protocol}): {features}")
except KeyboardInterrupt:
    print("\nCapture stopped.")
