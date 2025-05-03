import pyshark
import time
from collections import defaultdict
import numpy as np
import json
from typing import Optional, Tuple, Dict, Any

# config.json dosyasını oku
with open('config.json', 'r') as f:
    config = json.load(f)

class PacketFlow:
    def __init__(self, src_ip: str, dst_ip: str, src_port: str, dst_port: str, protocol: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = []
        self.timestamps = []
        self.last_packet_time = time.time()  # Son paketin zamanı

    def add_packet(self, packet) -> None:
        self.packets.append(packet)
        try:
            self.timestamps.append(float(packet.frame_info.time_epoch))
        except AttributeError:
            self.timestamps.append(time.time())
        self.last_packet_time = time.time()  # Yeni paket geldiğinde zaman güncellenir
            
    def is_expired(self, timeout: float = 20.0) -> bool:
        """Flow'un zaman aşımına uğrayıp uğramadığını kontrol et"""
        if not self.timestamps:
            return True
        return (time.time() - self.last_packet_time) > timeout
    
    def _calculate_header_length(self, pkt) -> int:
        hdr_len = 0
        if hasattr(pkt, 'ip'):
            hdr_len += int(getattr(pkt.ip, 'hdr_len', 20))
            
        if 'TCP' in pkt:
            hdr_len += int(getattr(pkt.tcp, 'hdr_len', 20))
        elif 'UDP' in pkt:
            hdr_len += 8
        return hdr_len
    
    def _safe_stats(self, data) -> Dict[str, Any]:
        """NumPy dizileri için güvenli istatistik hesaplama"""
        if len(data) == 0:
            return {
                'tot': 0,
                'mean': 0,
                'std': 0,
                'max': 0,
                'min': 0
            }
        return {
            'tot': np.sum(data),
            'mean': float(np.mean(data)),
            'std': float(np.std(data)),
            'max': float(np.max(data)),
            'min': float(np.min(data))
        }
    
    def calculate_features(self) -> Dict[str, Any]:
        if len(self.packets) < 1:
            return {}

        try:
            packet_lengths = np.array([len(pkt) for pkt in self.packets])
            flow_duration = self.timestamps[-1] - self.timestamps[0] if len(self.timestamps) > 1 else 0

            fwd_pkts = [pkt for pkt in self.packets 
                       if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'src') and pkt.ip.src == self.src_ip]
            bwd_pkts = [pkt for pkt in self.packets 
                       if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'src') and pkt.ip.src == self.dst_ip]

            fwd_lengths = np.array([len(pkt) for pkt in fwd_pkts])
            bwd_lengths = np.array([len(pkt) for pkt in bwd_pkts])
            
            fwd_hdr_len = sum(self._calculate_header_length(pkt) for pkt in fwd_pkts)
            bwd_hdr_len = sum(self._calculate_header_length(pkt) for pkt in bwd_pkts)

            # Zaman aralıkları (IAT) hesaplama
            flow_iat = np.diff(self.timestamps) if len(self.timestamps) > 1 else np.array([])
            fwd_iat = np.diff([float(pkt.frame_info.time_epoch) for pkt in fwd_pkts]) if len(fwd_pkts) > 1 else np.array([])
            bwd_iat = np.diff([float(pkt.frame_info.time_epoch) for pkt in bwd_pkts]) if len(bwd_pkts) > 1 else np.array([])

            # Güvenli istatistik hesaplamaları
            flow_iat_stats = self._safe_stats(flow_iat)
            fwd_iat_stats = self._safe_stats(fwd_iat)
            bwd_iat_stats = self._safe_stats(bwd_iat)

            # Idle zaman hesaplamaları
            idle_threshold = np.percentile(flow_iat, 95) if len(flow_iat) > 0 else 0
            idle_times = flow_iat[flow_iat > idle_threshold] if idle_threshold > 0 else np.array([0])
            idle_stats = self._safe_stats(idle_times)

            features = {
                'Flow Duration': flow_duration,
                'Tot Fwd Pkts': len(fwd_pkts),
                'Tot Bwd Pkts': len(bwd_pkts),
                'TotLen Fwd Pkts': int(np.sum(fwd_lengths)),
                'TotLen Bwd Pkts': int(np.sum(bwd_lengths)),
                'Fwd Pkt Len Max': int(np.max(fwd_lengths)) if len(fwd_lengths) > 0 else 0,
                'Fwd Pkt Len Min': int(np.min(fwd_lengths)) if len(fwd_lengths) > 0 else 0,
                'Fwd Pkt Len Mean': float(np.mean(fwd_lengths)) if len(fwd_lengths) > 0 else 0,
                'Fwd Pkt Len Std': float(np.std(fwd_lengths)) if len(fwd_lengths) > 0 else 0,
                'Bwd Pkt Len Max': int(np.max(bwd_lengths)) if len(bwd_lengths) > 0 else 0,
                'Bwd Pkt Len Min': int(np.min(bwd_lengths)) if len(bwd_lengths) > 0 else 0,
                'Bwd Pkt Len Mean': float(np.mean(bwd_lengths)) if len(bwd_lengths) > 0 else 0,
                'Bwd Pkt Len Std': float(np.std(bwd_lengths)) if len(bwd_lengths) > 0 else 0,
                'Flow Byts/s': (np.sum(fwd_lengths) + np.sum(bwd_lengths)) / flow_duration if flow_duration > 0 else 0,
                'Flow Pkts/s': len(self.packets) / flow_duration if flow_duration > 0 else 0,
                'Flow IAT Mean': flow_iat_stats['mean'],
                'Flow IAT Std': flow_iat_stats['std'],
                'Flow IAT Max': flow_iat_stats['max'],
                'Flow IAT Min': flow_iat_stats['min'],
                'Fwd IAT Tot': fwd_iat_stats['tot'],
                'Fwd IAT Mean': fwd_iat_stats['mean'],
                'Fwd IAT Std': fwd_iat_stats['std'],
                'Fwd IAT Max': fwd_iat_stats['max'],
                'Fwd IAT Min': fwd_iat_stats['min'],
                'Bwd IAT Tot': bwd_iat_stats['tot'],
                'Bwd IAT Mean': bwd_iat_stats['mean'],
                'Bwd IAT Std': bwd_iat_stats['std'],
                'Bwd IAT Max': bwd_iat_stats['max'],
                'Bwd IAT Min': bwd_iat_stats['min'],
                'Fwd Header Len': fwd_hdr_len,
                'Bwd Header Len': bwd_hdr_len,
                'Fwd Pkts/s': len(fwd_pkts) / flow_duration if flow_duration > 0 else 0,
                'Bwd Pkts/s': len(bwd_pkts) / flow_duration if flow_duration > 0 else 0,
                'Pkt Len Min': int(np.min(packet_lengths)) if len(packet_lengths) > 0 else 0,
                'Pkt Len Max': int(np.max(packet_lengths)) if len(packet_lengths) > 0 else 0,
                'Pkt Len Mean': float(np.mean(packet_lengths)),
                'Pkt Len Std': float(np.std(packet_lengths)),
                'Pkt Len Var': float(np.var(packet_lengths)),
                'Pkt Size Avg': float(np.mean(packet_lengths)),
                'Active Mean': flow_iat_stats['mean'],
                'Active Std': flow_iat_stats['std'],
                'Active Max': flow_iat_stats['max'],
                'Active Min': flow_iat_stats['min'],
                'Idle Mean': idle_stats['mean'],
                'Idle Std': idle_stats['std'],
                'Idle Max': idle_stats['max'],
                'Idle Min': idle_stats['min'],
            }
            return features

        except Exception as e:
            print(f"Error calculating features: {str(e)}")
            return {}

def create_flow_key(packet) -> Optional[Tuple]:
    if 'IP' not in packet:
        return None

    src_ip, dst_ip = packet.ip.src, packet.ip.dst
    src_port, dst_port = '0', '0'

    if 'TCP' in packet:
        src_port, dst_port = packet.tcp.srcport, packet.tcp.dstport
        protocol = 'TCP'
    elif 'UDP' in packet:
        src_port, dst_port = packet.udp.srcport, packet.udp.dstport
        protocol = 'UDP'
    else:
        return None  # Sadece TCP ve UDP'yi dahil et

    try:
        if (src_ip, int(src_port)) <= (dst_ip, int(dst_port)):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        return (dst_ip, src_ip, dst_port, src_port, protocol)
    except ValueError:
        return None


def main():
    flows = defaultdict(lambda: None)
    interface = config.get('interface', 'eth0')
    display_filter = config.get('display_filter', 'ip and (tcp or udp or icmp)')

    print(f"Listening on {interface} with filter: {display_filter}")

    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter=display_filter,
        only_summaries=False
    )

    try:
        while True:
            # Eski flow'ları temizle
            for flow_key in list(flows.keys()):
                if flows[flow_key] and flows[flow_key].is_expired():
                    # Flow bittiğinde, özellikleri yazdır
                    features = flows[flow_key].calculate_features()
                    if features:
                        print(f"Flow {flow_key}: {features}")
                    del flows[flow_key]

            # Yeni paketi işle
            packet = next(cap.sniff_continuously())
            flow_key = create_flow_key(packet)
            if flow_key is None:
                continue

            if flows[flow_key] is None:
                src_ip, dst_ip, src_port, dst_port, protocol = flow_key
                flows[flow_key] = PacketFlow(src_ip, dst_ip, src_port, dst_port, protocol)

            flows[flow_key].add_packet(packet)

    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print(f"Runtime error: {str(e)}")

if __name__ == "__main__":
    main()
