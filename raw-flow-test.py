import pyshark
import time

# Ayarlar
IDLE_TIMEOUT = 30  # saniye
active_flows = {}

# Sadece TCP ve UDP paketlerini işliyoruz
VALID_PROTOCOLS = ['TCP', 'UDP']

def get_flow_key(packet):
    try:
        proto = packet.transport_layer
        if proto not in VALID_PROTOCOLS:
            return None
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet[proto].srcport
        dst_port = packet[proto].dstport
        return (src_ip, src_port, dst_ip, dst_port, proto)
    except AttributeError:
        return None  # IP veya TCP/UDP olmayan paketler

def update_flows(packet):
    key = get_flow_key(packet)
    if key is None:
        return

    now = time.time()
    if key not in active_flows:
        active_flows[key] = {
            'start_time': now,
            'last_packet_time': now,
            'packet_count': 1,
            'byte_count': int(packet.length)
        }
    else:
        flow = active_flows[key]
        flow['last_packet_time'] = now
        flow['packet_count'] += 1
        flow['byte_count'] += int(packet.length)

def flush_old_flows():
    now = time.time()
    to_delete = []
    for key, flow in active_flows.items():
        if now - flow['last_packet_time'] > IDLE_TIMEOUT:
            print(f"[Flow Ended] {key} -> Packets: {flow['packet_count']}, Bytes: {flow['byte_count']}")
            to_delete.append(key)
    for key in to_delete:
        del active_flows[key]

# Canlı paket dinleme
cap = pyshark.LiveCapture(interface='eth0')  # Arayüz adını uygun şekilde değiştir

for packet in cap.sniff_continuously():
    update_flows(packet)
    flush_old_flows()
