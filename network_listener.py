import pyshark
from collections import defaultdict
import time
import numpy as np
import pandas as pd
import joblib

# Modeli yükle
rf_model = joblib.load('ddos_model.pkl')

# 5-tuple'ı temsil eden fonksiyon
def packet_to_flow_key(pkt):
    try:
        # IP paketi olduğundan emin ol
        if 'IP' in pkt:
            print(f"Processing packet: {pkt}")  # Paketin tüm bilgilerini yazdır
            return (
                pkt.ip.src, pkt.ip.dst, 
                pkt[pkt.transport_layer].srcport, 
                pkt[pkt.transport_layer].dstport, 
                pkt.transport_layer
            )
    except AttributeError as e:
        print(f"Error extracting flow key: {e}")
    return None  # Eğer IP paketi değilse, None döndür

# Feature çıkarma fonksiyonu
def extract_flow_features(flow):
    """
    Flow'dan özellik çıkarma fonksiyonu.
    Bu fonksiyon, her akış için özellikleri hesaplar.
    """
    try:
        timestamps = [pkt['timestamp'] for pkt in flow]
        lengths = [int(pkt.length) for pkt in flow if hasattr(pkt, 'length')]  # length özelliği kontrolü
        directions = [pkt['direction'] for pkt in flow]
        
        if len(lengths) == 0:  # Eğer length verisi yoksa, özellik çıkarma işlemini geç
            print("No length data found in flow.")
            return {}

        flow_duration = max(timestamps) - min(timestamps)  # Flow süresi
        total_fwd_pkts = sum([1 for direction in directions if direction == 'fwd'])
        total_bwd_pkts = sum([1 for direction in directions if direction == 'bwd'])
        total_len_fwd_pkts = sum([length for idx, direction in enumerate(directions) if direction == 'fwd'])
        total_len_bwd_pkts = sum([length for idx, direction in enumerate(directions) if direction == 'bwd'])
        fwd_pkt_len_max = max([length for idx, direction in enumerate(directions) if direction == 'fwd'], default=0)
        bwd_pkt_len_max = max([length for idx, direction in enumerate(directions) if direction == 'bwd'], default=0)

        # Diğer tüm özellikleri hesapla
        features = {
            'Flow Duration': flow_duration,
            'Tot Fwd Pkts': total_fwd_pkts,
            'Tot Bwd Pkts': total_bwd_pkts,
            'TotLen Fwd Pkts': total_len_fwd_pkts,
            'TotLen Bwd Pkts': total_len_bwd_pkts,
            'Fwd Pkt Len Max': fwd_pkt_len_max,
            'Bwd Pkt Len Max': bwd_pkt_len_max
        }
        
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return {}

# DDoS tahmini yapma fonksiyonu
def predict_ddos(features):
    try:
        # Özellikleri pandas dataframe'e çevir
        features_df = pd.DataFrame([features])
        
        # Modeli kullanarak tahmin yap
        prediction = rf_model.predict(features_df)
        
        # Tahmin sonuclarını ekrana yazdır
        if prediction == 1:  # Eğer DDoS olarak sınıflandırılmışsa
            print("DDoS attack detected!")
        else:
            print("Normal traffic.")
    except Exception as e:
        print(f"Error making prediction: {e}")

# Active Flow yapısını tutan dictionary
active_flows = defaultdict(list)
FLOW_TIMEOUT = 10  # saniye

# Wireshark üzerinden paketleri dinleme
interface_name = r'\Device\NPF_{9C8239F9-0C47-4838-B3F1-051D76CCEDE8}'  # WiFi adapter'ı buraya yazın

# Capture başlat
capture = pyshark.LiveCapture(interface=interface_name)
print("Listening on:", interface_name)

try:
    for packet in capture.sniff_continuously():
        try:
            # Eğer IP paketiyse
            if 'IP' in packet:
                flow_key = packet_to_flow_key(packet)
                if flow_key is None:  # Eğer geçerli bir flow anahtarı yoksa, devam et
                    continue
                
                timestamp = float(packet.sniff_timestamp)
                
                # Paket yönü belirleme (fwd veya bwd)
                if packet.ip.src == packet.ip.dst:
                    direction = 'bwd'  # Yerel ağdan dışarı giden paket
                else:
                    direction = 'fwd'  # Dışarıdan gelen paket
                
                # Flow'a paket ekle
                active_flows[flow_key].append({
                    'timestamp': timestamp,
                    'length': int(packet.length) if hasattr(packet, 'length') else 0,  # length kontrolü
                    'direction': direction
                })
                
                # Timeout kontrolü
                for flow_key in list(active_flows):
                    flow = active_flows[flow_key]
                    # Eğer 10 saniyedir bir paket yoksa, bu flow'u bitir
                    if timestamp - flow[-1]['timestamp'] > FLOW_TIMEOUT:
                        print(f"Flow expired: {flow_key}")  # Akış sona erdiğinde yazdır
                        
                        # Flow özelliklerini çıkar
                        features = extract_flow_features(flow)
                        if features:
                            print(f"Extracted features: {features}")  # Özellikleri yazdır

                            # Özelliklerin doğru formatta olduğunu kontrol et
                            print(f"Features DataFrame: {pd.DataFrame([features])}")  # DataFrame'i yazdır

                            # DDoS tahmini yap
                            predict_ddos(features)
                        
                        # Akışı temizle
                        del active_flows[flow_key]
        except Exception as e:
            print(f"Error processing packet: {e}")

except KeyboardInterrupt:
    print("Capture stopped.")
