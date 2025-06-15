# InSDN DDoS Detection with Random Forest

Bu proje, InSDN veri seti kullanılarak DDoS saldırılarını tespit etmek amacıyla bir makine öğrenimi modeli geliştirmektedir. Model, en etkili 48 özelliği otomatik olarak seçmekte ve Random Forest algoritması ile eğitilmektedir. Proje kapsamında veri setinin analizi, modelin doğruluk değerlendirmesi ve önemli özelliklerin görselleştirilmesi yapılmaktadır.

## Özellikler

- InSDN veri setinin birleştirilmesi ve ön işlenmesi
- En önemli 48 özelliğin otomatik seçimi
- Random Forest ile DDoS tespit modeli eğitimi
- Modelin doğruluk, precision, recall ve f1-score metrikleriyle değerlendirilmesi
- Özellik önem sıralaması ve görselleştirilmesi
- Eğitilen modelin kaydedilmesi ve yeni verilerle tahmin yapılabilmesi

## Kullanılan Teknolojiler

- Python (pandas, numpy, scikit-learn, matplotlib, seaborn)
- InSDN_DatasetCSV (Normal_data.csv, OVS.csv, metasploitable-2.csv)

## Kurulum

1. Gerekli Python kütüphanelerini yükleyin:
   ```
   pip install pandas numpy scikit-learn matplotlib seaborn joblib
   ```
2. `InSDN_DatasetCSV` klasörünü ve veri dosyalarını proje dizinine ekleyin.

## Kullanım

- `main.ipynb` dosyasını açarak adım adım çalıştırabilirsiniz.
- Model eğitimi, değerlendirme ve tahmin örnekleri notebook içinde yer almaktadır.

## Katkı

Katkıda bulunmak isterseniz lütfen bir issue açın veya pull request gönderin.

---

Eklemek istediğiniz özel bir açıklama, görsel veya kullanım örneği varsa belirtmekten çekinmeyin!
