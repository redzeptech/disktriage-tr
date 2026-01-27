# DiskTriage TR

DiskTriage TR, adli bilişim ön inceleme (forensic triage) amaçlı geliştirilmiş basit bir analiz aracıdır.

Bu araç, bir klasör, dosya veya disk imajı üzerinden:
- Bütünlük doğrulama için hash üretir
- Dosya envanteri çıkarır
- Zaman bilgilerine dayalı basit analiz yapar
- Özet rapor üretir (TXT ve JSON)

Amaç, teknik ön değerlendirme yapabilmeyi sağlamaktır. Bu araç adli incelemenin, uzman analizinin veya hukuki değerlendirmenin yerini tutmaz.

## Kullanım

Klasör analizi:

python disktriage.py "D:\DELIL_EXPORT"

Disk imajı hash alma:

python disktriage.py "D:\images\disk01.dd"

Çıktı klasörü belirtmek:

python disktriage.py "D:\DELIL_EXPORT" --out "D:\raporlar\case_001"

## Çıktılar

Araç çalıştığında:
- report.txt → İnsan okunabilir özet
- report.json → Yapısal veri çıktısı

## Not

Bu yazılım eğitim ve farkındalık amaçlıdır. Gerçek adli süreçlerde uygun usuller ve araçlar kullanılmalıdır.
