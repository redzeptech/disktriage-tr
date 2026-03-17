# DiskTriage TR

**Adli bilişim ön inceleme (forensic triage)** için geliştirilmiş, modüler ve genişletilebilir analiz aracı. Disk imajları, klasörler ve Windows artifact'ları üzerinde hızlı triyaj, hash doğrulama ve raporlama sunar.

---

## Proje Yapısı

```
disktriage-tr-1.0.0/
├── disktriage/              # Ana paket
│   ├── __init__.py
│   ├── cli.py               # Komut satırı orkestrasyonu
│   └── modules/             # Analiz, raporlama, maskeleme modülleri
│       ├── io.py, processing.py, models.py, utils.py
│       ├── prefetch.py, browser_history.py, evtx.py, userassist.py
│       ├── persistence.py, virustotal.py, timeline.py
│       ├── anonymizer.py    # Maskeleme
│       ├── reporting.py, html_report.py, report_generator.py
│       └── logging_utils.py, console_output.py
├── tests/                   # Test senaryoları
├── main.py                  # Giriş noktası
├── dashboard.py             # Streamlit dashboard
├── build.py                 # PyInstaller build
├── pyproject.toml           # Paket kurulumu
└── requirements.txt
```

---

## Teknolojiler

| Teknoloji | Kullanım |
|-----------|----------|
| **Python 3.9+** | Ana dil |
| **Plotly** | İnteraktif grafikler (Timeline, Pie Chart) |
| **Pandas** | Büyük envanterlerde hızlı veri işleme |
| **Streamlit** | Web tabanlı dashboard |
| **Chart.js** | HTML rapor grafikleri |
| **DataTables.net** | Filtrelenebilir tablolar |
| **Rich** | Terminal çıktısı formatlama |
| **PyInstaller** | Tek dosya (.exe) dağıtım |

---

## Özellikler

### Artifact Toplama
- **Dosya Sistemi**: Envanter taraması, MACE zamanları, en büyük / son değişen dosyalar, uzantı dağılımı
- **Prefetch**: Son çalıştırılan programlar (.pf)
- **Tarayıcı Geçmişi**: Chrome, Edge, Firefox (History / places.sqlite)
- **Windows Event Log**: System (Critical/Error), Security (logon 4624/4625)
- **UserAssist**: HKCU son çalıştırma izleri
- **Persistence**: Run keys, Startup klasörü, servisler, zamanlanmış görevler
- **Timeline**: Tüm artifact'ların kronolojik birleşimi

### Maskeleme (Anonymizer)
- Kişisel verilerin otomatik maskelemesi (varsayılan: açık)
- Kullanıcı dizin yolları (`C:\Users\<ad>\...` → `[HIDDEN]`)
- PC adı, IP adresleri, kullanıcı adları
- `--no-anonymize` ile kapatılabilir

### İnteraktif HTML Raporlama
- **report.html**: Chart.js grafikleri, tablolar, arama filtresi
- **report_[timestamp].html**: Plotly + DataTables, karanlık mod
- Zaman çizelgesi, dosya türü dağılımı, hata/uyarı özeti
- VirusTotal sonuçları (malicious/suspicious vurgulama)

---

## Kurulum

### Gereksinimler
- Python 3.9 veya üzeri
- Windows (Prefetch, UserAssist, EVTX modülleri için)

### Adımlar

```bash
# Depoyu klonlayın veya indirin
cd disktriage-tr-1.0.0

# Sanal ortam oluşturun (önerilir)
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate   # Linux/macOS

# Bağımlılıkları yükleyin
pip install -r requirements.txt
# veya paket olarak kurun:
pip install -e .

# Kurulumu doğrulayın
python main.py --help
# veya paket kurulumu sonrası:
disktriage --help
```

---

## Nasıl Çalışır? (How it Works)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DiskTriage TR — Akış Şeması                         │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐     ┌──────────────────────────────────────────────────────┐
  │   HEDEF      │     │                    VERİ TOPLAMA                        │
  │  (Klasör /   │────▶│  • Hash (SHA256/MD5)                                   │
  │   Dosya /    │     │  • Envanter (ThreadPoolExecutor, --workers)             │
  │   Disk imajı)│     │  • Prefetch, Browser History, EVTX, UserAssist         │
  └──────────────┘     │  • Persistence (Run keys, Services, Tasks)             │
                       └─────────────────────┬──────────────────────────────────┘
                                             │
                                             ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │                         İŞLEME & BİRLEŞTİRME                                 │
  │  • Özet (Pandas/Python fallback)  • Timeline (kronolojik sıralama)           │
  │  • Anonymizer (maskeleme)         • VirusTotal (opt-in, SHA256)              │
  └─────────────────────────────────────┬──────────────────────────────────────┘
                                         │
                                         ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │                              RAPOR ÜRETİMİ                                    │
  │  report.txt  │  report.json  │  reports/report.html  │  reports/report_*.html │
  │  reports/timeline.csv  │  reports/disktriage.log                             │
  └──────────────────────────────────────────────────────────────────────────────┘
```

**Akış özeti:**
1. Hedef (klasör/dosya) belirlenir.
2. Modüller paralel/ardışık veri toplar (hash, envanter, artifact'lar).
3. Veriler işlenir, özetlenir, isteğe bağlı maskeleme uygulanır.
4. TXT, JSON, HTML ve CSV raporları üretilir.

---

## Kullanım

### CLI (Komut Satırı)

```bash
# Temel klasör analizi
python main.py "D:\DELIL_EXPORT"

# Çıktı klasörü belirtme
python main.py "D:\DELIL_EXPORT" --out "D:\raporlar\case_001"

# Tam analiz (tüm modüller)
python main.py "D:\DELIL_EXPORT" --out "D:\raporlar" \
  --prefetch --browser-history --evtx --userassist --persistence --timeline \
  --workers 8 --log-level INFO
```

| Parametre | Açıklama |
|-----------|----------|
| `--prefetch` | Windows Prefetch analizi |
| `--browser-history` | Chrome/Edge/Firefox geçmişi |
| `--evtx` | Windows Event Log özeti |
| `--userassist` | UserAssist (HKCU) izleri |
| `--persistence` | Run keys, Startup, Services, Tasks |
| `--timeline` | Zaman tüneli (kronolojik) |
| `--virustotal` | VirusTotal kontrolü (`VT_API_KEY` gerekir) |
| `--workers N` | Paralel envanter sayısı (varsayılan: 8) |
| `--no-anonymize` | Maskeleme kapatma |

### Dashboard (Streamlit)

```bash
streamlit run dashboard.py
```

Tarayıcıda açılan arayüzden hedef seçip **"Tarama Başlat"** ile analiz yapılır. İlerleme çubuğu ve anlık log akışı gösterilir.

<!-- Ekran görüntüsü yer tutucusu -->
```
┌─────────────────────────────────────────────────────────┐
│  [Ekran görüntüsü: Streamlit Dashboard]                  │
│  • Sol panel: Hedef, çıktı, modül seçenekleri            │
│  • Ana alan: Tarama Başlat butonu, log akışı             │
└─────────────────────────────────────────────────────────┘
```

### Örnek Komutlar

```bash
# Disk imajı hash
python main.py "D:\images\disk01.dd"

# Offline EVTX
python main.py "D:\case" --evtx --evtx-path "D:\case\System.evtx" --evtx-days 30

# VirusTotal (VT_API_KEY ortam değişkeni gerekli)
set VT_API_KEY=your_key
python main.py "D:\DELIL_EXPORT" --persistence --virustotal --vt-max 25
```

<!-- Ekran görüntüsü yer tutucusu -->
```
┌─────────────────────────────────────────────────────────┐
│  [Ekran görüntüsü: Terminal çıktısı]                     │
│  python main.py "D:\DELIL_EXPORT" --prefetch             │
│  Run started. target=D:\DELIL_EXPORT ...                 │
│  Inventory done. scanned=15234 records=15234             │
│  Raporlar: D:\...\disktriage_out\reports\                │
└─────────────────────────────────────────────────────────┘
```

---

## Çıktılar

| Dosya | Açıklama |
|-------|----------|
| `report.txt` | İnsan okunabilir özet |
| `report.json` | Yapısal veri (SIEM entegrasyonu) |
| `reports/report.html` | Chart.js interaktif rapor |
| `reports/report_[timestamp].html` | Plotly + DataTables (karanlık mod) |
| `reports/report.json` | HTML ile birlikte JSON kopyası |
| `reports/timeline.csv` | Kronolojik olay listesi |
| `reports/disktriage.log` | Çalışma logları |

---

## Performans & Dayanıklılık

- **Threading**: `--workers 8` ile büyük dizinlerde hızlanma
- **Pandas**: 80k+ kayıtta otomatik hızlandırma
- **Log seviyesi**: `--log-level DEBUG|INFO|WARNING|ERROR`
- **Hata yönetimi**: Erişim reddi / dosya bulunamadı durumunda çökme yok, rapora uyarı yazılır

---

## Cursor ile İyileştirme Akışı

Projeyi Cursor'da açıp `Ctrl+L` ile chat panelini kullanarak:

- **Kod analizi**: `@Files` + "Zayıf noktaları analiz et"
- **Refactor**: "Modüler hale getir, DRY uygula"
- **Özellik**: "UserAssist / EVTX / Timeline modülü ekle"
- **Build**: "PyInstaller ile exe üret"

---

## Uyarı

Bu yazılım **eğitim ve farkındalık** amaçlıdır. Gerçek adli süreçlerde uzman analizi ve uygun usuller kullanılmalıdır.
