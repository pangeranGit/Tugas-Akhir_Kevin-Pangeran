Tugas Akhir — Pipeline Enrichment dan AI-Assisted Summarization untuk Deteksi Command and Control

Kevin Pangeran Enrico — NPM 2221101801  
Program Studi Rekayasa Keamanan Siber, Politeknik Siber dan Sandi Negara

Implementasi pipeline enrichment dan AI-assisted summarization dalam mendukung deteksi Command and Control (C2) berbasis Wazuh dan Suricata, menggunakan dataset EarlyCrowAPT (45 file PCAP).

## Arsitektur
Pipeline lima lapisan pada satu host lokal:

1. Simulasi traffic — injeksi PCAP melalui Suricata offline mode (`inject_all_pcap.py`)
2. Deteksi — Suricata + ruleset Emerging Threats → log EVE JSON
3. Agregasi — Wazuh Manager → Wazuh Indexer (OpenSearch)
4. Enrichment pipeline (5 modul Python + sub-modul substitusi IP):
   - `module1_query_alerts.py` — query & deduplikasi alert C2 dari OpenSearch
   - `substitution_step1..5_*.py` — substitusi IP (mitigasi temporal decay)
   - `module2_abuseipdb.py` — enrichment reputasi IP via AbuseIPDB API
   - `module3_mitre_mapping.py` — pemetaan MITRE ATT&CK tiga lapis
   - `module4_llm_summary.py` — narasi dua kalimat via Gemini 2.5 Flash (temperature=0)
   - `module5_save_results.py` — penyimpanan hasil ke JSON
5. Evaluasi — `evaluator.py` menghitung M-1 (MITRE Mapping Coverage),
   M-2 (AI Summary Fidelity, rubrik tiga dimensi), dan kondisi validitas
   Pipeline Coverage; `timing_report.py` merangkum pengukuran performance impact.

## Instalasi
1. Prasyarat sistem

- Kali Linux (diuji pada Kali Rolling 2025.3, kernel 6.12) atau distribusi Debian-based lain
- Python 3.13+
- Suricata 8.x dengan ruleset Emerging Threats (`suricata-update`)
- Wazuh 4.14.x (Manager, Indexer, Dashboard) pada host yang sama
- Integrasi Suricata–Wazuh melalui pembacaan EVE JSON (`localfile` pada `ossec.conf`)

2. Clone / unduh repository
git clone https://github.com/pangeranGit/Tugas-Akhir_Kevin-Pangeran.git
cd Tugas-Akhir_Kevin-Pangeran

Atau unduh sebagai ZIP: tombol **Code → Download ZIP**, lalu ekstrak.

3. Siapkan virtual environment Python
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv opensearch-py google-genai pandas tqdm

4. Konfigurasi API key
cp src/config.example.py src/config.py
nano src/config.py


Isi nilai berikut pada `config.py`:

- `ABUSEIPDB_API_KEY` — API key AbuseIPDB (gratis di https://www.abuseipdb.com/api)
- `GEMINI_API_KEYS` — satu atau lebih API key Gemini (https://aistudio.google.com/apikey);
  disarankan beberapa key karena pipeline melakukan rotasi otomatis saat menerima
  error 429/503 (rate limit)
- Kredensial OpenSearch/Wazuh Indexer (host, port, user, password)

Catatan: `src/config.py` tidak disertakan dalam repository karena berisi kredensial. Jangan pernah meng-commit file ini.

5. Siapkan dataset

Unduh dataset EarlyCrowAPT (45 file PCAP) dan letakkan pada direktori dataset
sesuai path yang dikonfigurasi di `config.py`, lalu injeksikan:

python3 src/inject_all_pcap.py


Verifikasi alert masuk ke Wazuh Indexer sebelum menjalankan pipeline.
python3 src/pipeline.py --full      # eksekusi penuh end-to-end (Modul 1-5 + evaluator)
python3 src/timing_report.py        # ringkasan pengukuran performance impact

Modul juga dapat dijalankan mandiri untuk keperluan demonstrasi per tahap:
python3 src/module1_query_alerts.py
python3 src/module2_abuseipdb.py
python3 src/module3_mitre_mapping.py
python3 src/module4_llm_summary.py
python3 src/module5_save_results.py
python3 src/evaluator.py


Hasil evaluasi (eksekusi penuh 14 Juli 2026)

- M-1 (MITRE Mapping Coverage): **100%** (47/47 alert)
- M-2 (AI Summary Fidelity): **3,0000** (skala 1–3)
- Pipeline Coverage: **47/47** alert terproses end-to-end
- Total durasi: **395,07 s** (Modul 4/LLM: 85,7% dari total)

## Artefak Keterulangan

Tiga eksekusi penuh yang dilaporkan pada naskah tersedia pada `artefak/`:

| Folder | Tanggal eksekusi | M-1 | M-2 | Pipeline Coverage |
|---|---|---|---|---|
| `run_20260714_pertama/` | 14 Juli 2026 | 100% | 3,0000 | 47/47 |
| `run_20260720_utama/`   | 20 Juli 2026 | 100% | 2,9929 | 47/47 |
| `run_20260721_ketiga/`  | 21 Juli 2026 | 100% | 2,9078 | 45/47 |

Eksekusi ketiga tidak memenuhi kondisi validitas Pipeline Coverage sehingga nilai
M-2-nya tidak diperbandingkan pada evaluasi mutu, tetapi tetap dilaporkan pada
tingkat keandalan end-to-end.

Angka performa pada naskah bersumber dari `run_20260714_pertama/pipeline_run_metadata.json`,
satu-satunya eksekusi yang diaktifkan instrumentasi waktunya.

Berkas `c2_alerts_raw.json` (56 MB, 440.581 alert mentah) tidak diunggah karena
ukurannya; checksum SHA-256-nya tercatat pada `artefak/checksum/artefak_sha256.txt`.

Catatan: label `"Evaluator: M1-1 s.d. M1-4"` pada `pipeline_run_metadata.json`
merupakan teks log lama yang tertinggal pada orkestrator. Kerangka evaluasi yang
benar-benar dijalankan adalah kerangka final, sebagaimana terlihat pada kunci
keluaran `m1_coverage`, `m2_fidelity`, dan `validity_coverage` di
`evaluation_results.json` serta pada `src/evaluator.py`.
