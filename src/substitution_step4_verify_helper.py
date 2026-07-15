"""
Tahap 4 — Helper untuk verifikasi manual di web AbuseIPDB.

Fungsi:
- Tampilkan tabel mapping dalam format yang mudah dibaca
- Generate daftar URL untuk verifikasi manual
- Buat checklist verifikasi yang bisa Anda print/save
- Setelah verifikasi, apply manual override jika perlu
"""

import sys
import json
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


def main():
    print("=" * 100)
    print("TAHAP 4 — VERIFIKASI MANUAL HELPER")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    # Load draft
    with open(OUTPUT_DIR / "ip_substitution_draft.json") as f:
        draft = json.load(f)
    
    mappings = draft['mappings']
    
    # Tampilkan tabel detail
    print("\n=== TABEL MAPPING DETAIL UNTUK VERIFIKASI ===\n")
    
    for i, m in enumerate(mappings, 1):
        old = m.get('old_profile', {})
        new = m.get('new_profile', {})
        
        print(f"[{i:02d}/26] " + "─" * 90)
        print(f"  OLD: {m['old_ip']}")
        print(f"       Malware  : {', '.join(old.get('malware_families', []))}")
        print(f"       Country  : {old.get('country_code', '')} ({old.get('country_name', '')})")
        print(f"       Usage    : {old.get('usage_type', '')}")
        print(f"       ISP      : {old.get('isp', '')}")
        print(f"       Score    : {old.get('old_abuse_score', 0)} (decayed)")
        print(f"")
        print(f"  NEW: {m['new_ip']}")
        print(f"       Country  : {new.get('country_code', '')} ({new.get('country_name', '')})")
        print(f"       Usage    : {new.get('usage_type', '')}")
        print(f"       ISP      : {new.get('isp', '')}")
        print(f"       Score    : {new.get('abuse_score', 0)}/100  ← AKTIF")
        print(f"       Reports  : {new.get('total_reports', 0)}")
        print(f"       Last Rep : {new.get('last_reported_at', '')[:10]}")
        print(f"")
        print(f"  Match score  : {m.get('match_score', 0)}")
        print(f"  Reasons      : {', '.join(m.get('match_reasons', []))}")
        print(f"  🌐 VERIFY    : {m.get('verification_url', '')}")
        print()
    
    # Generate URL list untuk batch verify
    print("\n" + "=" * 100)
    print("DAFTAR URL VERIFIKASI (copy-paste ke browser)")
    print("=" * 100)
    
    url_list_path = OUTPUT_DIR / "verification_urls.txt"
    with open(url_list_path, "w") as f:
        f.write("# Daftar URL Verifikasi AbuseIPDB\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Total: {len(mappings)} URL\n\n")
        f.write("# Cara pakai:\n")
        f.write("# 1. Buka setiap URL di browser\n")
        f.write("# 2. Verifikasi: score, country, usage type, last reports\n")
        f.write("# 3. Screenshot halaman untuk dokumentasi BAB IV\n")
        f.write("# 4. Catat di checklist apakah cocok atau perlu diganti\n\n")
        
        for i, m in enumerate(mappings, 1):
            line = f"{i:02d}. {m['old_ip']:<18} → {m['new_ip']:<18} {m.get('verification_url', '')}\n"
            f.write(line)
            print(line.strip())
    
    # Generate checklist
    checklist_path = OUTPUT_DIR / "verification_checklist.md"
    with open(checklist_path, "w") as f:
        f.write("# Verifikasi Manual IP Substitution\n\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
        f.write(f"**Total IP:** {len(mappings)}\n\n")
        f.write("## Petunjuk\n\n")
        f.write("1. Buka URL verifikasi di browser\n")
        f.write("2. Cek: score ≥ 75, kategori report relevan (C2/malware/botnet)\n")
        f.write("3. Screenshot halaman untuk dokumentasi\n")
        f.write("4. Centang ✅ jika cocok, ❌ jika perlu diganti\n")
        f.write("5. Simpan screenshot di folder `docs/screenshots/abuseipdb/`\n\n")
        f.write("## Checklist\n\n")
        f.write("| No | Old IP | New IP | Score | Status | Catatan |\n")
        f.write("|----|--------|--------|-------|--------|--------|\n")
        for i, m in enumerate(mappings, 1):
            f.write(f"| {i:02d} | `{m['old_ip']}` | `{m['new_ip']}` | {m.get('match_score', 0)} | [ ] | |\n")
    
    print(f"\n✅ File verifikasi tersimpan:")
    print(f"   - {url_list_path}")
    print(f"   - {checklist_path}")
    
    print("\n" + "=" * 100)
    print("LANGKAH MANUAL ANDA SEKARANG")
    print("=" * 100)
    print("""
    1. Buka file verification_urls.txt
    2. Untuk setiap URL:
       a. Buka di browser
       b. Verifikasi:
          - Abuse Confidence Score ≥ 75
          - Last reported recent (dalam 30 hari)
          - Categories yang reported relevan dengan C2/malware
       c. SCREENSHOT halaman untuk lampiran BAB IV
       d. Simpan di folder docs/screenshots/abuseipdb/IP_OLD.png
    3. Update verification_checklist.md (centang yang valid)
    4. Jika ada yang TIDAK COCOK:
       - Catat IP pengganti yang Anda pilih manual
       - Akan kita override di Tahap 4b
    5. Setelah semua diverifikasi → lanjut ke Tahap 5 (apply substitusi)
    """)
    print("=" * 100)


if __name__ == "__main__":
    main()
