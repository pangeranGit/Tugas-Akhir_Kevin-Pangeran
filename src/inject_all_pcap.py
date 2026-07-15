"""
inject_all_pcap.py - Injeksi seluruh PCAP EarlyCrowAPT via Suricata offline mode.
Output: eve.json gabungan + log statistik per file.

Catatan teknis:
- Menggunakan suricata -r (offline mode) karena AF-PACKET+dummy0 tidak memproses paket
- Flag -l memastikan eve.json ditulis ke /var/log/suricata/ (bukan current dir)
- Eve.json di-append (tidak di-truncate antar file) agar semua alert terkumpul
"""

import subprocess
import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime

# === Konfigurasi ===
PCAP_DIR = Path(os.path.expanduser("~/ta-pipeline/dataset/pcap_files/raw"))
EVE_JSON = Path("/var/log/suricata/eve.json")
SURICATA_YAML = "/etc/suricata/suricata.yaml"
LOG_OUTPUT_DIR = "/var/log/suricata"
STATS_FILE = Path(os.path.expanduser("~/ta-pipeline/output/pcap_injection_stats.json"))

def count_alerts_in_eve(eve_path):
    """Hitung jumlah alert di eve.json."""
    try:
        result = subprocess.run(
            ["grep", "-c", '"event_type":"alert"', str(eve_path)],
            capture_output=True, text=True
        )
        return int(result.stdout.strip()) if result.returncode == 0 else 0
    except:
        return 0

def count_lines_in_eve(eve_path):
    """Hitung total baris di eve.json."""
    try:
        result = subprocess.run(
            ["wc", "-l", str(eve_path)],
            capture_output=True, text=True
        )
        return int(result.stdout.strip().split()[0]) if result.returncode == 0 else 0
    except:
        return 0

def run_suricata_offline(pcap_path):
    """Jalankan Suricata offline mode pada satu file PCAP."""
    cmd = [
        "sudo", "suricata",
        "-c", SURICATA_YAML,
        "-r", str(pcap_path),
        "-l", LOG_OUTPUT_DIR,
        "--set", "outputs.0.eve-log.append=yes"
    ]
    
    result = subprocess.run(
        cmd,
        capture_output=True, text=True,
        timeout=1200  # 20 menit max per PCAP
    )
    return result

def main():
    print("=" * 70)
    print("INJEKSI SELURUH PCAP EarlyCrowAPT via Suricata Offline Mode")
    print(f"Waktu mulai: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # Cari semua file PCAP
    pcap_files = sorted(PCAP_DIR.glob("*.pcap"))
    if not pcap_files:
        print(f"[X] Tidak ada file .pcap di {PCAP_DIR}")
        sys.exit(1)

    print(f"\nDitemukan {len(pcap_files)} file PCAP")
    print(f"EVE JSON output: {EVE_JSON}")
    print()

    # Pastikan output dir ada
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)

    stats = []
    total_alerts_before = count_alerts_in_eve(EVE_JSON)
    
    for i, pcap in enumerate(pcap_files, 1):
        pcap_name = pcap.name
        pcap_size_mb = pcap.stat().st_size / (1024 * 1024)
        
        print(f"[{i:02d}/{len(pcap_files)}] {pcap_name} ({pcap_size_mb:.1f} MB) ... ", end="", flush=True)
        
        alerts_before = count_alerts_in_eve(EVE_JSON)
        time_start = time.time()
        
        try:
            result = run_suricata_offline(pcap)
            time_elapsed = time.time() - time_start
            
            alerts_after = count_alerts_in_eve(EVE_JSON)
            new_alerts = alerts_after - alerts_before
            
            # Cari info dari stderr (Suricata prints stats there)
            status = "OK" if result.returncode == 0 else f"EXIT:{result.returncode}"
            
            print(f"{new_alerts:>7,} alerts ({time_elapsed:.1f}s) [{status}]")
            
            stats.append({
                "file": pcap_name,
                "size_mb": round(pcap_size_mb, 2),
                "alerts": new_alerts,
                "time_seconds": round(time_elapsed, 1),
                "status": status,
                "cumulative_alerts": alerts_after
            })
            
        except subprocess.TimeoutExpired:
            print(f"TIMEOUT (>600s)")
            stats.append({
                "file": pcap_name,
                "size_mb": round(pcap_size_mb, 2),
                "alerts": 0,
                "time_seconds": 600,
                "status": "TIMEOUT",
                "cumulative_alerts": count_alerts_in_eve(EVE_JSON)
            })
        except Exception as e:
            print(f"ERROR: {e}")
            stats.append({
                "file": pcap_name,
                "size_mb": round(pcap_size_mb, 2),
                "alerts": 0,
                "time_seconds": 0,
                "status": f"ERROR:{str(e)[:50]}",
                "cumulative_alerts": count_alerts_in_eve(EVE_JSON)
            })

    # === Ringkasan ===
    total_alerts_final = count_alerts_in_eve(EVE_JSON)
    total_lines = count_lines_in_eve(EVE_JSON)
    total_time = sum(s["time_seconds"] for s in stats)
    files_with_alerts = sum(1 for s in stats if s["alerts"] > 0)
    files_zero_alerts = sum(1 for s in stats if s["alerts"] == 0)
    
    print()
    print("=" * 70)
    print("RINGKASAN INJEKSI")
    print("=" * 70)
    print(f"  Total file PCAP     : {len(pcap_files)}")
    print(f"  File dengan alert   : {files_with_alerts}")
    print(f"  File tanpa alert    : {files_zero_alerts}")
    print(f"  Total alert baru    : {total_alerts_final:,}")
    print(f"  Total baris eve.json: {total_lines:,}")
    print(f"  Total waktu         : {total_time:.0f} detik ({total_time/60:.1f} menit)")
    print(f"  Waktu selesai       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # Top 10 PCAP dengan alert terbanyak
    top10 = sorted(stats, key=lambda x: x["alerts"], reverse=True)[:10]
    print("\nTop 10 PCAP dengan alert terbanyak:")
    for rank, s in enumerate(top10, 1):
        print(f"  {rank:2d}. {s['file']:<35s} {s['alerts']:>8,} alerts")

    # Simpan stats ke JSON
    output_data = {
        "injection_date": datetime.now().isoformat(),
        "total_pcap_files": len(pcap_files),
        "total_alerts": total_alerts_final,
        "total_eve_lines": total_lines,
        "total_time_seconds": round(total_time, 1),
        "files_with_alerts": files_with_alerts,
        "files_zero_alerts": files_zero_alerts,
        "per_file_stats": stats
    }
    
    with open(STATS_FILE, "w") as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nStatistik disimpan ke: {STATS_FILE}")


if __name__ == "__main__":
    main()
