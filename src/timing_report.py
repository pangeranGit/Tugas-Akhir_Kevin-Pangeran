"""
Timing Report: Agregasi pengukuran Performance Impact pipeline.

Dijalankan SETELAH pipeline selesai (python src/pipeline.py).
Membaca:
  - output/pipeline_run_metadata.json  (durasi per tahap)
  - output/module2_timing.json         (latency query AbuseIPDB per IP)
  - output/c2_alerts_enriched_llm.json (latency LLM per alert)

Output:
  - Tabel statistik di terminal (siap disalin ke Bab IV)
  - output/performance_report.json

Catatan metodologis:
  Pengukuran dilakukan pada replay traffic terkontrol (offline), BUKAN
  evaluasi trafik real-time. Latency murni dipisahkan dari jeda artifisial
  rate limit (1 s antar query AbuseIPDB, 3 s antar request Gemini).
"""

import sys
import json
import statistics
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import *


def describe(values):
    """Statistik deskriptif sederhana untuk list durasi (detik)."""
    if not values:
        return None
    return {
        "n": len(values),
        "mean": round(statistics.mean(values), 3),
        "median": round(statistics.median(values), 3),
        "stdev": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
        "min": round(min(values), 3),
        "max": round(max(values), 3),
    }


def main():
    report = {}

    # === 1. Durasi per tahap (pipeline_run_metadata.json) ===
    meta_path = OUTPUT_DIR / "pipeline_run_metadata.json"
    stage_durations = {}
    total_duration = None
    if meta_path.exists():
        with open(meta_path) as f:
            meta = json.load(f).get("pipeline_run", {})
        stage_durations = meta.get("stage_durations_seconds", {})
        total_duration = meta.get("duration_seconds")
    else:
        print(f"PERINGATAN: {meta_path} tidak ditemukan. Jalankan pipeline dulu.")

    report["stage_durations_seconds"] = stage_durations
    report["total_pipeline_duration_seconds"] = total_duration

    # === 2. Latency AbuseIPDB per IP (module2_timing.json) ===
    m2_path = OUTPUT_DIR / "module2_timing.json"
    if m2_path.exists():
        with open(m2_path) as f:
            report["abuseipdb_query_latency"] = json.load(f)

    # === 3. Latency LLM per alert (c2_alerts_enriched_llm.json) ===
    llm_path = OUTPUT_DIR / "c2_alerts_enriched_llm.json"
    llm_stats = None
    n_alerts = None
    if llm_path.exists():
        with open(llm_path) as f:
            alerts = json.load(f)
        n_alerts = len(alerts)
        latencies = [a["llm_summary"]["llm_latency_seconds"]
                     for a in alerts
                     if "llm_latency_seconds" in a.get("llm_summary", {})]
        llm_stats = describe(latencies)
        report["llm_latency_per_alert"] = llm_stats

    # === 4. Estimasi jeda artifisial (rate limit) ===
    artificial = {}
    if n_alerts:
        artificial["gemini_sleep_seconds"] = (n_alerts - 1) * 3  # sleep 3 s antar request
    m2 = report.get("abuseipdb_query_latency", {})
    if m2.get("ip_queried"):
        artificial["abuseipdb_sleep_seconds"] = max(m2["ip_queried"] - 1, 0) * ABUSEIPDB_RATE_LIMIT
    artificial["note"] = ("Jeda artifisial berasal dari kebijakan rate limit layanan API "
                          "gratis, bukan beban komputasi pipeline.")
    report["artificial_delay_estimate"] = artificial

    # === 5. Waktu efektif per alert ===
    if total_duration and n_alerts:
        total_sleep = (artificial.get("gemini_sleep_seconds", 0)
                       + artificial.get("abuseipdb_sleep_seconds", 0))
        effective = total_duration - total_sleep
        report["effective_processing"] = {
            "total_wall_clock_seconds": round(total_duration, 3),
            "total_artificial_sleep_seconds": total_sleep,
            "effective_total_seconds": round(effective, 3),
            "effective_per_alert_seconds": round(effective / n_alerts, 3),
            "alerts_processed": n_alerts,
            "throughput_alerts_per_minute": round(n_alerts / (total_duration / 60), 2),
        }

    # === Cetak tabel siap salin ke Bab IV ===
    print("=" * 70)
    print("  PERFORMANCE IMPACT REPORT (Pengukuran Deskriptif)")
    print("  Konteks: offline replay dataset EarlyCrowAPT, BUKAN trafik real-time")
    print("=" * 70)

    if stage_durations:
        print("\n  [A] Durasi per tahap pipeline (wall-clock):")
        for stage, secs in stage_durations.items():
            print(f"      {stage:<34} {secs:>10.2f} s")
        if total_duration:
            print(f"      {'TOTAL':<34} {total_duration:>10.2f} s")

    if m2:
        print("\n  [B] Latency query AbuseIPDB per IP (tanpa jeda rate limit):")
        print(f"      n={m2.get('ip_queried')}  mean={m2.get('mean_seconds')} s  "
              f"min={m2.get('min_seconds')} s  max={m2.get('max_seconds')} s")

    if llm_stats:
        print("\n  [C] Latency Gemini 2.5 Flash per alert (tanpa jeda antar request):")
        print(f"      n={llm_stats['n']}  mean={llm_stats['mean']} s  median={llm_stats['median']} s")
        print(f"      stdev={llm_stats['stdev']} s  min={llm_stats['min']} s  max={llm_stats['max']} s")

    eff = report.get("effective_processing")
    if eff:
        print("\n  [D] Waktu pemrosesan efektif:")
        print(f"      Total wall-clock       : {eff['total_wall_clock_seconds']} s")
        print(f"      Estimasi jeda artifisial: {eff['total_artificial_sleep_seconds']} s")
        print(f"      Efektif total          : {eff['effective_total_seconds']} s")
        print(f"      Efektif per alert      : {eff['effective_per_alert_seconds']} s")
        print(f"      Throughput             : {eff['throughput_alerts_per_minute']} alert/menit")

    print("\n" + "=" * 70)

    out_path = OUTPUT_DIR / "performance_report.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Report disimpan: {out_path}")
    return report


if __name__ == "__main__":
    main()
