"""
Pipeline Orchestrator: Menjalankan seluruh pipeline enrichment end-to-end.

Alur:
  1. [Opsional] Modul 1 - Query alert C2 dari Wazuh/OpenSearch
  2. Substitusi IP (Tahap 5) - Ganti dest_ip dengan IP aktif AbuseIPDB
  3. Modul 2 - AbuseIPDB enrichment
  4. Modul 3 - MITRE ATT&CK mapping
  5. Modul 4 - LLM summarization (Gemini 2.5 Flash)
  6. Modul 5 - Finalisasi output
  7. Evaluator - Hitung M1-1, M1-2, M1-3, M1-4

Penggunaan:
  python src/pipeline.py              # Mulai dari substitusi (Modul 1 sudah jalan)
  python src/pipeline.py --full       # Termasuk Modul 1 (butuh Wazuh aktif)
  python src/pipeline.py --skip-llm   # Skip Modul 4 (hemat API quota saat testing)
"""

import sys
import json
import time
import shutil
import argparse
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import *

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "pipeline.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# === Timing Instrumentation (Performance Impact) ===
STAGE_TIMINGS = {}


def timed(stage_name, func):
    """Jalankan satu step pipeline sambil mengukur durasi wall-clock-nya."""
    t0 = time.perf_counter()
    result = func()
    elapsed = round(time.perf_counter() - t0, 3)
    STAGE_TIMINGS[stage_name] = elapsed
    logger.info(f"[TIMING] {stage_name}: {elapsed:.2f} detik")
    return result


# === Pipeline Steps ===

def step_module1():
    """Modul 1: Query alert C2 dari Wazuh/OpenSearch."""
    from module1_query_alerts import main as run_module1
    logger.info("=" * 70)
    logger.info("STEP 1: MODUL 1 — QUERY ALERT C2")
    logger.info("=" * 70)
    result = run_module1()
    if result is None:
        raise RuntimeError("Modul 1 gagal. Pastikan Wazuh/OpenSearch aktif.")
    return result


def step_substitution():
    """Tahap 5: Apply substitusi IP ke alert data."""
    logger.info("=" * 70)
    logger.info("STEP 2: SUBSTITUSI IP")
    logger.info("=" * 70)

    source = OUTPUT_DIR / "c2_alerts_deduped.json"
    substituted = OUTPUT_DIR / "c2_alerts_deduped_substituted.json"
    mapping_file = OUTPUT_DIR / "ip_substitution_draft.json"

    # Cek apakah substitusi sudah pernah dijalankan
    if substituted.exists():
        logger.info(f"File substituted ditemukan: {substituted.name}")
        shutil.copy2(substituted, source)
        logger.info(f"Copied {substituted.name} → {source.name}")
    elif mapping_file.exists():
        logger.info("Menjalankan substitusi dari draft mapping...")
        from substitution_step5_apply import main as run_step5
        run_step5()
        if substituted.exists():
            shutil.copy2(substituted, source)
            logger.info(f"Copied {substituted.name} → {source.name}")
    else:
        logger.warning("Tidak ada mapping substitusi. Melanjutkan dengan IP asli.")
        return

    # Verifikasi
    with open(source) as f:
        alerts = json.load(f)
    has_orig = sum(1 for a in alerts if "_original_dest_ip" in a)
    logger.info(f"Verifikasi: {len(alerts)} alerts, {has_orig} punya _original_dest_ip")

    # Hapus cache AbuseIPDB lama
    cache = OUTPUT_DIR / "abuseipdb_cache.json"
    if cache.exists():
        cache.unlink()
        logger.info("Cache AbuseIPDB lama dihapus")


def step_module2():
    """Modul 2: AbuseIPDB enrichment."""
    from module2_abuseipdb import main as run_module2
    logger.info("=" * 70)
    logger.info("STEP 3: MODUL 2 — ABUSEIPDB ENRICHMENT")
    logger.info("=" * 70)
    result = run_module2()
    if result is None:
        raise RuntimeError("Modul 2 gagal.")
    return result


def step_module3():
    """Modul 3: MITRE ATT&CK mapping."""
    from module3_mitre_mapping import main as run_module3
    logger.info("=" * 70)
    logger.info("STEP 4: MODUL 3 — MITRE ATT&CK MAPPING")
    logger.info("=" * 70)
    result = run_module3()
    output_file = OUTPUT_DIR / "c2_alerts_enriched_mitre.json"
    if not output_file.exists():
        raise RuntimeError("Modul 3 gagal.")
    return result


def step_module4():
    """Modul 4: LLM summarization."""
    from module4_llm_summary import main as run_module4
    logger.info("=" * 70)
    logger.info("STEP 5: MODUL 4 — LLM SUMMARIZATION")
    logger.info("=" * 70)
    result = run_module4()
    if result is None:
        raise RuntimeError("Modul 4 gagal.")
    return result


def step_module5():
    """Modul 5: Finalisasi output."""
    from module5_save_results import main as run_module5
    logger.info("=" * 70)
    logger.info("STEP 6: MODUL 5 — FINALISASI OUTPUT")
    logger.info("=" * 70)
    result = run_module5()
    if result is None:
        raise RuntimeError("Modul 5 gagal.")
    return result


def step_evaluator():
    """Evaluator: Hitung M1-1 s.d. M1-4."""
    from evaluator import main as run_evaluator
    logger.info("=" * 70)
    logger.info("STEP 7: EVALUATOR — M1-1, M1-2, M1-3, M1-4")
    logger.info("=" * 70)
    result = run_evaluator()
    if result is None:
        raise RuntimeError("Evaluator gagal.")
    return result


# === Main Orchestrator ===

def main():
    parser = argparse.ArgumentParser(description="Pipeline Enrichment Orchestrator")
    parser.add_argument("--full", action="store_true",
                        help="Termasuk Modul 1 (butuh Wazuh/OpenSearch aktif)")
    parser.add_argument("--skip-llm", action="store_true",
                        help="Skip Modul 4 LLM (hemat API quota saat testing)")
    parser.add_argument("--skip-eval", action="store_true",
                        help="Skip evaluator")
    args = parser.parse_args()

    start_time = datetime.now()

    print()
    print("=" * 70)
    print("  PIPELINE ENRICHMENT DAN AI-ASSISTED SUMMARIZATION")
    print("  Deteksi Command and Control (TA0011)")
    print("  Wazuh + Suricata + AbuseIPDB + Gemini 2.5 Flash")
    print("=" * 70)
    print(f"  Waktu mulai : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Mode        : {'Full (incl. Modul 1)' if args.full else 'Post-detection'}")
    print(f"  LLM         : {'Skip' if args.skip_llm else GEMINI_MODEL}")
    print(f"  Evaluator   : {'Skip' if args.skip_eval else 'Aktif'}")
    print("=" * 70)
    print()

    # Validasi config
    if not validate_config():
        logger.error("Konfigurasi tidak valid. Perbaiki .env terlebih dahulu.")
        sys.exit(1)

    steps_executed = []
    try:
        # Step 1: Modul 1 (opsional)
        if args.full:
            timed("modul1_query_alert", step_module1)
            steps_executed.append("Modul 1: Query Alert C2")

        # Step 2: Substitusi IP
        timed("substitusi_ip", step_substitution)
        steps_executed.append("Substitusi IP")

        # Step 3: Modul 2
        timed("modul2_abuseipdb_enrichment", step_module2)
        steps_executed.append("Modul 2: AbuseIPDB Enrichment")

        # Step 4: Modul 3
        timed("modul3_mitre_mapping", step_module3)
        steps_executed.append("Modul 3: MITRE ATT&CK Mapping")

        # Step 5: Modul 4 (opsional skip)
        if not args.skip_llm:
            timed("modul4_llm_summarization", step_module4)
            steps_executed.append("Modul 4: LLM Summarization")
        else:
            logger.info("SKIP: Modul 4 (--skip-llm)")
            steps_executed.append("Modul 4: SKIPPED")

        # Step 6: Modul 5
        timed("modul5_finalisasi", step_module5)
        steps_executed.append("Modul 5: Finalisasi Output")

        # Step 7: Evaluator (opsional skip)
        if not args.skip_eval:
            timed("evaluator", step_evaluator)
            steps_executed.append("Evaluator: M1-1 s.d. M1-4")
        else:
            logger.info("SKIP: Evaluator (--skip-eval)")
            steps_executed.append("Evaluator: SKIPPED")

    except RuntimeError as e:
        logger.error(f"Pipeline gagal: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Pipeline dibatalkan oleh user (Ctrl+C)")
        sys.exit(1)

    end_time = datetime.now()
    duration = end_time - start_time

    # Ringkasan akhir
    print()
    print("=" * 70)
    print("  PIPELINE SELESAI")
    print("=" * 70)
    print(f"  Waktu mulai  : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Waktu selesai: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Durasi       : {duration}")
    print()
    print("  Tahapan yang dieksekusi:")
    for i, step in enumerate(steps_executed, 1):
        print(f"    {i}. {step}")

    # Load dan tampilkan hasil evaluasi jika ada
    eval_path = OUTPUT_DIR / "evaluation_results.json"
    if eval_path.exists() and not args.skip_eval:
        with open(eval_path) as f:
            eval_data = json.load(f)
        summary = eval_data.get("summary", {})
        print()
        print("  Hasil Evaluasi:")
        print(f"    M1-1 (Enrichment Accuracy)  : {summary.get('M1-1', 'N/A')}%")
        print(f"    M1-2 (MITRE Precision)      : {summary.get('M1-2', 'N/A')}%")
        print(f"    M1-3 (Summary Fidelity)     : {summary.get('M1-3', 'N/A')} / 3.0")
        print(f"    M1-4 (Pipeline Coverage)    : {summary.get('M1-4', 'N/A')}%")

    print()
    print("  Output files:")
    for fname in ["enriched_alerts.json", "evaluation_results.json"]:
        fpath = OUTPUT_DIR / fname
        if fpath.exists():
            size_kb = fpath.stat().st_size / 1024
            print(f"    {fname:<30} {size_kb:>8.1f} KB")
    print("=" * 70)

    # Ringkasan durasi per tahap (Performance Impact)
    if STAGE_TIMINGS:
        print()
        print("  Durasi per tahap:")
        for stage, secs in STAGE_TIMINGS.items():
            print(f"    {stage:<34} {secs:>10.2f} s")

    # Simpan pipeline run metadata
    run_meta = {
        "pipeline_run": {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration.total_seconds(),
            "stage_durations_seconds": STAGE_TIMINGS,
            "mode": "full" if args.full else "post-detection",
            "llm_skipped": args.skip_llm,
            "eval_skipped": args.skip_eval,
            "steps_executed": steps_executed,
        }
    }
    with open(OUTPUT_DIR / "pipeline_run_metadata.json", "w") as f:
        json.dump(run_meta, f, indent=2)


if __name__ == "__main__":
    main()
