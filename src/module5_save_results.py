"""
Module 5: Finalisasi output pipeline.

Fungsi:
- Baca hasil akhir dari Module 4 (c2_alerts_enriched_llm.json)
- Tambahkan metadata pipeline (timestamp, version, stats)
- Simpan ke enriched_alerts.json sebagai output final pipeline
- File ini menjadi input untuk evaluator.py
"""

import sys
import json
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import *

# === Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "module5.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def compute_pipeline_stats(alerts):
    """Hitung statistik ringkas seluruh pipeline."""
    total = len(alerts)
    
    # Module 2 stats
    abuseipdb_success = sum(
        1 for a in alerts 
        if a.get("abuseipdb", {}).get("query_status") == "success"
    )
    
    # Module 3 stats
    mitre_with_ta0011 = sum(
        1 for a in alerts 
        if "TA0011" in a.get("mitre", {}).get("tactic_ids", [])
    )
    
    # Module 4 stats
    llm_success = sum(
        1 for a in alerts 
        if a.get("llm_summary", {}).get("parse_status") == "success"
    )
    llm_partial = sum(
        1 for a in alerts 
        if a.get("llm_summary", {}).get("parse_status") == "partial"
    )
    llm_failed = sum(
        1 for a in alerts 
        if a.get("llm_summary", {}).get("parse_status") in ("empty_response", "fallback")
    )
    
    # Fidelity preview
    d1s = [a.get("fidelity_preview", {}).get("d1", 0) for a in alerts]
    d2s = [a.get("fidelity_preview", {}).get("d2", 0) for a in alerts]
    d3s = [a.get("fidelity_preview", {}).get("d3", 0) for a in alerts]
    scores = [a.get("fidelity_preview", {}).get("score", 0) for a in alerts]
    
    # Unique entities
    unique_signatures = len(set(a.get("signature", "") for a in alerts))
    unique_dest_ips = len(set(a.get("dest_ip", "") for a in alerts))
    
    return {
        "total_alerts": total,
        "unique_signatures": unique_signatures,
        "unique_dest_ips": unique_dest_ips,
        "module2_abuseipdb_success": abuseipdb_success,
        "module3_mitre_ta0011_count": mitre_with_ta0011,
        "module4_llm_success": llm_success,
        "module4_llm_partial": llm_partial,
        "module4_llm_failed": llm_failed,
        "avg_d1_factual": round(sum(d1s) / len(d1s), 4) if d1s else 0,
        "avg_d2_completeness": round(sum(d2s) / len(d2s), 4) if d2s else 0,
        "avg_d3_relevance": round(sum(d3s) / len(d3s), 4) if d3s else 0,
        "preview_m13_fidelity": round(sum(scores) / len(scores), 4) if scores else 0,
    }


def main():
    print("=" * 70)
    print("MODULE 5: FINALISASI OUTPUT PIPELINE")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # Step 1: Load hasil Module 4
    input_path = OUTPUT_DIR / "c2_alerts_enriched_llm.json"
    if not input_path.exists():
        logger.error(f"File tidak ditemukan: {input_path}")
        logger.error("Jalankan Module 4 terlebih dahulu!")
        return None
    
    with open(input_path) as f:
        alerts = json.load(f)
    
    logger.info(f"Loaded {len(alerts)} alert dari Module 4")
    
    # Step 2: Hitung stats
    stats = compute_pipeline_stats(alerts)
    
    # Step 3: Bangun struktur final dengan metadata
    final_output = {
        "metadata": {
            "pipeline_name": "C2 Alert Enrichment and AI-Assisted Summarization",
            "version": "1.0",
            "generated_at": datetime.now().isoformat(),
            "dataset": "EarlyCrowAPT",
            "detection_stack": "Suricata + Wazuh",
            "llm_model": GEMINI_MODEL,
            "llm_temperature": GEMINI_TEMPERATURE,
            "enrichment_sources": ["AbuseIPDB", "MITRE ATT&CK"],
            "prompt_components": [
                "Role Constraint",
                "Structured Input",
                "Output Format",
                "Anti-Hallucination Constraint"
            ]
        },
        "pipeline_stats": stats,
        "alerts": alerts
    }
    
    # Step 4: Simpan ke enriched_alerts.json
    output_path = OUTPUT_DIR / "enriched_alerts.json"
    with open(output_path, "w") as f:
        json.dump(final_output, f, indent=2, default=str)
    
    logger.info(f"Output final disimpan ke: {output_path}")
    
    # Step 5: Tampilkan ringkasan
    print("\n" + "=" * 70)
    print("RINGKASAN PIPELINE END-TO-END")
    print("=" * 70)
    print(f"  Total alert diproses       : {stats['total_alerts']}")
    print(f"  Unique signatures          : {stats['unique_signatures']}")
    print(f"  Unique destination IPs     : {stats['unique_dest_ips']}")
    print()
    print(f"  Module 2 (AbuseIPDB)       : {stats['module2_abuseipdb_success']}/{stats['total_alerts']} success")
    print(f"  Module 3 (MITRE TA0011)    : {stats['module3_mitre_ta0011_count']}/{stats['total_alerts']} mapped")
    print(f"  Module 4 (LLM Summary)     : {stats['module4_llm_success']}/{stats['total_alerts']} success")
    print()
    print(f"  === PREVIEW FIDELITAS (dihitung di Module 4) ===")
    print(f"  Avg D1 (Factual Accuracy)  : {stats['avg_d1_factual']:.4f} / 3.00")
    print(f"  Avg D2 (Completeness)      : {stats['avg_d2_completeness']:.4f} / 3.00")
    print(f"  Avg D3 (Relevance)         : {stats['avg_d3_relevance']:.4f} / 3.00")
    print(f"  Preview M1-3 Fidelity      : {stats['preview_m13_fidelity']:.4f}")
    print()
    print(f"  Output file                : {output_path}")
    print(f"  File size                  : {output_path.stat().st_size / 1024:.1f} KB")
    print("=" * 70)
    print()
    print("Catatan: Evaluasi formal M1-1, M1-2, M1-3, M1-4 dilakukan")
    print("         oleh script evaluator.py (bukan oleh Module 5).")
    print("=" * 70)
    
    return final_output


if __name__ == "__main__":
    main()
