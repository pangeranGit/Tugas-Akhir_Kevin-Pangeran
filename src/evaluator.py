#!/usr/bin/env python3
"""
evaluator.py — Evaluasi pipeline terhadap ground truth EarlyCrowAPT.

SKEMA BARU (dua metrik utama + satu kondisi validitas):
  - M-1  MITRE Mapping Coverage  (eks M1-2)  -> metrik utama 1
  - M-2  AI Summary Fidelity      (eks M1-3)  -> metrik utama 2
  - Kondisi Validitas: Pipeline Coverage (eks M1-4) -> prasyarat keabsahan M-1/M-2
  - Temuan Enrichment (temporal decay / kalibrasi): DILAPORKAN sebagai TEMUAN,
    BUKAN metrik. Enrichment Accuracy (eks M1-1) dihapus dari daftar metrik karena
    dinilai sirkular oleh pembimbing; perilakunya tetap dilaporkan untuk analisis
    sensitivitas dan narasi temporal decay di Pembahasan.

Perubahan dari versi lama:
  - calc_m1_1() + confusion_matrix DIHAPUS sebagai metrik (diganti report_enrichment_finding()).
  - calc_m1_2()  -> calc_m1_coverage(), name "MITRE Mapping Coverage".
  - calc_m1_3()  -> calc_m2_fidelity(), metric "M-2".
  - calc_m1_4()  -> calc_validity_coverage(), dilaporkan sebagai kondisi validitas.
  - Kunci JSON output: m1_coverage, m2_fidelity, validity_coverage, enrichment_finding.
  - pipeline.py TIDAK disentuh.

Input:
  - output/enriched_alerts.json (output final pipeline)
  - dataset/EarlyCrowAPT/data/contextual_summaries/testing.csv (ground truth)
Output:
  - output/evaluation_results.json
"""
import sys
import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import *  # OUTPUT_DIR, LOG_DIR, GROUND_TRUTH_PATH, RELEVANT_C2_TACTICS, MITRE_C2_TACTIC_ID

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "evaluator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# === Ground Truth Loader ===
def load_ground_truth(gt_path):
    """Load ground truth dari testing.csv. Return dict {destination_ip: {label, capture_type}}."""
    gt = {}
    with open(gt_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            dest = row.get("Destination", "").strip()
            if dest:
                gt[dest] = {
                    "label": row.get("label", "").strip(),
                    "capture_type": row.get("capture_type", "").strip(),
                }
    return gt


# ==========================================================================
# METRIK UTAMA 1 — M-1  MITRE Mapping Coverage  (eks M1-2)
# ==========================================================================
def calc_m1_coverage(alerts):
    """
    M-1 = Alert terpetakan valid / Total alert C2.
    "Terpetakan valid" = alert memiliki taktik relevan kanal C2
        (TA0011 Command and Control ATAU TA0010 Exfiltration via T1041
         Exfiltration Over C2 Channel) DAN field technique terisi,
        sesuai definisi Tabel 2.3.
    Seluruh alert pada pipeline ini sudah berkategori C2 (hasil filter Modul 1).
    Metrik ini mengukur CAKUPAN & KONSISTENSI pemetaan terhadap metadata otoritatif
    (Emerging Threats ruleset / MITRE Software Catalog), BUKAN presisi klasifikasi
    statistik dengan False Positive independen — karena alert Suricata tidak memiliki
    ground truth taktik berlabel per alert.
    """
    total = len(alerts)
    mapping_valid = 0
    with_techniques = 0
    details = []
    for alert in alerts:
        mitre = alert.get("mitre", {})
        tactic_ids = mitre.get("tactic_ids", [])
        technique_ids = mitre.get("technique_ids", [])
        source = mitre.get("mapping_source", "unknown")

        ta0011_present = MITRE_C2_TACTIC_ID in tactic_ids
        tactic_relevant = any(t in RELEVANT_C2_TACTICS for t in tactic_ids)
        has_tech = len(technique_ids) > 0
        is_valid = tactic_relevant and has_tech

        if is_valid:
            mapping_valid += 1
        if has_tech:
            with_techniques += 1

        details.append({
            "signature": alert.get("signature", ""),
            "tactic_ids": tactic_ids,
            "technique_ids": technique_ids,
            "mapping_source": source,
            "ta0011_present": ta0011_present,
            "tactic_relevant": tactic_relevant,
            "has_techniques": has_tech,
            "is_valid": is_valid,
        })

    m1 = mapping_valid / total if total > 0 else 0
    sources = Counter(d["mapping_source"] for d in details)
    all_techs = Counter()
    for d in details:
        for t in d["technique_ids"]:
            all_techs[t] += 1

    return {
        "metric": "M-1",
        "name": "MITRE Mapping Coverage",
        "formula": "Alert terpetakan valid (taktik relevan C2/eksfiltrasi + teknik terisi) / Total alert C2",
        "value": round(m1, 4),
        "value_percent": round(m1 * 100, 2),
        "mapping_valid": mapping_valid,
        "with_techniques": with_techniques,
        "total_alerts": total,
        "mapping_sources": dict(sources),
        "technique_distribution": dict(all_techs.most_common()),
        "detail": details,
    }


# ==========================================================================
# METRIK UTAMA 2 — M-2  AI Summary Fidelity  (eks M1-3)
# ==========================================================================
def calc_m2_fidelity(alerts):
    """
    M-2 = (1/n) * Σ((D1 + D2 + D3) / 3) untuk setiap alert.
    D1 (Factual Accuracy), D2 (Completeness), D3 (Relevance) dihitung deterministik
    dari data enrichment vs narasi LLM. D3 membaca taktik AKTUAL yang dipetakan pada
    tiap alert (mitre.tactic_ids), bukan hardcode TA0011, sehingga adil untuk TA0011
    maupun TA0010.
    """
    fidelity_scores = []
    for alert in alerts:
        narration = alert.get("llm_summary", {})
        behavior = narration.get("behavior", "")
        threat_context = narration.get("threat_context", "")
        text = (behavior + " " + threat_context).lower()

        # D1: Factual Accuracy
        checks = []
        dest_ip = alert.get("dest_ip", "")
        src_ip = alert.get("src_ip", "")
        if dest_ip:
            checks.append(dest_ip.lower() in text)
        if src_ip:
            checks.append(src_ip.lower() in text)
        abuse_score = str(alert.get("abuseipdb", {}).get("abuseConfidenceScore", ""))
        if abuse_score and abuse_score != "-1":
            checks.append(abuse_score in text)
        sig = alert.get("signature", "").lower()
        if sig:
            keywords = [w for w in sig.split() if len(w) > 3
                        and w not in ["malware", "alert", "activity", "detected", "generic"]]
            if keywords:
                checks.append(any(kw in text for kw in keywords[:3]))
        if not checks:
            d1 = 1
        else:
            ratio = sum(checks) / len(checks)
            d1 = 3 if ratio >= 0.75 else (2 if ratio >= 0.4 else 1)

        # D2: Completeness
        has_b = bool(behavior and len(behavior) > 10)
        has_t = bool(threat_context and len(threat_context) > 10)
        d2 = 3 if (has_b and has_t) else (2 if (has_b or has_t) else 1)

        # D3: Relevance (baca tactic yang DIPETAKAN, bukan hardcode TA0011)
        mapped_tactics = [t.lower() for t in alert.get("mitre", {}).get("tactic_ids", [])]
        has_mapped_tactic = any(t in text for t in mapped_tactics) if mapped_tactics else False
        has_c2 = any(t in text for t in ["command and control", "c2", "cnc", "c&c", "beacon", "callback"])
        d3 = 3 if (has_mapped_tactic and has_c2) else (2 if (has_mapped_tactic or has_c2) else 1)

        score = round((d1 + d2 + d3) / 3, 4)
        fidelity_scores.append({
            "signature": alert.get("signature", ""),
            "d1": d1, "d2": d2, "d3": d3, "score": score,
            "behavior_len": len(behavior),
            "threat_context_len": len(threat_context),
            "parse_status": narration.get("parse_status", "unknown"),
        })

    n = len(fidelity_scores)
    avg_d1 = sum(f["d1"] for f in fidelity_scores) / n if n else 0
    avg_d2 = sum(f["d2"] for f in fidelity_scores) / n if n else 0
    avg_d3 = sum(f["d3"] for f in fidelity_scores) / n if n else 0
    avg_score = sum(f["score"] for f in fidelity_scores) / n if n else 0
    d1_dist = Counter(f["d1"] for f in fidelity_scores)
    d2_dist = Counter(f["d2"] for f in fidelity_scores)
    d3_dist = Counter(f["d3"] for f in fidelity_scores)

    return {
        "metric": "M-2",
        "name": "AI Summary Fidelity",
        "formula": "(1/n) * Σ((D1 + D2 + D3) / 3)",
        "value": round(avg_score, 4),
        "scale_max": 3.0,
        "avg_d1_factual": round(avg_d1, 4),
        "avg_d2_completeness": round(avg_d2, 4),
        "avg_d3_relevance": round(avg_d3, 4),
        "d1_distribution": {f"score_{k}": v for k, v in sorted(d1_dist.items())},
        "d2_distribution": {f"score_{k}": v for k, v in sorted(d2_dist.items())},
        "d3_distribution": {f"score_{k}": v for k, v in sorted(d3_dist.items())},
        "total_alerts": n,
        "detail": fidelity_scores,
    }


# ==========================================================================
# KONDISI VALIDITAS — Pipeline Coverage  (eks M1-4, kini bukan metrik)
# ==========================================================================
def calc_validity_coverage(alerts, total_raw_alerts=None):
    """
    Kondisi Validitas = Alert complete / Total alert masuk × 100%.
    Alert "complete" = memiliki abuseipdb (success) + mitre valid + llm_summary
    (success/partial). Nilai coverage tinggi menjadi PRASYARAT agar M-1 dan M-2
    bermakna; dilaporkan sebagai statistik keandalan, bukan sebagai metrik evaluasi.
    """
    if total_raw_alerts is None:
        total_raw_alerts = len(alerts)
    complete = 0
    incomplete = []
    per_module = {"abuseipdb": 0, "mitre": 0, "llm": 0}
    for alert in alerts:
        has_abuse = alert.get("abuseipdb", {}).get("query_status") == "success"
        _m = alert.get("mitre", {})
        has_mitre = (any(t in RELEVANT_C2_TACTICS for t in _m.get("tactic_ids", []))
                     and len(_m.get("technique_ids", [])) > 0)
        has_llm = alert.get("llm_summary", {}).get("parse_status") in ("success", "partial")
        per_module["abuseipdb"] += int(has_abuse)
        per_module["mitre"] += int(has_mitre)
        per_module["llm"] += int(has_llm)
        if has_abuse and has_mitre and has_llm:
            complete += 1
        else:
            incomplete.append({
                "signature": alert.get("signature", ""),
                "has_abuseipdb": has_abuse,
                "has_mitre": has_mitre,
                "has_llm": has_llm,
            })
    cov = complete / total_raw_alerts if total_raw_alerts > 0 else 0
    return {
        "name": "Pipeline Coverage (Kondisi Validitas)",
        "formula": "Alert complete / Total alert masuk × 100%",
        "value": round(cov, 4),
        "value_percent": round(cov * 100, 2),
        "complete": complete,
        "incomplete": len(incomplete),
        "total_alerts_in": total_raw_alerts,
        "per_module_complete": per_module,
        "incomplete_detail": incomplete,
    }


# ==========================================================================
# TEMUAN (BUKAN METRIK) — Perilaku Enrichment vs Ground Truth
# Dipakai untuk analisis sensitivitas + narasi temporal decay (Pembahasan).
# ==========================================================================
def report_enrichment_finding(alerts, gt, score_threshold=50):
    """
    TEMUAN, BUKAN METRIK. Membandingkan skor reputasi AbuseIPDB (pada kondisi data
    aktif hasil substitusi) terhadap label ground truth EarlyCrowAPT, ditelusuri via
    _original_dest_ip. Enrichment Accuracy (eks M1-1) DIHAPUS sebagai metrik karena
    dinilai sirkular; perilaku ini hanya dilaporkan untuk mendukung argumen kalibrasi
    construct validity dan fenomena temporal decay.
    """
    evaluable = 0
    correct = 0
    classified_malicious = 0
    gt_malicious = 0
    gt_legitimate = 0
    zero_score = 0
    details = []
    for alert in alerts:
        original_ip = alert.get("_original_dest_ip", alert.get("dest_ip", ""))
        abuse_score = alert.get("abuseipdb", {}).get("abuseConfidenceScore", -1)
        g = gt.get(original_ip)
        if abuse_score == 0:
            zero_score += 1
        if g is None:
            continue
        evaluable += 1
        label = g["label"]
        is_mal = abuse_score >= score_threshold
        if is_mal:
            classified_malicious += 1
        if label == "malicious":
            gt_malicious += 1
            ok = is_mal
        elif label == "legitimate":
            gt_legitimate += 1
            ok = not is_mal
        else:
            ok = False
        if ok:
            correct += 1
        details.append({
            "original_ip": original_ip,
            "dest_ip_substituted": alert.get("dest_ip"),
            "gt_label": label,
            "abuse_score": abuse_score,
            "classified_malicious": is_mal,
            "is_correct": ok,
        })
    acc = correct / evaluable if evaluable > 0 else 0
    return {
        "note": "TEMUAN, bukan metrik evaluasi utama. Enrichment Accuracy (eks M1-1) dihapus (sirkular).",
        "classification_accuracy_finding": round(acc, 4),
        "classification_accuracy_percent": round(acc * 100, 2),
        "evaluable_ips": evaluable,
        "gt_malicious": gt_malicious,
        "gt_legitimate": gt_legitimate,
        "classified_malicious": classified_malicious,
        "alerts_with_zero_score": zero_score,
        "detail": details,
    }


# === Main ===
def main():
    print("=" * 70)
    print("EVALUATOR — M-1 (Coverage), M-2 (Fidelity) + Kondisi Validitas")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    enriched_path = OUTPUT_DIR / "enriched_alerts.json"
    if not enriched_path.exists():
        logger.error(f"File tidak ditemukan: {enriched_path}")
        return None
    with open(enriched_path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "alerts" in data:
        alerts = data["alerts"]
        pipeline_stats = data.get("pipeline_stats", {})
    else:
        alerts = data
        pipeline_stats = {}
    logger.info(f"Loaded {len(alerts)} alert dari {enriched_path}")

    if not GROUND_TRUTH_PATH.exists():
        logger.error(f"Ground truth tidak ditemukan: {GROUND_TRUTH_PATH}")
        return None
    gt = load_ground_truth(GROUND_TRUTH_PATH)
    gt_malicious = sum(1 for v in gt.values() if v["label"] == "malicious")
    gt_legitimate = sum(1 for v in gt.values() if v["label"] == "legitimate")
    logger.info(f"Ground truth: {len(gt)} entri ({gt_malicious} malicious, {gt_legitimate} legitimate)")

    # Metrik utama + kondisi validitas + temuan
    print("\n[*] M-1 (MITRE Mapping Coverage)...")
    m1 = calc_m1_coverage(alerts)
    print("[*] M-2 (AI Summary Fidelity)...")
    m2 = calc_m2_fidelity(alerts)
    print("[*] Kondisi Validitas (Pipeline Coverage)...")
    validity = calc_validity_coverage(alerts)
    print("[*] Temuan enrichment (bukan metrik)...")
    enrichment = report_enrichment_finding(alerts, gt)

    print("\n" + "=" * 70)
    print("HASIL EVALUASI PIPELINE")
    print("=" * 70)
    print(f"\n  M-1  MITRE Mapping Coverage")
    print(f"       Nilai   : {m1['value_percent']}%  ({m1['mapping_valid']}/{m1['total_alerts']})")
    print(f"       Sumber  : {m1['mapping_sources']}")
    print(f"       Teknik  : {m1['technique_distribution']}")
    print(f"\n  M-2  AI Summary Fidelity")
    print(f"       Nilai   : {m2['value']:.4f} / 3.0000")
    print(f"       Avg D1  : {m2['avg_d1_factual']:.4f}  {m2['d1_distribution']}")
    print(f"       Avg D2  : {m2['avg_d2_completeness']:.4f}  {m2['d2_distribution']}")
    print(f"       Avg D3  : {m2['avg_d3_relevance']:.4f}  {m2['d3_distribution']}")
    print(f"\n  Kondisi Validitas — Pipeline Coverage")
    print(f"       Nilai   : {validity['value_percent']}%  ({validity['complete']}/{validity['total_alerts_in']})")
    print(f"       Per modul: {validity['per_module_complete']}")
    print(f"\n  [Temuan] Perilaku enrichment (bukan metrik)")
    print(f"       Akurasi klasifikasi vs GT : {enrichment['classification_accuracy_percent']}%"
          f"  ({enrichment['evaluable_ips']} IP evaluable)")
    print(f"       Alert skor nol            : {enrichment['alerts_with_zero_score']}"
          f"  (indikasi temporal decay bila pada IP asli)")

    print("\n" + "=" * 70)
    print("RINGKASAN AKHIR")
    print("=" * 70)
    print(f"  M-1 (MITRE Mapping Coverage) : {m1['value_percent']:>8}%")
    print(f"  M-2 (AI Summary Fidelity)    : {m2['value']:>8.4f} / 3.0")
    print(f"  Kondisi Validitas (Coverage) : {validity['value_percent']:>8}%")
    print("=" * 70)

    results = {
        "metadata": {
            "evaluated_at": datetime.now().isoformat(),
            "enriched_alerts_file": str(enriched_path),
            "ground_truth_file": str(GROUND_TRUTH_PATH),
            "ground_truth_stats": {
                "total_entries": len(gt),
                "malicious": gt_malicious,
                "legitimate": gt_legitimate,
            },
            "total_alerts_evaluated": len(alerts),
            "scheme": "2 metrik utama (M-1, M-2) + 1 kondisi validitas; enrichment sebagai temuan",
        },
        "metrics": {
            "m1_coverage": {k: v for k, v in m1.items() if k != "detail"},
            "m2_fidelity": {k: v for k, v in m2.items() if k != "detail"},
        },
        "validity_coverage": validity,
        "enrichment_finding": {k: v for k, v in enrichment.items() if k != "detail"},
        "detail": {
            "m1_per_alert": m1["detail"],
            "m2_per_alert": m2["detail"],
            "enrichment_per_alert": enrichment["detail"],
        },
        "summary": {
            "M-1_coverage_percent": m1["value_percent"],
            "M-2_fidelity": m2["value"],
            "validity_coverage_percent": validity["value_percent"],
        }
    }
    output_path = OUTPUT_DIR / "evaluation_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"Hasil evaluasi disimpan ke: {output_path}")
    return results


if __name__ == "__main__":
    main()
