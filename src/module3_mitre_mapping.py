#!/usr/bin/env python3
"""
Modul 3: Pemetaan MITRE ATT&CK Tiga Lapis (Versi Final)

Hierarki pemetaan (hasil diskusi dengan pembimbing):
  Lapis 1: Metadata pass-through (mitre_tactic_id, mitre_technique_id dari rule)
           Basis: ET Open Ruleset convention; pendukung Vasilakis et al. (2025)
  Lapis 2: classtype/category -> tactic TA0011
           Basis: Vasilakis et al. (2025); pendukung Winkler & Sharma (2025)
  Lapis 3: malware_family -> technique
           Basis: MITRE ATT&CK Software Catalog; pendukung Sheikhi et al. (2025)

Prinsip data-driven inclusion: tabel hanya memuat 9 entri yang
terdeteksi empiris pada dataset EarlyCrowAPT.

Input  : output/c2_alerts_enriched_abuseipdb.json  (output Modul 2)
Output : output/c2_alerts_enriched_mitre.json       (dibaca Modul 4)

Field 'mitre' pada output mengikuti struktur yang dibaca Modul 4:
  - tactic_ids        : list
  - tactic_names      : list
  - technique_ids     : list
  - technique_details : list of {id, name}
  - mapping_source    : string
"""

import json
import logging
import sys
from pathlib import Path
from datetime import datetime

# === Setup paths and logging ===
BASE_DIR = Path(__file__).parent.parent
OUTPUT_DIR = BASE_DIR / "output"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
log_file = LOG_DIR / f"module3_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


# ============================================================================
# TABEL LAPIS 2: Classtype / Category Suricata -> Tactic
# ============================================================================
CLASSTYPE_TO_TACTIC = {
    "command-and-control": ("TA0011", "Command and Control"),
    "malware-cnc": ("TA0011", "Command and Control"),
    "trojan-activity": ("TA0011", "Command and Control"),
    "Malware Command and Control Activity Detected": ("TA0011", "Command and Control"),
    "A Network Trojan was detected": ("TA0011", "Command and Control"),
}


# ============================================================================
# TABEL LAPIS 3: Malware Family -> Technique via MITRE Software Catalog
# Data-driven inclusion: 9 entri terdeteksi di dataset EarlyCrowAPT
# ============================================================================
MALWARE_TO_SOFTWARE = {
    "Emotet":      {"software_id": "S0367", "technique_id": "T1071.001", "technique_name": "Web Protocols",              "url": "https://attack.mitre.org/software/S0367/"},
    "Geodo":       {"software_id": "S0367", "technique_id": "T1071.001", "technique_name": "Web Protocols",              "url": "https://attack.mitre.org/software/S0367/", "alias_of": "Emotet"},
    "Ramnit":      {"software_id": "S0185", "technique_id": "T1071.001", "technique_name": "Web Protocols",              "url": "https://attack.mitre.org/software/S0185/"},
    "PoisonIvy":   {"software_id": "S0012", "technique_id": "T1071",     "technique_name": "Application Layer Protocol", "url": "https://attack.mitre.org/software/S0012/"},
    "njRAT":       {"software_id": "S0385", "technique_id": "T1071",     "technique_name": "Application Layer Protocol", "url": "https://attack.mitre.org/software/S0385/"},
    "Bladabindi":  {"software_id": "S0385", "technique_id": "T1071",     "technique_name": "Application Layer Protocol", "url": "https://attack.mitre.org/software/S0385/", "alias_of": "njRAT"},
    "Gozi":        {"software_id": "S0386", "technique_id": "T1071.001", "technique_name": "Web Protocols",              "url": "https://attack.mitre.org/software/S0386/"},
    "Sakula":      {"software_id": "S0074", "technique_id": "T1071",     "technique_name": "Application Layer Protocol", "url": "https://attack.mitre.org/software/S0074/"},
    "Mivast":      {"software_id": "S0074", "technique_id": "T1071",     "technique_name": "Application Layer Protocol", "url": "https://attack.mitre.org/software/S0074/", "alias_of": "Sakula"},
    "Mustang Panda": {"software_id": "G0129", "technique_id": "T1071",   "technique_name": "Application Layer Protocol", "url": "https://attack.mitre.org/groups/G0129/", "is_group_fallback": True},
}

KNOWN_MALWARE_LOWER = {k.lower(): k for k in MALWARE_TO_SOFTWARE.keys()}

TACTIC_NAME = {"TA0011": "Command and Control", "TA0010": "Exfiltration"}


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return [x for x in v if x not in (None, "")]
    if isinstance(v, str):
        return [v] if v else []
    return [v]


# ============================================================================
# LAYER 1: Metadata Pass-Through
# ============================================================================
def layer1_metadata(alert):
    tactic_ids = _as_list(alert.get("mitre_tactic_id"))
    technique_ids = _as_list(alert.get("mitre_technique_id"))
    if tactic_ids and technique_ids:
        return {
            "tactic_ids": tactic_ids,
            "tactic_names": [TACTIC_NAME.get(t, "Unknown") for t in tactic_ids],
            "technique_ids": technique_ids,
            "technique_details": [{"id": t, "name": "From rule metadata"} for t in technique_ids],
        }
    return None


# ============================================================================
# LAYER 2: Classtype/Category -> Tactic
# ============================================================================
def layer2_classtype(alert):
    for field in ("category", "classtype"):
        val = alert.get(field, "")
        if val in CLASSTYPE_TO_TACTIC:
            tid, tname = CLASSTYPE_TO_TACTIC[val]
            return {"tactic_id": tid, "tactic_name": tname}
    return None


# ============================================================================
# LAYER 3: Malware Family -> Technique
# ============================================================================
def _normalize(name):
    return str(name).lower().replace("_", " ").strip()


def extract_malware_family(alert):
    # Sumber 1: field malware_family
    for name in _as_list(alert.get("malware_family")):
        nm = str(name).strip()
        if nm in MALWARE_TO_SOFTWARE:
            return ("malware_family_field", nm)
        norm = _normalize(nm)
        if norm in KNOWN_MALWARE_LOWER:
            return ("malware_family_field", KNOWN_MALWARE_LOWER[norm])
    # Sumber 2: pattern matching pada signature
    sig = _normalize(alert.get("signature", ""))
    for mw_lower, mw_orig in KNOWN_MALWARE_LOWER.items():
        if mw_lower in sig:
            return ("signature_pattern", mw_orig)
    return (None, None)


def layer3_malware(alert):
    source, mw = extract_malware_family(alert)
    if not mw:
        return None
    sw = MALWARE_TO_SOFTWARE.get(mw)
    if not sw:
        return None
    return {
        "technique_id": sw["technique_id"],
        "technique_name": sw["technique_name"],
        "software_id": sw["software_id"],
        "malware_matched": mw,
        "extraction_source": source,
        "reference_url": sw["url"],
        "is_group_fallback": sw.get("is_group_fallback", False),
    }


# ============================================================================
# ORCHESTRATOR per alert
# ============================================================================
def map_mitre_for_alert(alert):
    """Kembalikan objek 'mitre' lengkap untuk satu alert."""
    mitre = {
        "tactic_ids": [],
        "tactic_names": [],
        "technique_ids": [],
        "technique_details": [],
        "mapping_source": "unmapped",
        "has_original_mitre": False,
    }

    # --- Layer 1 ---
    l1 = layer1_metadata(alert)
    if l1:
        mitre.update(l1)
        mitre["mapping_source"] = "layer1_metadata"
        mitre["has_original_mitre"] = True
        return mitre

    # --- Layer 2 + Layer 3 (komplementer) ---
    sources = []

    l2 = layer2_classtype(alert)
    if l2:
        mitre["tactic_ids"] = [l2["tactic_id"]]
        mitre["tactic_names"] = [l2["tactic_name"]]
        sources.append("layer2_classtype")

    l3 = layer3_malware(alert)
    if l3:
        mitre["technique_ids"] = [l3["technique_id"]]
        mitre["technique_details"] = [{"id": l3["technique_id"], "name": l3["technique_name"]}]
        mitre["software_id"] = l3["software_id"]
        mitre["malware_matched"] = l3["malware_matched"]
        mitre["reference_url"] = l3["reference_url"]
        if l3["is_group_fallback"]:
            mitre["group_level_fallback"] = True
        if l3["extraction_source"] == "malware_family_field":
            sources.append("layer3_malware_family")
        else:
            sources.append("layer3_signature_pattern")

    if sources:
        mitre["mapping_source"] = " + ".join(sources)

    return mitre


# ============================================================================
# Fungsi untuk dipanggil pipeline.py (kompatibilitas)
# ============================================================================
def enrich_alerts_with_mitre(alerts):
    """Terima list alert, kembalikan list alert + field 'mitre'."""
    enriched = []
    for alert in alerts:
        mitre = map_mitre_for_alert(alert)
        new_alert = {**alert, "mitre": mitre}
        enriched.append(new_alert)
    return enriched


def get_mitre_summary(enriched_alerts):
    total = len(enriched_alerts)
    with_tactic = sum(1 for a in enriched_alerts if a["mitre"]["tactic_ids"])
    with_technique = sum(1 for a in enriched_alerts if a["mitre"]["technique_ids"])
    source_dist = {}
    technique_dist = {}
    for a in enriched_alerts:
        src = a["mitre"]["mapping_source"]
        source_dist[src] = source_dist.get(src, 0) + 1
        for tid in a["mitre"]["technique_ids"]:
            technique_dist[tid] = technique_dist.get(tid, 0) + 1
    return {
        "total_alerts": total,
        "mapped_with_tactic": with_tactic,
        "mapped_with_technique": with_technique,
        "tactic_coverage_pct": round(with_tactic / total * 100, 1) if total else 0,
        "technique_coverage_pct": round(with_technique / total * 100, 1) if total else 0,
        "source_distribution": source_dist,
        "technique_distribution": technique_dist,
    }


# ============================================================================
# MAIN (standalone)
# ============================================================================
def main():
    input_path = OUTPUT_DIR / "c2_alerts_enriched_abuseipdb.json"
    output_path = OUTPUT_DIR / "c2_alerts_enriched_mitre.json"
    summary_path = OUTPUT_DIR / "module3_summary.json"

    print("=" * 70)
    print("MODULE 3: PEMETAAN MITRE ATT&CK TIGA LAPIS")
    print(f"Waktu: {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 70)

    if not input_path.exists():
        logger.error(f"File tidak ditemukan: {input_path}")
        sys.exit(1)

    with open(input_path) as f:
        alerts = json.load(f)
    if isinstance(alerts, dict):
        alerts = alerts.get("alerts", list(alerts.values()))

    logger.info(f"Loaded {len(alerts)} alert dari {input_path.name}")

    enriched = enrich_alerts_with_mitre(alerts)
    summary = get_mitre_summary(enriched)

    with open(output_path, "w") as f:
        json.dump(enriched, f, indent=2)
    logger.info(f"Output disimpan ke: {output_path}")

    summary["timestamp"] = datetime.now().isoformat()
    summary["input_file"] = input_path.name
    summary["output_file"] = output_path.name
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Summary disimpan ke: {summary_path}")

    total = summary["total_alerts"]
    print()
    print("=" * 70)
    print("RINGKASAN MODULE 3")
    print("=" * 70)
    print(f"Total alert            : {total}")
    print(f"Mapped tactic          : {summary['mapped_with_tactic']} ({summary['tactic_coverage_pct']}%)")
    print(f"Mapped technique       : {summary['mapped_with_technique']} ({summary['technique_coverage_pct']}%)")
    print()
    print("Distribusi mapping_source:")
    for src, n in sorted(summary["source_distribution"].items(), key=lambda x: -x[1]):
        print(f"  {src:<48}: {n:3d} ({n/total*100:5.1f}%)")
    print()
    print("Distribusi technique:")
    for tid, n in sorted(summary["technique_distribution"].items(), key=lambda x: -x[1]):
        print(f"  {tid:<48}: {n:3d}")
    print("=" * 70)


if __name__ == "__main__":
    main()
