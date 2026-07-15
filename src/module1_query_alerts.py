"""
Module 1: Query Alert C2 dari OpenSearch/Wazuh Indexer.

Fungsi:
- Query alert Suricata berkategori C2 dari OpenSearch
- Ekstrak field penting per alert
- Deduplikasi berdasarkan kombinasi (src_ip, dest_ip, signature_id)
- Output: list dict alert C2 terstruktur

Catatan teknis:
- Menggunakan scroll API karena hasil > 10.000 dokumen
- Category filter: "Malware Command and Control Activity Detected"
- Field metadata MITRE diekstrak jika tersedia (hanya 0.2% alert)
"""

import sys
import json
import logging
from datetime import datetime
from pathlib import Path

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import *

# === Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "module1.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Konstanta ===
AUTH = (WAZUH_USER, WAZUH_PASS)
HEADERS = {"Content-Type": "application/json"}
SCROLL_SIZE = 5000
SCROLL_TIMEOUT = "5m"


def build_c2_query(category_filter="strict"):
    """
    Bangun query OpenSearch untuk alert C2.
    
    Args:
        category_filter: "strict" = hanya C2 category
                        "broad"  = C2 + Trojan + C2 Domain
    """
    if category_filter == "strict":
        query = {
            "bool": {
                "must": [
                    {"match": {"rule.groups": "suricata"}},
                    {"match_phrase": {
                        "data.alert.category": "Malware Command and Control Activity Detected"
                    }}
                ]
            }
        }
    else:  # broad
        query = {
            "bool": {
                "must": [{"match": {"rule.groups": "suricata"}}],
                "should": [
                    {"match_phrase": {"data.alert.category": "Malware Command and Control Activity Detected"}},
                    {"match_phrase": {"data.alert.category": "A Network Trojan was detected"}},
                    {"match_phrase": {"data.alert.category": "Domain Observed Used for C2 Detected"}}
                ],
                "minimum_should_match": 1
            }
        }
    return query


def extract_alert_fields(hit):
    """Ekstrak field penting dari satu dokumen OpenSearch."""
    source = hit.get("_source", {})
    data = source.get("data", {})
    alert_data = data.get("alert", {})
    metadata = alert_data.get("metadata", {})
    rule = source.get("rule", {})

    return {
        # === Identifikasi ===
        "opensearch_id": hit.get("_id", ""),
        "timestamp": data.get("timestamp", ""),
        
        # === Network ===
        "src_ip": data.get("src_ip", ""),
        "dest_ip": data.get("dest_ip", ""),
        "src_port": data.get("src_port", ""),
        "dest_port": data.get("dest_port", ""),
        "proto": data.get("proto", ""),
        
        # === Alert Info ===
        "signature": alert_data.get("signature", ""),
        "signature_id": alert_data.get("signature_id", ""),
        "category": alert_data.get("category", ""),
        "severity": alert_data.get("severity", ""),
        
        # === MITRE Metadata (jika ada) ===
        "mitre_tactic_id": metadata.get("mitre_tactic_id", []),
        "mitre_technique_id": metadata.get("mitre_technique_id", []),
        
        # === Rule Metadata Tambahan ===
        "malware_family": metadata.get("malware_family", []),
        "signature_severity": metadata.get("signature_severity", []),
        "confidence": metadata.get("confidence", []),
        "attack_target": metadata.get("attack_target", []),
        "affected_product": metadata.get("affected_product", []),
        "deployment": metadata.get("deployment", []),
        
        # === Wazuh Rule ===
        "wazuh_rule_description": rule.get("description", ""),
        "wazuh_rule_level": rule.get("level", ""),
    }


def query_c2_alerts(category_filter="strict", max_alerts=None):
    """
    Query semua alert C2 dari OpenSearch menggunakan scroll API.
    
    Args:
        category_filter: "strict" atau "broad"
        max_alerts: batasi jumlah alert (None = semua)
    
    Returns:
        list[dict]: alert C2 terstruktur
    """
    query = build_c2_query(category_filter)
    
    logger.info(f"Memulai query alert C2 (filter={category_filter})")
    logger.info(f"OpenSearch: {WAZUH_HOST}")
    
    # === Initial scroll request ===
    try:
        r = requests.post(
            f"{WAZUH_HOST}/{WAZUH_INDEX_PATTERN}/_search?scroll={SCROLL_TIMEOUT}",
            auth=AUTH, verify=False, timeout=60,
            headers=HEADERS,
            json={
                "size": SCROLL_SIZE,
                "query": query,
                "track_total_hits": True,
                "sort": [{"data.timestamp": {"order": "asc"}}],
                "_source": [
                    "data.alert.*", "data.src_ip", "data.dest_ip",
                    "data.src_port", "data.dest_port", "data.proto",
                    "data.timestamp", "rule.description", "rule.level"
                ]
            }
        )
        r.raise_for_status()
    except Exception as e:
        logger.error(f"Query awal gagal: {e}")
        raise

    result = r.json()
    scroll_id = result.get("_scroll_id")
    total_hits = result["hits"]["total"]["value"]
    
    logger.info(f"Total alert C2 ditemukan: {total_hits:,}")
    
    if max_alerts:
        logger.info(f"Dibatasi ke: {max_alerts:,} alert")
    
    # === Kumpulkan semua hasil ===
    alerts = []
    hits = result["hits"]["hits"]
    
    while hits:
        for hit in hits:
            alert = extract_alert_fields(hit)
            alerts.append(alert)
            
            if max_alerts and len(alerts) >= max_alerts:
                break
        
        if max_alerts and len(alerts) >= max_alerts:
            break
        
        # Progress
        if len(alerts) % 10000 == 0:
            logger.info(f"  Progress: {len(alerts):,}/{total_hits:,} ({len(alerts)/total_hits*100:.1f}%)")
        
        # Scroll berikutnya
        try:
            r = requests.post(
                f"{WAZUH_HOST}/_search/scroll",
                auth=AUTH, verify=False, timeout=60,
                headers=HEADERS,
                json={"scroll": SCROLL_TIMEOUT, "scroll_id": scroll_id}
            )
            result = r.json()
            scroll_id = result.get("_scroll_id")
            hits = result.get("hits", {}).get("hits", [])
        except Exception as e:
            logger.warning(f"Scroll gagal: {e}")
            break
    
    # Bersihkan scroll
    try:
        requests.delete(
            f"{WAZUH_HOST}/_search/scroll",
            auth=AUTH, verify=False, timeout=10,
            headers=HEADERS,
            json={"scroll_id": scroll_id}
        )
    except:
        pass
    
    logger.info(f"Total alert diambil: {len(alerts):,}")
    return alerts


def deduplicate_alerts(alerts):
    """
    Deduplikasi alert berdasarkan kombinasi (src_ip, dest_ip, signature_id).
    Simpan alert pertama (earliest timestamp) per kombinasi.
    """
    seen = {}
    for alert in alerts:
        key = (alert["src_ip"], alert["dest_ip"], str(alert["signature_id"]))
        if key not in seen:
            seen[key] = alert
    
    deduped = list(seen.values())
    logger.info(f"Deduplikasi: {len(alerts):,} -> {len(deduped):,} alert unik")
    return deduped


def get_alert_summary(alerts):
    """Buat ringkasan statistik dari alert."""
    unique_src = len(set(a["src_ip"] for a in alerts))
    unique_dest = len(set(a["dest_ip"] for a in alerts))
    unique_sig = len(set(str(a["signature_id"]) for a in alerts))
    has_mitre = sum(1 for a in alerts if a["mitre_tactic_id"])
    
    categories = {}
    for a in alerts:
        cat = a["category"]
        categories[cat] = categories.get(cat, 0) + 1
    
    malware_families = {}
    for a in alerts:
        for fam in a.get("malware_family", []):
            malware_families[fam] = malware_families.get(fam, 0) + 1
    
    return {
        "total_alerts": len(alerts),
        "unique_src_ips": unique_src,
        "unique_dest_ips": unique_dest,
        "unique_signatures": unique_sig,
        "alerts_with_mitre": has_mitre,
        "category_distribution": categories,
        "malware_families": dict(sorted(malware_families.items(), key=lambda x: -x[1])[:20])
    }


def save_alerts(alerts, filename="c2_alerts_raw.json"):
    """Simpan alert ke file JSON."""
    output_path = OUTPUT_DIR / filename
    with open(output_path, "w") as f:
        json.dump(alerts, f, indent=2, default=str)
    logger.info(f"Alert disimpan ke: {output_path}")
    return output_path


def main():
    """Main function - query, deduplikasi, simpan."""
    print("=" * 70)
    print("MODULE 1: QUERY ALERT C2 DARI OPENSEARCH")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # Step 1: Query alert C2
    alerts_raw = query_c2_alerts(
        category_filter="strict",
        max_alerts=MAX_ALERTS
    )
    
    if not alerts_raw:
        logger.error("Tidak ada alert C2 ditemukan!")
        return None
    
    # Step 2: Deduplikasi
    alerts_deduped = deduplicate_alerts(alerts_raw)
    
    # Step 3: Ringkasan
    summary = get_alert_summary(alerts_deduped)
    
    print("\n" + "=" * 70)
    print("RINGKASAN MODULE 1")
    print("=" * 70)
    print(f"  Alert C2 raw          : {len(alerts_raw):,}")
    print(f"  Alert C2 deduplikasi  : {len(alerts_deduped):,}")
    print(f"  Unique source IPs     : {summary['unique_src_ips']}")
    print(f"  Unique dest IPs       : {summary['unique_dest_ips']}")
    print(f"  Unique signatures     : {summary['unique_signatures']}")
    print(f"  Alert dengan MITRE    : {summary['alerts_with_mitre']}")
    
    if summary["malware_families"]:
        print(f"\n  Malware families terdeteksi:")
        for fam, count in list(summary["malware_families"].items())[:10]:
            print(f"    {count:>5,}  {fam}")
    
    print("=" * 70)
    
    # Step 4: Simpan
    save_alerts(alerts_raw, "c2_alerts_raw.json")
    save_alerts(alerts_deduped, "c2_alerts_deduped.json")
    
    # Simpan summary
    summary_path = OUTPUT_DIR / "module1_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Summary disimpan ke: {summary_path}")
    
    return alerts_deduped


if __name__ == "__main__":
    main()
