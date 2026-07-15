"""
Module 2: AbuseIPDB Enrichment.

Fungsi:
- Query reputasi setiap unique dest_ip ke AbuseIPDB API
- Caching: 1 IP hanya di-query 1 kali
- Rate limiting: 1 detik antar request
- Retry: max 3x jika gagal
- Output: alert C2 yang sudah diperkaya data reputasi IP

Metrik terkait: M1-1 (Enrichment Accuracy Rate)
"""

import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import *

# === Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "module2.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def query_abuseipdb(ip_address, max_retries=3):
    """
    Query satu IP ke AbuseIPDB API.
    
    Args:
        ip_address: IP yang akan dicek
        max_retries: jumlah retry jika gagal
    
    Returns:
        dict: data reputasi IP, atau dict dengan error info
    """
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS,
        "verbose": ""
    }
    
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(
                ABUSEIPDB_BASE_URL,
                headers=headers,
                params=params,
                timeout=15
            )
            
            # Rate limit hit
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 60))
                logger.warning(f"  Rate limit hit untuk {ip_address}, tunggu {wait}s...")
                time.sleep(wait)
                continue
            
            r.raise_for_status()
            data = r.json().get("data", {})
            
            return {
                "ip": ip_address,
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "numDistinctUsers": data.get("numDistinctUsers", 0),
                "isPublic": data.get("isPublic", True),
                "isWhitelisted": data.get("isWhitelisted", False),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "usageType": data.get("usageType", ""),
                "countryCode": data.get("countryCode", ""),
                "countryName": data.get("countryName", ""),
                "isTor": data.get("isTor", False),
                "lastReportedAt": data.get("lastReportedAt", ""),
                "query_status": "success",
                "query_timestamp": datetime.now().isoformat()
            }
            
        except requests.exceptions.Timeout:
            logger.warning(f"  Timeout untuk {ip_address} (attempt {attempt}/{max_retries})")
            time.sleep(2)
        except requests.exceptions.HTTPError as e:
            logger.error(f"  HTTP error untuk {ip_address}: {e}")
            if attempt == max_retries:
                return {
                    "ip": ip_address,
                    "abuseConfidenceScore": -1,
                    "query_status": f"http_error:{r.status_code}",
                    "query_timestamp": datetime.now().isoformat()
                }
            time.sleep(2)
        except Exception as e:
            logger.error(f"  Error untuk {ip_address}: {e}")
            if attempt == max_retries:
                return {
                    "ip": ip_address,
                    "abuseConfidenceScore": -1,
                    "query_status": f"error:{str(e)[:50]}",
                    "query_timestamp": datetime.now().isoformat()
                }
            time.sleep(2)
    
    return {
        "ip": ip_address,
        "abuseConfidenceScore": -1,
        "query_status": "max_retries_exceeded",
        "query_timestamp": datetime.now().isoformat()
    }


def enrich_alerts_with_abuseipdb(alerts):
    """
    Enrich semua alert dengan data AbuseIPDB.
    Menggunakan cache agar setiap IP hanya di-query 1 kali.
    
    Args:
        alerts: list[dict] dari Module 1 (c2_alerts_deduped)
    
    Returns:
        list[dict]: alert yang sudah diperkaya data reputasi
    """
    # === Kumpulkan unique dest IPs ===
    unique_ips = list(set(a["dest_ip"] for a in alerts if a.get("dest_ip")))
    logger.info(f"Unique destination IPs: {len(unique_ips)}")
    
    # === Cek cache yang sudah ada ===
    cache_path = OUTPUT_DIR / "abuseipdb_cache.json"
    ip_cache = {}
    if CACHE_ABUSEIPDB and cache_path.exists():
        with open(cache_path) as f:
            ip_cache = json.load(f)
        logger.info(f"Cache loaded: {len(ip_cache)} IPs dari file sebelumnya")
    
    # === Query setiap IP ===
    ips_to_query = [ip for ip in unique_ips if ip not in ip_cache]
    logger.info(f"IPs perlu di-query: {len(ips_to_query)} (cached: {len(unique_ips) - len(ips_to_query)})")
    
    for i, ip in enumerate(ips_to_query, 1):
        print(f"  [{i:02d}/{len(ips_to_query)}] Querying {ip} ... ", end="", flush=True)
        
        t0 = time.perf_counter()
        result = query_abuseipdb(ip)
        result["query_duration_seconds"] = round(time.perf_counter() - t0, 3)
        ip_cache[ip] = result
        
        score = result.get("abuseConfidenceScore", -1)
        reports = result.get("totalReports", 0)
        status = result.get("query_status", "unknown")
        
        if status == "success":
            print(f"score={score}, reports={reports}")
        else:
            print(f"GAGAL ({status})")
        
        # Rate limit delay
        if i < len(ips_to_query):
            time.sleep(ABUSEIPDB_RATE_LIMIT)
    
    # === Simpan cache ===
    with open(cache_path, "w") as f:
        json.dump(ip_cache, f, indent=2)
    logger.info(f"Cache disimpan ke: {cache_path}")
    
    # === Timing summary (Performance Impact) ===
    durations = [v["query_duration_seconds"] for v in ip_cache.values()
                 if "query_duration_seconds" in v]
    if durations:
        timing = {
            "ip_queried": len(durations),
            "mean_seconds": round(sum(durations) / len(durations), 3),
            "min_seconds": round(min(durations), 3),
            "max_seconds": round(max(durations), 3),
            "note": "Durasi query API murni, tidak termasuk jeda rate limit antar request."
        }
        with open(OUTPUT_DIR / "module2_timing.json", "w") as f:
            json.dump(timing, f, indent=2)
        logger.info(f"[TIMING] AbuseIPDB: mean={timing['mean_seconds']}s per IP (n={timing['ip_queried']})")
    
    # === Enrich setiap alert dengan data AbuseIPDB ===
    enriched_alerts = []
    for alert in alerts:
        dest_ip = alert.get("dest_ip", "")
        abuse_data = ip_cache.get(dest_ip, {})
        
        enriched = {**alert}  # Copy semua field asli
        enriched["abuseipdb"] = {
            "abuseConfidenceScore": abuse_data.get("abuseConfidenceScore", -1),
            "totalReports": abuse_data.get("totalReports", 0),
            "numDistinctUsers": abuse_data.get("numDistinctUsers", 0),
            "isWhitelisted": abuse_data.get("isWhitelisted", False),
            "isp": abuse_data.get("isp", ""),
            "domain": abuse_data.get("domain", ""),
            "usageType": abuse_data.get("usageType", ""),
            "countryCode": abuse_data.get("countryCode", ""),
            "countryName": abuse_data.get("countryName", ""),
            "isTor": abuse_data.get("isTor", False),
            "lastReportedAt": abuse_data.get("lastReportedAt", ""),
            "query_status": abuse_data.get("query_status", "not_queried"),
        }
        enriched_alerts.append(enriched)
    
    return enriched_alerts


def get_enrichment_summary(enriched_alerts):
    """Buat ringkasan hasil enrichment."""
    scores = [a["abuseipdb"]["abuseConfidenceScore"] 
              for a in enriched_alerts 
              if a["abuseipdb"]["abuseConfidenceScore"] >= 0]
    
    success = sum(1 for a in enriched_alerts if a["abuseipdb"]["query_status"] == "success")
    failed = sum(1 for a in enriched_alerts if a["abuseipdb"]["query_status"] != "success")
    
    score_0 = sum(1 for s in scores if s == 0)
    score_1_50 = sum(1 for s in scores if 1 <= s <= 50)
    score_51_99 = sum(1 for s in scores if 51 <= s <= 99)
    score_100 = sum(1 for s in scores if s == 100)
    
    # Unique IPs dan distribusi score per IP
    ip_scores = {}
    for a in enriched_alerts:
        ip = a["dest_ip"]
        score = a["abuseipdb"]["abuseConfidenceScore"]
        if ip not in ip_scores and score >= 0:
            ip_scores[ip] = score
    
    return {
        "total_alerts_enriched": len(enriched_alerts),
        "query_success": success,
        "query_failed": failed,
        "unique_ips_queried": len(ip_scores),
        "score_distribution": {
            "score_0": score_0,
            "score_1_50": score_1_50,
            "score_51_99": score_51_99,
            "score_100": score_100,
        },
        "avg_score": round(sum(scores) / len(scores), 2) if scores else 0,
        "ip_scores": ip_scores
    }


def main():
    """Main function - load alerts, enrich, simpan."""
    print("=" * 70)
    print("MODULE 2: ABUSEIPDB ENRICHMENT")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # Step 1: Load alert dari Module 1
    input_path = OUTPUT_DIR / "c2_alerts_deduped.json"
    if not input_path.exists():
        logger.error(f"File tidak ditemukan: {input_path}")
        logger.error("Jalankan Module 1 terlebih dahulu!")
        return None
    
    with open(input_path) as f:
        alerts = json.load(f)
    logger.info(f"Loaded {len(alerts)} alert dari {input_path}")
    
    # Step 2: Enrich dengan AbuseIPDB
    print()
    enriched = enrich_alerts_with_abuseipdb(alerts)
    
    # Step 3: Ringkasan
    summary = get_enrichment_summary(enriched)
    
    print("\n" + "=" * 70)
    print("RINGKASAN MODULE 2")
    print("=" * 70)
    print(f"  Total alert enriched  : {summary['total_alerts_enriched']}")
    print(f"  Query success         : {summary['query_success']}")
    print(f"  Query failed          : {summary['query_failed']}")
    print(f"  Unique IPs queried    : {summary['unique_ips_queried']}")
    print(f"  Average abuse score   : {summary['avg_score']}")
    
    print(f"\n  Distribusi abuseConfidenceScore:")
    print(f"    Score = 0           : {summary['score_distribution']['score_0']} alert")
    print(f"    Score 1-50          : {summary['score_distribution']['score_1_50']} alert")
    print(f"    Score 51-99         : {summary['score_distribution']['score_51_99']} alert")
    print(f"    Score = 100         : {summary['score_distribution']['score_100']} alert")
    
    print(f"\n  Detail per IP:")
    for ip, score in sorted(summary["ip_scores"].items(), key=lambda x: -x[1]):
        label = "MALICIOUS" if score >= 50 else "LOW" if score > 0 else "CLEAN/UNKNOWN"
        print(f"    {ip:<20s} score={score:>3d}  [{label}]")
    
    print("=" * 70)
    
    # Step 4: Simpan
    output_path = OUTPUT_DIR / "c2_alerts_enriched_abuseipdb.json"
    with open(output_path, "w") as f:
        json.dump(enriched, f, indent=2, default=str)
    logger.info(f"Alert enriched disimpan ke: {output_path}")
    
    summary_path = OUTPUT_DIR / "module2_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Summary disimpan ke: {summary_path}")
    
    return enriched


if __name__ == "__main__":
    main()
