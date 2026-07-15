"""
Tahap 2 — Substitusi IP: Ambil kandidat IP baru dari AbuseIPDB blacklist API.

Input  : - (langsung query API)
Output : output/abuseipdb_candidates.json

Strategi:
- Query endpoint /api/v2/blacklist dengan confidence minimum 75
- Limit 1000 IP (free tier biasanya allow ini)
- Untuk setiap kandidat, ambil detail via /api/v2/check
- Filter berdasarkan kategori reports yang relevan dengan C2/malware/botnet

AbuseIPDB report categories yang relevan untuk C2:
- 4: DDoS Attack
- 9: Open Proxy
- 14: Port Scan
- 15: Hacking
- 18: Brute-Force
- 19: Bad Web Bot
- 20: Exploited Host  ← C2 victim
- 21: Web App Attack
- 22: SSH
- 23: IoT Targeted
"""

import sys
import os
import json
import time
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import *

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Kategori AbuseIPDB yang relevan untuk C2/malware
RELEVANT_CATEGORIES = {
    4: "DDoS Attack",
    9: "Open Proxy",
    14: "Port Scan",
    15: "Hacking",
    20: "Exploited Host",
    21: "Web App Attack",
    23: "IoT Targeted",
}


def get_blacklist(api_key, confidence_min=75, limit=1000):
    """Query AbuseIPDB blacklist endpoint."""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {
        "confidenceMinimum": confidence_min,
        "limit": limit
    }
    
    logger.info(f"Querying AbuseIPDB blacklist (min conf: {confidence_min}, limit: {limit})...")
    
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('data', [])
        else:
            logger.error(f"API error {resp.status_code}: {resp.text[:200]}")
            return []
    except Exception as e:
        logger.error(f"Exception: {e}")
        return []


def check_ip_detail(api_key, ip):
    """Get detail report untuk satu IP."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }
    
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 200:
            return resp.json().get('data', {})
        else:
            logger.warning(f"  Failed to get detail for {ip}: {resp.status_code}")
            return None
    except Exception as e:
        logger.warning(f"  Exception getting {ip}: {e}")
        return None


def main():
    print("=" * 80)
    print("TAHAP 2 — AMBIL KANDIDAT IP BARU DARI ABUSEIPDB")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        logger.error("ABUSEIPDB_API_KEY tidak ditemukan di .env")
        return None
    
    # Step 1: Ambil blacklist
    print("\n[1/2] Mengambil blacklist...")
    blacklist = get_blacklist(api_key, confidence_min=75, limit=1000)
    
    if not blacklist:
        logger.error("Tidak ada IP yang dikembalikan dari blacklist")
        return None
    
    logger.info(f"Berhasil ambil {len(blacklist)} IP dari blacklist")
    
    # Step 2: Filter dan kelompokkan berdasarkan country/usage
    candidates = []
    for ip_data in blacklist:
        candidates.append({
            "ip": ip_data.get('ipAddress', ''),
            "abuse_score": ip_data.get('abuseConfidenceScore', 0),
            "country_code": ip_data.get('countryCode', ''),
            "last_reported_at": ip_data.get('lastReportedAt', ''),
        })
    
    # Step 3: Tampilkan top 30 untuk preview
    print(f"\n[2/2] Top 30 IP kandidat (sorted by score):")
    print(f"{'No':<4}{'IP':<20}{'Score':<8}{'Country':<10}{'Last Reported'}")
    print("-" * 70)
    
    sorted_candidates = sorted(candidates, key=lambda x: -x['abuse_score'])
    for i, c in enumerate(sorted_candidates[:30], 1):
        last = c['last_reported_at'][:10] if c['last_reported_at'] else 'N/A'
        print(f"{i:<4}{c['ip']:<20}{c['abuse_score']:<8}{c['country_code']:<10}{last}")
    
    # Step 4: Distribusi country
    country_count = {}
    for c in candidates:
        cc = c['country_code']
        country_count[cc] = country_count.get(cc, 0) + 1
    
    print(f"\n=== Distribusi Country (top 15) ===")
    sorted_countries = sorted(country_count.items(), key=lambda x: -x[1])[:15]
    for cc, count in sorted_countries:
        print(f"  {cc:<5}: {count} IP")
    
    # Step 5: Distribusi score
    score_buckets = {"75-80": 0, "81-90": 0, "91-99": 0, "100": 0}
    for c in candidates:
        s = c['abuse_score']
        if s == 100:
            score_buckets["100"] += 1
        elif s >= 91:
            score_buckets["91-99"] += 1
        elif s >= 81:
            score_buckets["81-90"] += 1
        else:
            score_buckets["75-80"] += 1
    
    print(f"\n=== Distribusi Score ===")
    for bucket, count in score_buckets.items():
        print(f"  Score {bucket}: {count} IP")
    
    # Step 6: Save
    output = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "source": "AbuseIPDB Blacklist API",
            "confidence_minimum": 75,
            "total_candidates": len(candidates),
            "country_distribution": dict(sorted_countries),
            "score_distribution": score_buckets,
        },
        "candidates": sorted_candidates
    }
    
    output_path = OUTPUT_DIR / "abuseipdb_candidates.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    
    logger.info(f"Output disimpan ke: {output_path}")
    
    print("\n" + "=" * 80)
    print(f"✅ Total kandidat: {len(candidates)} IP aktif di AbuseIPDB")
    print(f"   File tersimpan: {output_path}")
    print(f"   File size: {output_path.stat().st_size / 1024:.1f} KB")
    print("=" * 80)
    print("\nLangkah selanjutnya: Tahap 3 (cocokkan otomatis IP lama dengan kandidat baru)")
    
    return output


if __name__ == "__main__":
    main()
