"""
Tahap 3 — Substitusi IP: Cocokkan IP lama dengan kandidat baru.

Input  : - output/ip_old_profile.json (26 IP lama)
         - output/abuseipdb_candidates.json (1000 IP kandidat)
Output : - output/ip_substitution_draft.json (mapping draft untuk verifikasi)

Strategi matching:
1. Untuk setiap IP lama, cari kandidat yang country-nya sama
2. Enrich top 3 kandidat per IP dengan /api/v2/check untuk dapat usage type
3. Score matching:
   - Country exact match: +30
   - Usage type "Data Center/Web Hosting" match: +40
   - Abuse score / 10: +0..10
   - Bonus jika ISP serupa: +20
4. Pilih kandidat dengan total score tertinggi
5. Setiap IP pengganti hanya dipakai 1 kali (1:1 mapping)

Estimasi API call: ~26 IP lama × 3 detail check = 78 calls
                    + jika kurang country match, fallback ke any country
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


def check_ip_detail(api_key, ip):
    """Get detail report untuk satu IP via /api/v2/check."""
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
            return None
    except Exception as e:
        logger.warning(f"  Exception: {e}")
        return None


def calculate_match_score(old_profile, candidate_detail):
    """
    Hitung skor matching antara IP lama dan kandidat baru.
    Higher score = better match.
    """
    score = 0
    reasons = []
    
    old_country = old_profile['old_abuseipdb']['country_code']
    old_usage = old_profile['old_abuseipdb']['usage_type']
    old_isp = old_profile['old_abuseipdb']['isp'].lower() if old_profile['old_abuseipdb']['isp'] else ''
    
    new_country = candidate_detail.get('countryCode', '')
    new_usage = candidate_detail.get('usageType', '')
    new_isp = candidate_detail.get('isp', '').lower() if candidate_detail.get('isp') else ''
    new_score = candidate_detail.get('abuseConfidenceScore', 0)
    
    # 1. Country match (+30)
    if old_country == new_country:
        score += 30
        reasons.append(f"country match ({new_country})")
    
    # 2. Usage type match (+40) - paling penting
    if old_usage and new_usage and old_usage == new_usage:
        score += 40
        reasons.append(f"usage match ({new_usage[:30]})")
    elif old_usage and new_usage and "Data Center" in old_usage and "Data Center" in new_usage:
        score += 30
        reasons.append("both Data Center")
    
    # 3. Abuse score contribution
    score += new_score / 10
    
    # 4. ISP keyword overlap (+20)
    if old_isp and new_isp:
        old_words = set(old_isp.split())
        new_words = set(new_isp.split())
        overlap = old_words & new_words
        if overlap and len(overlap) > 0:
            score += 20
            reasons.append(f"ISP overlap: {','.join(overlap)}")
    
    return score, reasons


def main():
    print("=" * 80)
    print("TAHAP 3 — MATCHING OTOMATIS IP LAMA → IP BARU")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        logger.error("ABUSEIPDB_API_KEY tidak ditemukan di .env")
        return None
    
    # Step 1: Load profile dan candidates
    with open(OUTPUT_DIR / "ip_old_profile.json") as f:
        old_data = json.load(f)
    
    with open(OUTPUT_DIR / "abuseipdb_candidates.json") as f:
        cand_data = json.load(f)
    
    old_profiles = old_data['ip_profiles']
    candidates = cand_data['candidates']
    
    logger.info(f"Loaded {len(old_profiles)} IP lama dan {len(candidates)} kandidat")
    
    # Step 2: Group candidates by country untuk pencarian cepat
    cands_by_country = {}
    for c in candidates:
        cc = c['country_code']
        if cc not in cands_by_country:
            cands_by_country[cc] = []
        cands_by_country[cc].append(c)
    
    # Step 3: Untuk setiap IP lama, cari kandidat terbaik
    print(f"\n=== Matching 26 IP lama dengan kandidat baru ===\n")
    
    used_new_ips = set()
    mapping = []
    api_calls = 0
    
    for i, old in enumerate(old_profiles, 1):
        old_ip = old['old_ip']
        old_country = old['old_abuseipdb']['country_code']
        old_usage = old['old_abuseipdb']['usage_type']
        primary_malware = old['malware_families'][0] if old['malware_families'] else 'Unknown'
        
        print(f"[{i:02d}/26] {old_ip} ({primary_malware}, {old_country}, {old_usage[:20]}...)")
        
        # Ambil kandidat dari country yang sama dulu
        country_cands = cands_by_country.get(old_country, [])
        
        # Filter yang belum dipakai
        country_cands = [c for c in country_cands if c['ip'] not in used_new_ips]
        
        # Kalau kurang dari 5 kandidat di country sama, ambil dari country lain juga
        if len(country_cands) < 5:
            other_cands = [c for c in candidates 
                          if c['ip'] not in used_new_ips and c['country_code'] != old_country]
            country_cands.extend(other_cands[:10])
        
        # Ambil top 5 untuk di-detail check
        candidates_to_check = country_cands[:5]
        
        # Cek detail untuk masing-masing
        scored_candidates = []
        for cand in candidates_to_check:
            detail = check_ip_detail(api_key, cand['ip'])
            api_calls += 1
            time.sleep(0.5)  # rate limit safety
            
            if detail:
                score, reasons = calculate_match_score(old, detail)
                scored_candidates.append({
                    "ip": cand['ip'],
                    "score": score,
                    "reasons": reasons,
                    "detail": detail
                })
        
        # Pilih yang terbaik
        if scored_candidates:
            scored_candidates.sort(key=lambda x: -x['score'])
            best = scored_candidates[0]
            best_ip = best['ip']
            best_detail = best['detail']
            
            used_new_ips.add(best_ip)
            
            mapping_entry = {
                "old_ip": old_ip,
                "new_ip": best_ip,
                "old_profile": {
                    "malware_families": old['malware_families'],
                    "country_code": old_country,
                    "country_name": old['old_abuseipdb']['country_name'],
                    "usage_type": old_usage,
                    "isp": old['old_abuseipdb']['isp'],
                    "old_abuse_score": old['old_abuseipdb']['score'],
                },
                "new_profile": {
                    "abuse_score": best_detail.get('abuseConfidenceScore', 0),
                    "total_reports": best_detail.get('totalReports', 0),
                    "country_code": best_detail.get('countryCode', ''),
                    "country_name": best_detail.get('countryName', ''),
                    "usage_type": best_detail.get('usageType', ''),
                    "isp": best_detail.get('isp', ''),
                    "domain": best_detail.get('domain', ''),
                    "is_tor": best_detail.get('isTor', False),
                    "last_reported_at": best_detail.get('lastReportedAt', ''),
                },
                "match_score": best['score'],
                "match_reasons": best['reasons'],
                "verification_url": f"https://www.abuseipdb.com/check/{best_ip}",
                "needs_manual_review": best['score'] < 50
            }
            mapping.append(mapping_entry)
            
            print(f"  → {best_ip} (score: {best['score']:.1f}, {', '.join(best['reasons'])})")
        else:
            print(f"  → ⚠️ NO CANDIDATE FOUND")
            mapping.append({
                "old_ip": old_ip,
                "new_ip": None,
                "error": "No candidate found",
                "needs_manual_review": True
            })
    
    # Step 4: Save
    output = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "total_mappings": len(mapping),
            "successful_matches": sum(1 for m in mapping if m.get('new_ip')),
            "needs_manual_review": sum(1 for m in mapping if m.get('needs_manual_review')),
            "api_calls_used": api_calls,
        },
        "mappings": mapping
    }
    
    output_path = OUTPUT_DIR / "ip_substitution_draft.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    
    # Step 5: Print summary
    print("\n" + "=" * 80)
    print("RINGKASAN MATCHING")
    print("=" * 80)
    print(f"Total IP lama          : {len(old_profiles)}")
    print(f"Berhasil dimatch       : {output['metadata']['successful_matches']}")
    print(f"Perlu review manual    : {output['metadata']['needs_manual_review']}")
    print(f"API calls digunakan    : {api_calls}")
    print(f"\nFile draft tersimpan: {output_path}")
    print("=" * 80)
    
    print("\n=== TABEL MAPPING (DRAFT) ===")
    print(f"{'No':<4}{'Old IP':<18}{'New IP':<18}{'Score':<8}{'Status'}")
    print("-" * 80)
    for i, m in enumerate(mapping, 1):
        old_ip = m['old_ip']
        new_ip = m.get('new_ip', 'NONE')
        score = m.get('match_score', 0)
        status = "⚠️ review" if m.get('needs_manual_review') else "✓ ok"
        print(f"{i:<4}{old_ip:<18}{str(new_ip):<18}{score:<8.1f}{status}")
    
    print("\nLangkah selanjutnya:")
    print("  1. Buka ip_substitution_draft.json")
    print("  2. Untuk setiap mapping, buka URL verification di browser")
    print("  3. Screenshot halaman AbuseIPDB untuk dokumentasi")
    print("  4. Lanjut ke Tahap 4 (apply substitusi)")
    
    return output


if __name__ == "__main__":
    main()
