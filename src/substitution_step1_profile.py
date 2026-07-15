"""
Tahap 1 — Substitusi IP: Buat profil 26 IP lama dari pipeline.

Input  : output/enriched_alerts.json
Output : output/ip_old_profile.json

Profil setiap IP berisi:
- malware family (dari Suricata)
- signatures yang memicu (semua varian)
- kategori serangan
- usage type (dari AbuseIPDB sebelumnya)
- country
- ground truth status (malicious/legitimate/not_in_gt)
- jumlah alert yang terkait
"""

import sys
import json
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import *

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


def load_ground_truth():
    """Load ground truth EarlyCrowAPT untuk cek status IP."""
    df = pd.read_csv(GROUND_TRUTH_PATH)
    gt = df[['Destination', 'label', 'capture_type']].copy()
    return gt


def get_gt_status(ip, gt_df):
    """Ambil status IP dari ground truth."""
    rows = gt_df[gt_df['Destination'] == ip]
    if len(rows) == 0:
        return {"in_gt": False, "label": None, "capture_type": None}
    
    labels = rows['label'].unique().tolist()
    captures = rows['capture_type'].unique().tolist()
    return {
        "in_gt": True,
        "label": labels[0] if len(labels) == 1 else labels,
        "capture_type": captures[0] if len(captures) == 1 else captures
    }


def main():
    print("=" * 80)
    print("TAHAP 1 — PROFIL IP LAMA UNTUK SUBSTITUSI")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    # Load enriched alerts
    input_path = OUTPUT_DIR / "enriched_alerts.json"
    if not input_path.exists():
        logger.error(f"File tidak ditemukan: {input_path}")
        return None
    
    with open(input_path) as f:
        data = json.load(f)
    
    alerts = data['alerts'] if isinstance(data, dict) else data
    logger.info(f"Loaded {len(alerts)} alert dari pipeline")
    
    # Load ground truth
    gt_df = load_ground_truth()
    logger.info(f"Loaded ground truth: {len(gt_df)} baris")
    
    # Group by dest_ip
    ip_profiles = {}
    
    for alert in alerts:
        ip = alert.get('dest_ip', '')
        if not ip:
            continue
        
        if ip not in ip_profiles:
            # Profile baru
            abuseipdb = alert.get('abuseipdb', {})
            mitre = alert.get('mitre', {})
            
            ip_profiles[ip] = {
                "old_ip": ip,
                "malware_families": set(),
                "signatures": set(),
                "signature_ids": set(),
                "categories": set(),
                "tactic_ids": set(mitre.get('tactic_ids', [])),
                "technique_ids": set(mitre.get('technique_ids', [])),
                "old_abuseipdb": {
                    "score": abuseipdb.get('abuseConfidenceScore', 0),
                    "total_reports": abuseipdb.get('totalReports', 0),
                    "country_code": abuseipdb.get('countryCode', 'N/A'),
                    "country_name": abuseipdb.get('countryName', 'N/A'),
                    "isp": abuseipdb.get('isp', 'N/A'),
                    "usage_type": abuseipdb.get('usageType', 'N/A'),
                    "domain": abuseipdb.get('domain', 'N/A'),
                },
                "alert_count": 0,
                "ground_truth": get_gt_status(ip, gt_df)
            }
        
        # Update aggregated fields
        prof = ip_profiles[ip]
        prof['alert_count'] += 1
        
        sig = alert.get('signature', '')
        if sig:
            prof['signatures'].add(sig)
        
        sig_id = alert.get('signature_id', '')
        if sig_id:
            prof['signature_ids'].add(str(sig_id))
        
        cat = alert.get('category', '')
        if cat:
            prof['categories'].add(cat)
        
        # malware_family bisa list atau string
        fam = alert.get('malware_family', [])
        if isinstance(fam, list):
            for f in fam:
                if f:
                    prof['malware_families'].add(f)
        elif fam:
            prof['malware_families'].add(fam)
    
    # Convert sets to sorted lists for JSON serialization
    profiles_list = []
    for ip, prof in sorted(ip_profiles.items()):
        prof['malware_families'] = sorted(prof['malware_families'])
        prof['signatures'] = sorted(prof['signatures'])
        prof['signature_ids'] = sorted(prof['signature_ids'])
        prof['categories'] = sorted(prof['categories'])
        prof['tactic_ids'] = sorted(prof['tactic_ids'])
        prof['technique_ids'] = sorted(prof['technique_ids'])
        
        # Buat search hint untuk pencarian di AbuseIPDB
        primary_family = prof['malware_families'][0] if prof['malware_families'] else "Unknown"
        prof['search_hint'] = {
            "primary_malware": primary_family,
            "search_keywords": [primary_family.lower(), "c2", "command and control", "botnet"],
            "preferred_usage_type": prof['old_abuseipdb']['usage_type'],
        }
        
        profiles_list.append(prof)
    
    # Stats
    total_ips = len(profiles_list)
    in_gt = sum(1 for p in profiles_list if p['ground_truth']['in_gt'])
    not_in_gt = total_ips - in_gt
    
    family_count = {}
    for p in profiles_list:
        for f in p['malware_families']:
            family_count[f] = family_count.get(f, 0) + 1
    
    # Build output
    output = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "total_ips": total_ips,
            "in_ground_truth": in_gt,
            "not_in_ground_truth": not_in_gt,
            "malware_family_distribution": family_count,
        },
        "ip_profiles": profiles_list
    }
    
    # Save
    output_path = OUTPUT_DIR / "ip_old_profile.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    
    logger.info(f"Output disimpan ke: {output_path}")
    
    # Print summary tabel
    print("\n" + "=" * 100)
    print("RINGKASAN PROFIL 26 IP LAMA")
    print("=" * 100)
    print(f"{'No':<4}{'IP':<18}{'Malware':<20}{'Country':<10}{'Usage Type':<25}{'GT Status'}")
    print("-" * 100)
    
    for i, p in enumerate(profiles_list, 1):
        fam = p['malware_families'][0][:18] if p['malware_families'] else "Unknown"
        country = p['old_abuseipdb']['country_code']
        usage = p['old_abuseipdb']['usage_type'][:23]
        gt = p['ground_truth']
        if gt['in_gt']:
            gt_str = f"{gt['label']}/{gt['capture_type']}"
        else:
            gt_str = "not in GT"
        print(f"{i:<4}{p['old_ip']:<18}{fam:<20}{country:<10}{usage:<25}{gt_str}")
    
    print("-" * 100)
    print(f"\nDistribusi malware family:")
    for fam, count in sorted(family_count.items(), key=lambda x: -x[1]):
        print(f"  {fam:<25}: {count} IP")
    
    print(f"\nTotal: {total_ips} IP, {in_gt} ada di GT, {not_in_gt} tidak ada di GT")
    print("=" * 100)
    print(f"\n✅ Profil tersimpan di: {output_path}")
    print("\nLangkah selanjutnya: Tahap 2 (ambil kandidat IP dari AbuseIPDB blacklist API)")
    
    return output


if __name__ == "__main__":
    main()
