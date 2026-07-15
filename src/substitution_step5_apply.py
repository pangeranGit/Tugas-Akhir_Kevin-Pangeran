"""Tahap 5: Apply IP substitution pada dest_ip alert hasil dedup Modul 1."""
import json
from pathlib import Path
from datetime import datetime
from collections import Counter

BASE = Path(__file__).resolve().parent.parent
OUTPUT = BASE / "output"

SOURCE_ALERTS = OUTPUT / "c2_alerts_deduped.json"
SUBSTITUTION_MAP = OUTPUT / "ip_substitution_draft.json"
TARGET_ALERTS = OUTPUT / "c2_alerts_deduped_substituted.json"
REPORT = OUTPUT / "substitution_report.json"


# === Loader ===
def load_mapping(path: Path) -> tuple[dict, dict]:
    """Return (old->new map, old->full entry map) dari ip_substitution_draft.json."""
    with open(path) as f:
        data = json.load(f)

    entries = data["mappings"] if isinstance(data, dict) and "mappings" in data else data
    ip_map = {}
    entry_map = {}
    for e in entries:
        old, new = e.get("old_ip"), e.get("new_ip")
        if old and new:
            ip_map[old] = new
            entry_map[old] = e
    return ip_map, entry_map


def unwrap_alerts(data):
    """Kembalikan (list_of_alerts, wrapper_or_None). Wrapper dipakai saat menulis ulang."""
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict) and "alerts" in data and isinstance(data["alerts"], list):
        return data["alerts"], data
    raise ValueError("Struktur c2_alerts_deduped.json tidak dikenali (bukan list, bukan dict dengan key 'alerts').")


# === Substitusi ===
def substitute_dest_ip(alerts: list, ip_map: dict):
    """Ganti dest_ip pada tiap alert dan return log substitusi."""
    log = []
    per_ip = Counter()
    affected = 0

    for idx, alert in enumerate(alerts):
        old = alert.get("dest_ip")
        if old and old in ip_map:
            new = ip_map[old]
            alert["dest_ip"] = new
            alert["_original_dest_ip"] = old  # jejak untuk evaluator M1-1
            log.append({
                "alert_index": idx,
                "opensearch_id": alert.get("opensearch_id"),
                "signature": alert.get("signature"),
                "old_dest_ip": old,
                "new_dest_ip": new,
            })
            per_ip[old] += 1
            affected += 1

    return log, per_ip, affected


# === Main ===
def main():
    print(f"[*] Loading mapping   : {SUBSTITUTION_MAP.name}")
    ip_map, entry_map = load_mapping(SUBSTITUTION_MAP)
    if not ip_map:
        raise RuntimeError("Mapping kosong.")
    print(f"[+] {len(ip_map)} IP mappings loaded")

    print(f"[*] Loading source    : {SOURCE_ALERTS.name}")
    with open(SOURCE_ALERTS) as f:
        raw = json.load(f)
    alerts, wrapper = unwrap_alerts(raw)
    print(f"[+] {len(alerts)} alerts loaded (wrapped={wrapper is not None})")

    # Pre-check: IP unik di dest_ip sebelum substitusi
    dest_ips_before = Counter(a.get("dest_ip") for a in alerts if a.get("dest_ip"))
    mapped_present = [ip for ip in ip_map if ip in dest_ips_before]
    print(f"[*] Unique dest_ip di source   : {len(dest_ips_before)}")
    print(f"[*] Mapping hadir di dest_ip   : {len(mapped_present)}/{len(ip_map)}")

    log, per_ip, affected = substitute_dest_ip(alerts, ip_map)

    # Tulis ulang dengan struktur yang sama dengan source
    if wrapper is not None:
        wrapper["alerts"] = alerts
        wrapper.setdefault("substitution_metadata", {}).update({
            "applied_at": datetime.now().isoformat(),
            "mapping_file": SUBSTITUTION_MAP.name,
            "alerts_affected": affected,
        })
        output = wrapper
    else:
        output = alerts

    with open(TARGET_ALERTS, "w") as f:
        json.dump(output, f, indent=2)

    unused = sorted(set(ip_map) - set(per_ip))
    dest_ips_after = Counter(a.get("dest_ip") for a in alerts if a.get("dest_ip"))

    report = {
        "timestamp": datetime.now().isoformat(),
        "source_file": str(SOURCE_ALERTS),
        "target_file": str(TARGET_ALERTS),
        "mapping_file": str(SUBSTITUTION_MAP),
        "total_alerts": len(alerts),
        "alerts_affected": affected,
        "alerts_unchanged": len(alerts) - affected,
        "total_substitutions": len(log),
        "unique_old_ips_in_mapping": len(ip_map),
        "unique_old_ips_replaced": len(per_ip),
        "unique_dest_ips_before": len(dest_ips_before),
        "unique_dest_ips_after": len(dest_ips_after),
        "unused_mappings": unused,
        "replacement_counts_per_old_ip": dict(per_ip.most_common()),
        "substitution_log": log,
    }
    with open(REPORT, "w") as f:
        json.dump(report, f, indent=2)

    print()
    print(f"[+] Output         : {TARGET_ALERTS.name}")
    print(f"[+] Report         : {REPORT.name}")
    print(f"[+] Alerts affected: {affected}/{len(alerts)}")
    print(f"[+] Substitutions  : {len(log)}")
    print(f"[+] Old IPs used   : {len(per_ip)}/{len(ip_map)}")
    if unused:
        print(f"[!] Unused mapping : {len(unused)} IP tidak ditemukan di dest_ip source")
        for ip in unused:
            print(f"    - {ip}")


if __name__ == "__main__":
    main()
