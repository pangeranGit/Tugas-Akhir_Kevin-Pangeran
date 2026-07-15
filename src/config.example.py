"""
config.py - Konfigurasi terpusat untuk pipeline enrichment TA.
Membaca kredensial dari .env dan menyediakan konstanta.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# === Load .env ===
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# === Wazuh / OpenSearch ===
WAZUH_HOST = os.getenv("WAZUH_HOST", "https://localhost:9200")
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASS", "")
WAZUH_INDEX_PATTERN = "wazuh-alerts-*"

# === AbuseIPDB ===
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = 365
ABUSEIPDB_RATE_LIMIT = 1.0

# === Google Gemini (7-key rotation) ===
GEMINI_API_KEYS = [
    os.getenv("GEMINI_API_KEY_1", ""),
    os.getenv("GEMINI_API_KEY_2", ""),
    os.getenv("GEMINI_API_KEY_3", ""),
    os.getenv("GEMINI_API_KEY_4", ""),
    os.getenv("GEMINI_API_KEY_5", ""),
    os.getenv("GEMINI_API_KEY_6", ""),
    os.getenv("GEMINI_API_KEY_7", ""),
    os.getenv("GEMINI_API_KEY_8", ""),
    os.getenv("GEMINI_API_KEY_9", ""),
]
# Hapus key kosong
GEMINI_API_KEYS = [k for k in GEMINI_API_KEYS if k]
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_TEMPERATURE = 0
GEMINI_MAX_OUTPUT_TOKENS = 2048

# === Paths ===
SURICATA_EVE_PATH = os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
PCAP_DIR = Path(os.getenv("PCAP_DIR", str(BASE_DIR / "dataset/pcap_files/raw")))
GROUND_TRUTH_PATH = Path(os.getenv(
    "GROUND_TRUTH_PATH",
    str(BASE_DIR / "dataset/EarlyCrowAPT/data/contextual_summaries/testing.csv")
))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", str(BASE_DIR / "output")))
LOG_DIR = BASE_DIR / "logs"

# === Buat direktori jika belum ada ===
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# === C2 Category Mapping ===
C2_CATEGORIES = [
    "Malware Command and Control Activity Detected",
    "A Network Trojan was detected",
    "Potentially Bad Traffic",
    "Misc Attack",
]

C2_STRICT_CATEGORIES = [
    "Malware Command and Control Activity Detected",
]

# === MITRE ATT&CK ===
MITRE_C2_TACTIC_ID = "TA0011"
MITRE_C2_TACTIC_NAME = "Command and Control"

# Taktik MITRE relevan dengan aktivitas pada channel C2:
# TA0011 (Command and Control) + TA0010 (Exfiltration Over C2 Channel, via T1041)
RELEVANT_C2_TACTICS = {"TA0011", "TA0010"}

# === Pipeline Settings ===
BATCH_SIZE = 50
MAX_ALERTS = None
CACHE_ABUSEIPDB = True


def validate_config():
    """Validasi bahwa semua konfigurasi kritis tersedia."""
    errors = []

    if not WAZUH_PASS:
        errors.append("WAZUH_PASS belum diset di .env")
    if not ABUSEIPDB_API_KEY:
        errors.append("ABUSEIPDB_API_KEY belum diset di .env")
    if not GEMINI_API_KEYS:
        errors.append("GEMINI_API_KEY_1 s.d. _7 belum diset di .env")
    if not GROUND_TRUTH_PATH.exists():
        errors.append(f"Ground truth tidak ditemukan: {GROUND_TRUTH_PATH}")

    if errors:
        print("=" * 60)
        print("KONFIGURASI ERROR:")
        for e in errors:
            print(f"  [X] {e}")
        print("=" * 60)
        return False

    print("=" * 60)
    print("KONFIGURASI OK:")
    print(f"  [V] Wazuh/OpenSearch : {WAZUH_HOST}")
    print(f"  [V] AbuseIPDB Key    : ...{ABUSEIPDB_API_KEY[-8:]}")
    print(f"  [V] Gemini Keys      : {len(GEMINI_API_KEYS)} key(s) loaded")
    for i, k in enumerate(GEMINI_API_KEYS, 1):
        print(f"       Key {i}: ...{k[-8:]}")
    print(f"  [V] Ground Truth     : {GROUND_TRUTH_PATH}")
    print(f"  [V] Output Dir       : {OUTPUT_DIR}")
    print(f"  [V] PCAP Dir         : {PCAP_DIR}")
    print("=" * 60)
    return True


if __name__ == "__main__":
    validate_config()
