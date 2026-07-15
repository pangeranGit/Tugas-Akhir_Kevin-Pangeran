"""
Module 4: LLM Summarization menggunakan Gemini 2.5 Flash.

Fungsi:
- Bangun prompt dengan 4 komponen (role, structured input, output format, anti-hallucination)
- Kirim enriched alert ke Gemini -> narasi 2 kalimat (Behavior + Threat Context)
- Preview skor fidelitas per alert (evaluasi formal di evaluator.py)
- Dual key rotation jika rate limit
"""

import sys
import json
import re
import time
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
        logging.FileHandler(LOG_DIR / "module4.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ======================================================================
# PROMPT ENGINEERING - 4 KOMPONEN
# ======================================================================

# --- Komponen 1: ROLE CONSTRAINT ---
ROLE_CONSTRAINT = """You are a Security Operations Center (SOC) alert analysis system.
You MUST follow these rules strictly:
1. ONLY use information provided in the ENRICHED ALERT DATA below.
2. Do NOT add any information that is not present in the input data.
3. Respond ONLY in the exact format specified."""

# --- Komponen 3: OUTPUT FORMAT ---
OUTPUT_FORMAT = """Respond in EXACTLY this format (2 lines only, no extra text):

Behavior: [One sentence describing the observed attack behavior, including source IP, destination IP, protocol, and what the malware/signature indicates]
Threat Context: [One sentence providing threat context, including the MITRE ATT&CK tactic and technique IDs EXACTLY as given in the [MITRE ATT&CK Mapping] section of the input data, abuse confidence score, and malware family if available]"""

# --- Komponen 4: ANTI-HALLUCINATION CONSTRAINT ---
ANTI_HALLUCINATION = """CRITICAL CONSTRAINTS:
- Do NOT infer, assume, or fabricate any data not explicitly present in the input.
- If a piece of information is not available in the input, write "Data tidak tersedia".
- If abuse confidence score is 0, state it as 0, do NOT interpret it as "safe" or "clean".
- All IPs, scores, and identifiers MUST match the input data exactly.
- If malware family is empty or N/A, write "Data tidak tersedia" for that field.
- Temperature is set to 0: identical alerts must always produce identical narratives."""


# ======================================================================
# Komponen 2: STRUCTURED INPUT (dynamic per alert)
# ======================================================================

def build_structured_input(alert):
    """Bangun structured input dari enriched alert data."""
    abuse_data = alert.get("abuseipdb", {})
    mitre_data = alert.get("mitre", {})
    
    malware_fam = alert.get("malware_family", [])
    if isinstance(malware_fam, list):
        malware_fam = ", ".join(malware_fam) if malware_fam else "N/A"
    
    confidence = alert.get("confidence", [])
    if isinstance(confidence, list):
        confidence = ", ".join(confidence) if confidence else "N/A"
    
    sig_sev = alert.get("signature_severity", [])
    if isinstance(sig_sev, list):
        sig_sev = ", ".join(sig_sev) if sig_sev else "N/A"
    
    tech_details = mitre_data.get("technique_details", [])
    tech_str = ", ".join([f"{t['id']} ({t['name']})" for t in tech_details]) if tech_details else "N/A"

    return f"""=== ENRICHED ALERT DATA ===
[Network Information]
- Source IP: {alert.get('src_ip', 'N/A')}
- Destination IP: {alert.get('dest_ip', 'N/A')}
- Source Port: {alert.get('src_port', 'N/A')}
- Destination Port: {alert.get('dest_port', 'N/A')}
- Protocol: {alert.get('proto', 'N/A')}
- Timestamp: {alert.get('timestamp', 'N/A')}

[Detection Information]
- Signature: {alert.get('signature', 'N/A')}
- Signature ID: {alert.get('signature_id', 'N/A')}
- Category: {alert.get('category', 'N/A')}
- Severity: {alert.get('severity', 'N/A')}
- Signature Severity: {sig_sev}
- Confidence: {confidence}
- Malware Family: {malware_fam}

[AbuseIPDB Enrichment]
- Abuse Confidence Score: {abuse_data.get('abuseConfidenceScore', 'N/A')}
- Total Reports: {abuse_data.get('totalReports', 'N/A')}
- ISP: {abuse_data.get('isp', 'N/A')}
- Usage Type: {abuse_data.get('usageType', 'N/A')}
- Country: {abuse_data.get('countryName', 'N/A')} ({abuse_data.get('countryCode', 'N/A')})
- Is Tor: {abuse_data.get('isTor', 'N/A')}

[MITRE ATT&CK Mapping]
- Tactic IDs: {', '.join(mitre_data.get('tactic_ids', ['N/A']))}
- Tactic Names: {', '.join(mitre_data.get('tactic_names', ['N/A']))}
- Technique IDs: {', '.join(mitre_data.get('technique_ids', ['N/A']))}
- Techniques: {tech_str}
- Mapping Source: {mitre_data.get('mapping_source', 'N/A')}
=== END DATA ==="""


def build_full_prompt(alert):
    """Gabungkan 4 komponen prompt menjadi prompt lengkap."""
    return f"""{ROLE_CONSTRAINT}

{build_structured_input(alert)}

{OUTPUT_FORMAT}

{ANTI_HALLUCINATION}"""


# ======================================================================
# RESPONSE PARSING
# ======================================================================

def parse_llm_response(response_text):
    """
    Parse respons LLM menjadi Behavior dan Threat Context.
    Mendukung berbagai format output Gemini 2.5 Flash:
    - Behavior: ...
    - **Behavior:** ...
    - * **Behavior:** ...
    - **Behavior**: ...
    """
    if not response_text:
        return {"behavior": "", "threat_context": "", "parse_status": "empty_response"}
    
    behavior = ""
    threat_context = ""
    
    # Regex fleksibel: tangkap semua variasi format markdown Gemini
    behavior_pattern = re.compile(
        r'^[\s\-\*]*\*{0,2}\s*behavior\s*\*{0,2}\s*:\s*\*{0,2}\s*(.*)',
        re.IGNORECASE
    )
    threat_pattern = re.compile(
        r'^[\s\-\*]*\*{0,2}\s*threat\s+context\s*\*{0,2}\s*:\s*\*{0,2}\s*(.*)',
        re.IGNORECASE
    )
    
    for line in response_text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        
        bm = behavior_pattern.match(line)
        if bm and not behavior:
            behavior = re.sub(r'[\*]+', '', bm.group(1)).strip()
            continue
        
        tm = threat_pattern.match(line)
        if tm and not threat_context:
            threat_context = re.sub(r'[\*]+', '', tm.group(1)).strip()
            continue
    
    if behavior and threat_context:
        return {"behavior": behavior, "threat_context": threat_context, "parse_status": "success"}
    elif behavior or threat_context:
        return {"behavior": behavior, "threat_context": threat_context, "parse_status": "partial"}
    else:
        return {"behavior": response_text.strip()[:500], "threat_context": "", "parse_status": "fallback"}


# ======================================================================
# FIDELITY SCORING (Preview)
# ======================================================================

def score_d1(alert, narration):
    """D1: Factual Accuracy (1-3)."""
    text = (narration["behavior"] + " " + narration["threat_context"]).lower()
    checks = []
    
    if alert.get("dest_ip"):
        checks.append(alert["dest_ip"].lower() in text)
    if alert.get("src_ip"):
        checks.append(alert["src_ip"].lower() in text)
    
    abuse_score = str(alert.get("abuseipdb", {}).get("abuseConfidenceScore", ""))
    if abuse_score and abuse_score != "-1":
        checks.append(abuse_score in text)
    
    sig = alert.get("signature", "").lower()
    if sig:
        keywords = [w for w in sig.split() if len(w) > 3 and w not in ["malware", "alert", "activity", "detected", "generic"]]
        if keywords:
            checks.append(any(kw in text for kw in keywords[:3]))
    
    if not checks:
        return 1
    ratio = sum(checks) / len(checks)
    if ratio >= 0.75:
        return 3
    elif ratio >= 0.4:
        return 2
    return 1


def score_d2(narration):
    """D2: Completeness (1-3)."""
    has_b = bool(narration["behavior"] and len(narration["behavior"]) > 10)
    has_t = bool(narration["threat_context"] and len(narration["threat_context"]) > 10)
    if has_b and has_t:
        return 3
    elif has_b or has_t:
        return 2
    return 1


def score_d3(alert, narration):
    """D3: Relevance (1-3). Cek kesetiaan narasi pada tactic yang DIPETAKAN untuk alert ini."""
    text = (narration["behavior"] + " " + narration["threat_context"]).lower()
    mapped_tactics = [t.lower() for t in alert.get("mitre", {}).get("tactic_ids", [])]
    has_mapped_tactic = any(t in text for t in mapped_tactics) if mapped_tactics else False
    has_c2 = any(t in text for t in ["command and control", "c2", "cnc", "c&c", "beacon", "callback"])
    if has_mapped_tactic and has_c2:
        return 3
    elif has_mapped_tactic or has_c2:
        return 2
    return 1


def calc_fidelity(alert, narration):
    """Hitung preview skor fidelitas: (D1 + D2 + D3) / 3"""
    d1 = score_d1(alert, narration)
    d2 = score_d2(narration)
    d3 = score_d3(alert, narration)
    return {"d1": d1, "d2": d2, "d3": d3, "score": round((d1 + d2 + d3) / 3, 4)}


# ======================================================================
# GEMINI CLIENT
# ======================================================================

class GeminiClient:
    """Client Gemini dengan dual key rotation."""
    
    def __init__(self, api_keys, model_name):
        from google import genai
        from google.genai import types
        self.types = types
        self.model_name = model_name
        self.current_key = 0
        self.clients = [genai.Client(api_key=k) for k in api_keys]
        logger.info(f"GeminiClient: {len(self.clients)} key(s), model={model_name}")
    
    def generate(self, prompt, max_retries=3):
        for attempt in range(max_retries):
            try:
                client = self.clients[self.current_key]
                response = client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=self.types.GenerateContentConfig(
                        temperature=GEMINI_TEMPERATURE,
                        max_output_tokens=GEMINI_MAX_OUTPUT_TOKENS
                    )
                )
                if response.text:
                    return response.text
                elif response.candidates:
                    parts = response.candidates[0].content.parts
                    return parts[0].text if parts else None
                return None
            except Exception as e:
                if "429" in str(e) or "quota" in str(e).lower() or "rate" in str(e).lower():
                    old = self.current_key
                    self.current_key = (self.current_key + 1) % len(self.clients)
                    logger.warning(f"  Rate limit key {old+1}, switch ke key {self.current_key+1}")
                    if self.current_key == 0:
                        time.sleep(60)
                    continue
                logger.error(f"  Gemini error (attempt {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)
        return None


# ======================================================================
# MAIN
# ======================================================================

def main():
    print("=" * 70)
    print("MODULE 4: LLM SUMMARIZATION (Gemini 2.5 Flash)")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print(f"\n  Model: {GEMINI_MODEL}, Temperature: {GEMINI_TEMPERATURE}")
    print(f"  API Keys: {len(GEMINI_API_KEYS)}")
    print(f"  Prompt: Role + Structured Input + Output Format + Anti-Hallucination")
    
    input_path = OUTPUT_DIR / "c2_alerts_enriched_mitre.json"
    if not input_path.exists():
        logger.error(f"File tidak ditemukan: {input_path}")
        return None
    
    with open(input_path) as f:
        alerts = json.load(f)
    logger.info(f"Loaded {len(alerts)} alert")
    
    gemini = GeminiClient(GEMINI_API_KEYS, GEMINI_MODEL)
    results = []
    
    print()
    for i, alert in enumerate(alerts, 1):
        sig = alert.get("signature", "")[:50]
        print(f"  [{i:02d}/{len(alerts)}] {sig} ... ", end="", flush=True)
        
        prompt = build_full_prompt(alert)
        t0 = time.perf_counter()
        response_text = gemini.generate(prompt)
        llm_latency = round(time.perf_counter() - t0, 3)
        narration = parse_llm_response(response_text)
        fidelity = calc_fidelity(alert, narration)
        
        print(f"D1={fidelity['d1']} D2={fidelity['d2']} D3={fidelity['d3']} F={fidelity['score']:.2f} [{narration['parse_status']}]")
        
        enriched = {**alert}
        enriched["llm_summary"] = {
            "behavior": narration["behavior"],
            "threat_context": narration["threat_context"],
            "raw_response": response_text[:1000] if response_text else "",
            "parse_status": narration["parse_status"],
            "model": GEMINI_MODEL,
            "temperature": GEMINI_TEMPERATURE,
            "llm_latency_seconds": llm_latency,
            "generated_at": datetime.now().isoformat()
        }
        enriched["fidelity_preview"] = fidelity
        results.append(enriched)
        
        if i < len(alerts):
            time.sleep(3)
    
    # Ringkasan
    d1s = [r["fidelity_preview"]["d1"] for r in results]
    d2s = [r["fidelity_preview"]["d2"] for r in results]
    d3s = [r["fidelity_preview"]["d3"] for r in results]
    fs = [r["fidelity_preview"]["score"] for r in results]
    success = sum(1 for r in results if r["llm_summary"]["parse_status"] == "success")
    
    print("\n" + "=" * 70)
    print("RINGKASAN MODULE 4")
    print("=" * 70)
    print(f"  Total alert    : {len(results)}")
    print(f"  Parse success  : {success}")
    print(f"  Parse partial  : {sum(1 for r in results if r['llm_summary']['parse_status'] == 'partial')}")
    print(f"  Parse failed   : {sum(1 for r in results if r['llm_summary']['parse_status'] in ('empty_response','fallback'))}")
    print(f"\n  === PREVIEW FIDELITAS ===")
    print(f"  Avg D1 (Factual)      : {sum(d1s)/len(d1s):.2f} / 3.00  (3:{d1s.count(3)} 2:{d1s.count(2)} 1:{d1s.count(1)})")
    print(f"  Avg D2 (Completeness) : {sum(d2s)/len(d2s):.2f} / 3.00  (3:{d2s.count(3)} 2:{d2s.count(2)} 1:{d2s.count(1)})")
    print(f"  Avg D3 (Relevance)    : {sum(d3s)/len(d3s):.2f} / 3.00  (3:{d3s.count(3)} 2:{d3s.count(2)} 1:{d3s.count(1)})")
    print(f"\n  >>> PREVIEW M1-3 = {sum(fs)/len(fs):.4f} <<<")
    
    print(f"\n  === Contoh Narasi ===")
    for i, r in enumerate(results[:3], 1):
        print(f"\n  [{i}] {r.get('signature','')[:60]}")
        print(f"      Behavior: {r['llm_summary']['behavior'][:150]}")
        print(f"      Threat:   {r['llm_summary']['threat_context'][:150]}")
    print("\n" + "=" * 70)
    
    # Simpan
    output_path = OUTPUT_DIR / "c2_alerts_enriched_llm.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"Disimpan ke: {output_path}")
    
    latencies = [r["llm_summary"]["llm_latency_seconds"] for r in results
                 if "llm_latency_seconds" in r["llm_summary"]]
    stats = {
        "total": len(results), "success": success,
        "avg_d1": round(sum(d1s)/len(d1s), 4),
        "avg_d2": round(sum(d2s)/len(d2s), 4),
        "avg_d3": round(sum(d3s)/len(d3s), 4),
        "avg_m13": round(sum(fs)/len(fs), 4),
        "llm_latency": {
            "mean_seconds": round(sum(latencies)/len(latencies), 3) if latencies else None,
            "min_seconds": round(min(latencies), 3) if latencies else None,
            "max_seconds": round(max(latencies), 3) if latencies else None,
            "note": "Latency panggilan Gemini murni, tidak termasuk jeda 3 detik antar request."
        }
    }
    with open(OUTPUT_DIR / "module4_summary.json", "w") as f:
        json.dump(stats, f, indent=2)
    
    return results

if __name__ == "__main__":
    main()
