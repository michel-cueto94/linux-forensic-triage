#!/usr/bin/env python3
import os
import re
import json
import math
import hashlib
import argparse
import subprocess
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None

def calculate_hashes(filepath):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

def calculate_entropy(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = data.count(bytes([x])) / length
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return round(entropy, 4)

def extract_network_iocs(filepath):
    iocs = {"urls": [], "ips": []}
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        urls = re.findall(r'https?://[^\s\'"<>]+', content)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
        iocs["urls"] = list(set(urls))
        iocs["ips"] = list(set(ips))
    except Exception:
        pass
    return iocs

def query_virustotal(sha256_hash, api_key):
    if not api_key or not requests:
        return "No consultado (Sin API Key)"
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            return f"{malicious}/{total} detecciones"
        elif resp.status_code == 404:
            return "No encontrado en VT (0 detecciones conocidas)"
        else:
            return f"Error API (HTTP {resp.status_code})"
    except Exception as e:
        return f"Error de conexión: {str(e)}"

def collect_volatile_linux():
    volatile_data = {}
    commands = {
        "network_connections": ["ss", "-tunap"],
        "running_processes": ["ps", "aux"]
    }
    for key, cmd in commands.items():
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
            data_hash = hashlib.sha256(output.encode("utf-8")).hexdigest()
            volatile_data[key] = {
                "command": " ".join(cmd),
                "sha256": data_hash,
                "lines_captured": len(output.splitlines()),
                "sample": "\n".join(output.splitlines()[:10])
            }
        except Exception as e:
            volatile_data[key] = {"error": str(e)}
    return volatile_data

def main():
    parser = argparse.ArgumentParser(description="Herramienta de Triaje Forense y Cadena de Custodia en Linux")
    parser.add_argument("-d", "--dir", required=True, help="Directorio con artefactos a analizar")
    parser.add_argument("-o", "--out", default="reportes", help="Directorio de salida para reportes")
    parser.add_argument("--vt-key", default=os.getenv("VT_API_KEY"), help="API Key de VirusTotal (opcional)")
    args = parser.parse_args()

    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    os.makedirs(args.out, exist_ok=True)

    print(f"[*] Iniciando Triaje Forense - {timestamp_utc}")
    print("[*] Recolectando telemetría volátil de red y procesos en Linux...")
    volatile = collect_volatile_linux()

    artifacts = []
    print(f"[*] Analizando artefactos en '{args.dir}'...")
    for root, _, files in os.walk(args.dir):
        for file in sorted(files):
            filepath = os.path.join(root, file)
            size = os.path.getsize(filepath)
            md5_h, sha256_h = calculate_hashes(filepath)
            entropy = calculate_entropy(filepath)
            iocs = extract_network_iocs(filepath)
            vt_status = query_virustotal(sha256_h, args.vt_key)

            flag = "ALTA ENTROPÍA (Posible cifrado/empaquetado)" if entropy >= 7.5 else "Normal / Texto"
            if iocs["urls"] or iocs["ips"]:
                flag += " | IoCs de red detectados"

            artifacts.append({
                "filename": file,
                "path": filepath,
                "size_bytes": size,
                "md5": md5_h,
                "sha256": sha256_h,
                "entropy": entropy,
                "assessment": flag,
                "extracted_iocs": iocs,
                "virustotal": vt_status
            })
            print(f"    [+] {file} | SHA256: {sha256_h[:16]}... | Entropía: {entropy} | {flag}")

    report_data = {
        "metadata": {
            "timestamp_utc": timestamp_utc,
            "hostname": os.uname().nodename,
            "target_directory": args.dir
        },
        "volatile_system_state": volatile,
        "artifacts_chain_of_custody": artifacts
    }

    # Guardar JSON
    json_path = os.path.join(args.out, "triage_report.json")
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(report_data, jf, indent=4, ensure_ascii=False)

    # Guardar Markdown
    md_path = os.path.join(args.out, "triage_report.md")
    with open(md_path, "w", encoding="utf-8") as mf:
        mf.write(f"# Acta de Triaje Forense y Cadena de Custodia\n\n")
        mf.write(f"- **Fecha y Hora (UTC):** `{timestamp_utc}`\n")
        mf.write(f"- **Host de Adquisición:** `{report_data['metadata']['hostname']}`\n")
        mf.write(f"- **Directorio Analizado:** `{args.dir}`\n\n")
        mf.write("## 1. Cadena de Custodia y Análisis de Artefactos\n\n")
        mf.write("| Archivo | Tamaño (Bytes) | Entropía | SHA-256 | Evaluación | VirusTotal |\n")
        mf.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for a in artifacts:
            mf.write(f"| `{a['filename']}` | {a['size_bytes']} | {a['entropy']} | `{a['sha256']}` | {a['assessment']} | {a['virustotal']} |\n")
        
        mf.write("\n## 2. Indicadores de Compromiso (IoCs) Extraídos\n\n")
        for a in artifacts:
            if a["extracted_iocs"]["urls"] or a["extracted_iocs"]["ips"]:
                mf.write(f"- **{a['filename']}**: URLs: `{a['extracted_iocs']['urls']}` | IPs: `{a['extracted_iocs']['ips']}`\n")

        mf.write("\n## 3. Integridad de Telemetría Volátil (Linux)\n\n")
        for k, v in volatile.items():
            if "sha256" in v:
                mf.write(f"- **{k}** (`{v['command']}`): {v['lines_captured']} líneas capturadas | SHA-256: `{v['sha256']}`\n")

    print(f"\n[OK] Triaje completado. Reportes generados en:\n     -> {md_path}\n     -> {json_path}")

if __name__ == "__main__":
    main()
