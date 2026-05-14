import subprocess
import csv
import json
import os
import uuid
import requests
from collections import defaultdict

# ------------------------------------------------
# CONFIGURATION
# ------------------------------------------------

INTERFACE = "eth0"              
CAPTURE_DURATION = 100          # Duration in seconds
THRESHOLD = 40                  # Packet threshold to trigger alert

PCAP_FILE = "traffic.pcap"
CSV_FILE = "traffic.csv"
ALERT_FILE = "alert.json"

# ---- Airia Webhook ----
AIRIA_API_URL = "YOUR_EXECUTION_URL"
AIRIA_API_KEY = "YOUR_API_KEY"

# Metadata for AI Context
DESTINATION_HOST = "Kali-SOC-Target"
DESTINATION_IP = "YOUR_DEST_API"
SOURCE_HOST = "Ubuntu-Threat-Actor"    

# ------------------------------------------------
# HELPER
# ------------------------------------------------

def run_command(cmd, description):
    print(f"[+] {description}")
    subprocess.run(cmd, check=True)

# ------------------------------------------------
# STEP 1 – Capture Traffic
# ------------------------------------------------

def capture_traffic():
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    capture_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", f"dst host {DESTINATION_IP}", 
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", PCAP_FILE
    ]

    run_command(capture_cmd, f"Capturing on {INTERFACE} for {CAPTURE_DURATION}s")

    if not os.path.exists(PCAP_FILE):
        raise RuntimeError("PCAP capture failed.")

    print(f"[+] Capture saved to {PCAP_FILE}")

# ------------------------------------------------
# STEP 2 – Convert to CSV
# ------------------------------------------------

def convert_to_csv():
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    convert_cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "tcp.dstport",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d"
    ]

    with open(CSV_FILE, "w", newline="") as outfile:
        subprocess.run(convert_cmd, stdout=outfile, check=True)

    print(f"[+] CSV created at {CSV_FILE}")

# ------------------------------------------------
# STEP 3 – Analyze Traffic (Multi-Protocol)
# ------------------------------------------------

def analyze_traffic():
    activity_tracker = defaultdict(lambda: defaultdict(int))

    with open(CSV_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            src_ip = (row.get("ip.src") or "").strip().strip('"')
            proto_num = (row.get("ip.proto") or "").strip().strip('"')
            dst_port = (row.get("tcp.dstport") or "").strip().strip('"')

            if not src_ip:
                continue

            protocol_name = "UNKNOWN"
            alert_category = "Suspicious Network Volume"

            if proto_num == "1":
                protocol_name = "ICMP"
                alert_category = "Network Reconnaissance / Scanning"
            elif dst_port == "22":
                protocol_name = "SSH"
                alert_category = "Brute Force / Credential Stuffing"
            elif dst_port == "445":
                protocol_name = "SMB"
                alert_category = "Privilege Escalation / Lateral Movement"
            elif dst_port == "3389":
                protocol_name = "RDP"
                alert_category = "Brute Force / Credential Stuffing"
            elif proto_num == "6":
                protocol_name = f"TCP/{dst_port}"

            activity_tracker[src_ip][protocol_name] += 1

    print("\n[+] Traffic volume per source IP and Protocol:\n")
    
    for ip, protocols in activity_tracker.items():
        for proto, count in protocols.items():
            print(f"    {ip} -> {proto}: {count} packets")
            if count > THRESHOLD:
                print(f"\n[!] Suspicious {proto} activity detected from: {ip}")
                
                alert_type = "Suspicious Network Volume"
                if proto in ["SSH", "RDP"]: alert_type = "Brute Force / Credential Stuffing"
                elif proto == "SMB": alert_type = "Privilege Escalation / Lateral Movement"
                elif proto == "ICMP": alert_type = "Network Reconnaissance / Scanning"

                return ip, count, proto, alert_type

    print("\n[+] No suspicious activity detected.")
    return None, None, None, None

# ------------------------------------------------
# STEP 4 – Generate Alert JSON
# ------------------------------------------------

def generate_alert(ip, count, protocol, alert_type):
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"

    alert = {
        "alert_id": alert_id,
        "alert_type": alert_type,             
        "indicator_type": "ip",
        "indicator_value": ip,
        "source_host": SOURCE_HOST,
        "destination_host": DESTINATION_HOST,
        "destination_ip": DESTINATION_IP,
        "protocol": protocol,                 
        "evidence": {
            "packet_count": count,
            "time_window_seconds": CAPTURE_DURATION,
            "data_source": os.path.basename(PCAP_FILE)
        },
        "analyst_question": f"Is this {protocol} activity expected or malicious?"
    }

    with open(ALERT_FILE, "w") as f:
        json.dump(alert, f, indent=4)

    print(f"[+] Alert JSON written to {ALERT_FILE}")
    return alert

# ------------------------------------------------
# STEP 5 – Send to Airia API
# ------------------------------------------------

def send_to_airia(alert):
    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": AIRIA_API_KEY
    }

    payload = {
        "userInput": json.dumps(alert),   
        "asyncOutput": False
    }

    print("[+] Sending alert to Airia Agent Execution API...")

    response = requests.post(
        AIRIA_API_URL,
        headers=headers,
        json=payload,
        timeout=100
    )

    response.raise_for_status()

    print(f"[+] Airia responded with status {response.status_code}")

    try:
        data = response.json()
        print("[+] Airia Response JSON:")
        print(json.dumps(data, indent=2))
    except Exception:
        print("[+] Airia response (raw text):")
        print(response.text)

# ------------------------------------------------
# MAIN
# ------------------------------------------------

def main():
    try:
        capture_traffic()
        convert_to_csv()
        ip, count, protocol, alert_type = analyze_traffic()

        if ip:
            alert = generate_alert(ip, count, protocol, alert_type)
            send_to_airia(alert)
        else:
            print("[+] No alert generated, nothing sent to Airia.")

        print("\n[+] Workflow complete.")

    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()
