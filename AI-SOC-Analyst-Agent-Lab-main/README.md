# 🛡️ AI-Powered SOC Analyst Automation Lab

![Status](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Security](https://img.shields.io/badge/Security-Blue_Team-shield)
![AI](https://img.shields.io/badge/AI-Airia_GPT--5_Nano-purple)

## 📖 Project Overview
This project simulates an automated Tier-1 Security Operations Center (SOC) pipeline. It utilizes Python and `tshark` to capture live network traffic, employs dynamic thresholding to identify malicious activity across multiple protocols (e.g., ICMP, SSH), and leverages an LLM-powered AI agent to ingest telemetry and generate structured, actionable triage reports. 

This standalone lab serves as a foundational building block for automated threat detection, establishing logic that can be scaled into larger, more complex environments like Azure-hosted Active Directory networks and enterprise SIEMs.

---

## 🏗️ Architecture & Environment

The lab environment consists of three core components:

| Component | Role | Description |
| :--- | :--- | :--- |
| **Ubuntu VM** | Threat Actor (Attacker) | Generates malicious traffic (e.g., SSH brute force, Ping floods). IP: `192.168.56.102` |
| **Kali Linux VM** | SOC Target (Defender) | Runs the automated Python capture script (`soc_capture.py`) and listens for anomalies. IP: `192.168.56.20` |
| **Airia.ai** | AI SOC Analyst (Brain) | A custom GPT-5 Nano agent programmed with a strict defensive SOC playbook to analyze JSON alerts. |

---

## ⚙️ Setup & Configuration

To deploy this lab, the Python script must be configured to match the specific network IPs and API credentials of the host environment. 

Update the `CONFIGURATION` block in `soc_capture.py`:

```python
# Network Variables
INTERFACE = "eth0"              
DESTINATION_IP = "YOUR_DEST_IP" 

# Airia API Credentials
AIRIA_API_URL = "[https://api.airia.ai/v2/PipelineExecution/YOUR_UNIQUE_ID_HERE](https://api.airia.ai/v2/PipelineExecution/YOUR_UNIQUE_ID_HERE)"
AIRIA_API_KEY = "YOUR_API_KEY_HERE"

# IDS Tuning
CAPTURE_DURATION = 100          # Listening duration per cycle
THRESHOLD = 40                  # Packet threshold to trigger an alert
