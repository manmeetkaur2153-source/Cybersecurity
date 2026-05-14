# 🛡️ SOC Detection Engineering — Windows Brute-Force Attack Detection Using Wazuh

![Wazuh](https://img.shields.io/badge/Wazuh-SIEM%20%2F%20XDR-blue?style=for-the-badge&logo=wazuh&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-Target%20Endpoint-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Wazuh%20Manager-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110%20Brute%20Force-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)

---

## 📌 Project Overview

This project demonstrates **SOC Detection Engineering** using **Wazuh SIEM/XDR**. A custom frequency-based correlation rule was built to detect Windows brute-force login attacks by aggregating multiple failed authentication events within a defined timeframe and escalating them as a **Level 12 Critical alert**.

> **Role Target:** SOC Analyst (Tier 1/2) | Detection Engineer | Security Analyst

---

## 🛠️ Lab Environment

| Component | Details |
|-----------|---------|
| **Wazuh Manager** | Installed on Linux server — processes rules and generates alerts |
| **Wazuh Agent** | Installed on Windows endpoint — forwards Security Event Logs |
| **Log Source** | Windows Security Event ID 4625 (Failed Logon) |
| **Dashboard** | Wazuh Web Interface — Discover + Threat Hunting modules |
| **Custom Rule File** | `/var/ossec/etc/rules/local_rules.xml` |
| **Custom Rule ID** | 100200 |

---

## 🎯 Objectives

- ✅ Understand how Windows authentication failures are logged in Wazuh
- ✅ Build a custom frequency-based correlation rule in `local_rules.xml`
- ✅ Detect brute-force behavior — 3 failed logins within 120 seconds
- ✅ Validate real-time alert generation in Wazuh Dashboard
- ✅ Map the detection rule to MITRE ATT&CK T1110 (Brute Force)
- ✅ Troubleshoot and resolve Wazuh configuration errors

---

## 🏗️ Lab Architecture

```
┌──────────────────────┐     Failed Login Attempts     ┌───────────────────────┐
│   Windows Endpoint   │ ─────────────────────────►   │    Wazuh Agent        │
│   (Target Machine)   │                               │  (Installed on Win)   │
└──────────────────────┘                               └──────────┬────────────┘
                                                                  │
                                                     Security Event Logs (4625)
                                                                  │
                                                                  ▼
                                                       ┌─────────────────────┐
                                                       │   Wazuh Manager     │
                                                       │   (Linux Server)    │
                                                       │                     │
                                                       │  local_rules.xml    │
                                                       │  Rule ID: 100200    │
                                                       │  freq=3 / time=120s │
                                                       └──────────┬──────────┘
                                                                  │
                                                      Level 12 Critical Alert
                                                                  │
                                                                  ▼
                                                       ┌─────────────────────┐
                                                       │   Wazuh Dashboard   │
                                                       │  • Discover View    │
                                                       │  • Threat Hunting   │
                                                       └─────────────────────┘
```

---

## 📝 Custom Detection Rule

### Variation 1 — Using `if_matched_group` (Initial Test)
```xml
<rule id="100200" level="12" frequency="3" timeframe="120">
  <if_matched_group>authentication_failed</if_matched_group>
  <description>Multiple Windows login failures detected. Possible brute-force attack.</description>
  <mitre><id>T1110</id></mitre>
</rule>
```

### Variation 2 — Using `if_matched_sid` ✅ Recommended
```xml
<rule id="100200" level="12" frequency="3" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <description>Multiple Windows login failures detected. Possible brute-force attack.</description>
  <mitre><id>T1110</id></mitre>
</rule>
```

### Rule Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `frequency` | 3 | Number of events required to trigger |
| `timeframe` | 120 seconds | Time window for event counting |
| `level` | 12 | Critical severity |
| `if_matched_sid` | 60122 | Parent rule — Windows failed authentication |
| MITRE Technique | T1110 | Brute Force |

---

## ⚠️ Key Concept — `if_sid` vs `if_matched_sid`

| Directive | Behavior |
|-----------|----------|
| `if_sid` | Triggers **immediately** on a single event match — cannot be used with frequency |
| `if_matched_sid` | **Counts multiple occurrences** within a timeframe — required for brute-force detection |

> Using `if_sid` with a `frequency` attribute causes:
> `ERROR: Invalid use of frequency` on Wazuh Manager restart.

---

## 🔄 Implementation Steps

1. **Edit the rule file** on Wazuh Manager:
   ```bash
   sudo nano /var/ossec/etc/rules/local_rules.xml
   ```

2. **Add the custom rule** (Variation 2 — using `if_matched_sid`)

3. **Restart Wazuh Manager** to apply changes:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

4. **Simulate brute-force** — perform 3+ failed logins on Windows endpoint within 120 seconds

5. **Validate alert** in Wazuh Dashboard → Discover and Threat Hunting modules

---

## 📊 Alert Details

| Field | Value |
|-------|-------|
| **Rule ID** | 100200 |
| **Severity Level** | 12 — Critical |
| **Description** | Multiple Windows login failures detected. Possible brute-force attack. |
| **MITRE Technique** | T1110 — Brute Force |
| **Trigger Condition** | 3 failed logins within 120 seconds |
| **Agent** | Windows Endpoint |

---

## 🧠 Skills Demonstrated

- Custom Wazuh rule development (`local_rules.xml`)
- Frequency-based event correlation in SIEM
- Windows Security Event Log analysis (Event ID 4625)
- Real-time alert configuration and validation
- MITRE ATT&CK framework mapping
- Troubleshooting Wazuh Manager configuration errors
- SOC detection engineering workflow: **Configure → Restart → Simulate → Validate → Document**

---

## 📁 Repository Structure

```
wazuh-brute-force-detection/
│
├── README.md                              # Project documentation
├── Wazuh_SOC_Project_Report.docx          # Full project report with screenshots
└── screenshots/                           # Evidence from the lab
    ├── individual_login_failures_1.png
    ├── individual_login_failures_2.png
    ├── custom_rule_local_rules_xml.png
    ├── wazuh_manager_restart.png
    ├── threat_hunting_before_rule.png
    ├── alert_discover_view_1.png
    ├── alert_discover_view_2.png
    └── threat_hunting_after_rule.png
```

---

## 👤 Author

**Manmeet Kaur**
Cybersecurity Enthusiast | SOC Analyst 

[![GitHub]
[![LinkedIn]

---

## 📄 License

This project is for educational purposes only. All simulations were conducted in an isolated, controlled lab environment.

---

> *"Detection engineering is the art of turning noise into signal."*
