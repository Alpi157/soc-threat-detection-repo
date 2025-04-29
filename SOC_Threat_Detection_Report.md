# SOC Threat Detection & Investigation Using Splunk
*(Windows 10 + Apache / Ubuntu + Kali Red-Team Lab)*

---

## 1. Introduction

Modern Security Operations Centers must ingest heterogeneous log sources, detect multi-stage attacks, and document response actions quickly.  
This project demonstrates an end-to-end pipeline — collection → detection → response → reporting — using only open-source tooling and Splunk Enterprise (free license).

### Goals:

- Set up a mini-SOC on commodity hardware / VirtualBox.
- Generate realistic attacks (brute-force, web enumeration, data exfiltration).
- Build dashboards and alerts that demonstrate analyst skills required for roles such as Cyber Security Analyst.
- Document a repeatable incident-response playbook.

---

## 2. Environment Setup

| Component         | Details |
|-------------------|---------|
| Logging Platform  | Splunk Enterprise 9.4 (free 500 MB/day) on Ubuntu 22.04, IP: 192.168.56.105 |
| Indexer Inputs    | Port 9997 (TCP) for Universal Forwarders |
| Windows VM        | Windows 10 Home (22H2), Sysmon 15.15 + SwiftOnSecurity config, IP: 192.168.56.106 |
| Linux VM          | Ubuntu 22.04, Apache 2.4.58, Splunk Universal Forwarder 9.4 |
| Attacker VM       | Kali 2024.1 (Hydra 9.5, Gobuster 3.6, curl, nmap) |
| Network           | VirtualBox Host-Only (192.168.56.0/24) + NAT for Internet |
| Forwarded Logs    | Windows: Security (EventCode 4625), Sysmon Events 1/3<br>Ubuntu: /var/log/apache2/access.log, /var/log/apache2/error.log |
| Indexes / Sourcetypes | `index=main`, Sourcetypes: `WinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `apache:access`, `apache:error` |

---

## 3. Attack Simulations

| # | Tool (Kali)     | Target      | Command / Method                                                                 | Log Evidence                         |
|---|-----------------|-------------|----------------------------------------------------------------------------------|--------------------------------------|
| 1 | Hydra 9.5       | Windows 10 (SSH) | `hydra -l arman -P rockyou.txt ssh://192.168.56.106`                           | EventCode 4625 (>9k failures)        |
| 2 | Gobuster 3.6    | Apache /    | `gobuster dir -u http://192.168.56.105 -w .../common.txt`                        | Apache status=404 flood              |
| 3 | curl loop       | Apache /    | `for i in {1..500}; do curl -X POST -d "ex$i" http://192.168.56.105/; done`      | Apache "POST" burst                  |

> *(Port-scan detection was investigated but intentionally excluded from the final scope for brevity.)*

---
---

## 4. Detection & Dashboards

### 4.1 SPL Queries

| Use-Case          | Core SPL Query |
|-------------------|----------------|
| Brute-Force Count | ```index=main EventCode=4625``` |
| 404 Spike         | ```index=main sourcetype=apache:access status=404``` |
| POST Spike        | ```index=main sourcetype=apache:access "POST"``` |

### 4.2 Dashboard Panels (SOC Threat Detection)

- **Top Attacked Usernames (bar)** – highlights brute-force targets.
- **404 Errors over Time (line)** – visualizes directory enumeration.
- **Suspicious POST Requests (line)** – shows potential data exfiltration spikes.

> *All JSON exports are located in the `dashboards/` folder of the repo.*

### 4.3 Alerts

| Alert Name        | Schedule           | Trigger Logic                          | Action                  |
|-------------------|---------------------|----------------------------------------|--------------------------|
| Bruteforce Detected | Cron `*/5 * * * *` | count(EventCode 4625) > 100 in 5 min    | Add to Triggered Alerts |
| 404 Flood         | Cron `*/5 * * * *`   | status=404 > 20 events in 5 min         | Add to Triggered Alerts |

> *Screenshots of triggered alerts are included under `evidence/alerts/`.*

---

## 5. Incident Response

| Attack            | Detection Source               | Containment                         | Eradication                              | Recovery                       |
|-------------------|---------------------------------|-------------------------------------|-----------------------------------------|--------------------------------|
| SSH Brute-Force   | Splunk alert: Bruteforce Detected | Block attacker IP via `netsh advfirewall` | Check Sysmon 1 for persistence, reset passwords | Remove rule after 24h clean    |
| 404 Enumeration   | 404 panel + 404 Flood alert     | `sudo iptables -A INPUT -s <ip> -j DROP` | Remove unused directories, enable mod_security | Flush rule after validation   |
| POST Burst        | POST panel manual review        | Block IP; enable Apache `LimitRequestBody` | Verify no sensitive data written        | Keep rate-limit rule           |

> *A full IR playbook with command snippets is stored in `IR_Playbook.md`.*

---

## 6. Lessons Learned

- **Field extraction is critical** — custom regex for Apache (status, clientip, uri_path) was mandatory.
- **Sysmon limitations** — it logs only successful TCP handshakes; host-firewall logs or Zeek are better for SYN-scan detection.
- **Dashboards tell the story** — one concise panel per attack chain impresses stakeholders more than raw logs.
- **Automation first** — quick alerts with "Add to Triggered Alerts" proved effective for the lab; extendable to email/SOAR.
- **Resource discipline** — Splunk free 500 MB/day is sufficient if you prune noisy data (e.g., drop Windows Application logs).

---

## 7. Next Steps / Future Work

Optional extensions if time allows:

- Deploy Zeek for network-level scan detection.
- Add mod_security CRS rules and verify alert efficacy in Splunk.
- Push dashboards to Splunk Cloud trial to demo via public URL.
- Integrate SOAR action (e.g., automatic firewall block via Python script).

---

## 8. Repository Contents

| Path                | Description                       |
|---------------------|-----------------------------------|
| `dashboards/`        | JSON exports of three panels      |
| `spl/`               | All SPL queries used in alerts/dashboards |
| `evidence/alerts/`   | Screenshots of triggered alerts   |
| `evidence/logs/`     | Redacted sample logs (Windows, Apache) |
| `IR_Playbook.md`     | Detailed incident response plan   |
| `README.md`          | Quick-start and architecture diagram |
| `SOC_Threat_Detection_Report.md` | ← this document          |

---



