# Incident Response Playbook

---

## 1. Scope & Assumptions

| Item | Detail |
|-----|--------|
| **Monitoring stack** | Splunk Enterprise 9.x on Ubuntu, receiving data from:<br>• Windows 10 VM – Sysmon 15.15 + Security Log<br>• Ubuntu VM – Apache 2.4 access/error logs (Forwarder)<br>• All logs stored in index=main |
| **Attack surface in lab** | • Windows 10: SSH (OpenSSH), RDP closed, ports 1000-2000 closed<br>• Apache default site on Ubuntu |
| **Threat simulations covered** | ① SSH brute-force (hydra)<br>② Gobuster directory enumeration (404 flood)<br>③ POST burst / data-exfil over HTTP |
| **Goal of plan** | Detect, validate, contain, eradicate, and document the above attacks using only built-in OS controls and Splunk alerts. |

---

## 2. Playbooks by Attack Type

### 2.1 SSH Brute-Force (EventCode 4625)

| Phase | Action |
|------|--------|
| **Identification** | Alert **Bruteforce Detected** triggers when this SPL returns ≥1 row:<br>```spl
index="main" EventCode=4625 earliest=-5m@m latest=now
``` |
| **Validation** | • Pivot on Account_Name, host, Source_Network_Address to confirm single noisy IP.<br>• Correlate with normal baseline (expect <5 failed logons/5 min). |
| **Containment** | 1. On Windows:<br>```powershell
New-NetFirewallRule -DisplayName "BlockBruteforce" -Direction Inbound -RemoteAddress <attackerIP> -Action Block -Protocol TCP
```<br>2. Force password reset or disable targeted local account. |
| **Eradication** | • Inspect `C:\Users\<user>\AppData\Local\Temp` for malicious tools.<br>• Check Sysmon EventCode=1 for suspicious process launches from attacker IP. |
| **Recovery** | • Re-enable account with new strong password.<br>• Remove temporary firewall rule after ≥24h monitoring shows normal traffic. |
| **Evidence to preserve** | Screenshot of alert, SPL output, firewall rule command, zipped splunkd.log slice containing the incident. |

---

### 2.2 Gobuster Web Enumeration (404 Flood)

| Phase | Action |
|------|--------|
| **Identification** | Dashboard panel **404 Errors Over Time**:<br>```spl
index="main" sourcetype="apache:access" status=404
``` |
| **Validation** | • Verify single source IP (<attackerIP>) using:<br>```spl
index="main" sourcetype="apache:access" status=404
``` |
| **Containment** | • Add IP to Apache block list:<br>```bash
sudo iptables -A INPUT -s <attackerIP> -j DROP
``` |
| **Eradication** | • Review `/var/log/apache2/access.log` for successful hits on sensitive paths.<br>• Patch or remove any discovered insecure directories. |
| **Recovery** | • Flush iptables rule after penetration test proves directory listing secured.<br>• Deploy `mod_security` or `fail2ban` for longer-term protection. |
| **Evidence** | Export panel PNG + raw access-log snippet (showing 404 lines). |

---
---

### 2.3 HTTP POST Burst / Data-Exfil Attempt

| Phase          | Action |
|----------------|--------|
| **Identification** | Dashboard panel **Suspicious POST Requests** (SPL):<br>```spl
index="main" sourcetype="apache:access" "POST"
``` |
| **Validation** | • Confirm request bodies are large/repetitive with:<br>```spl
index="main" sourcetype="apache:access" "POST"
``` |
| **Containment** | • Block offending IP via iptables.<br>• If internal host, disable NIC or isolate VLAN. |
| **Eradication** | • Rotate credentials exposed in POST body (if any).<br>• Apply rate-limit rule in Apache (`mod_evasive`). |
| **Recovery** | • Re-enable IP after monitoring ≤10 POST/min for 1 hour.<br>• Keep rate-limiting permanently. |
| **Evidence** | Saved SPL CSV of POST spike, screenshot of timechart, firewall block command. |

---

## 3. Cross-Cutting Controls & Logging

| Control        | Implementation Details |
|----------------|-------------------------|
| **Time Sync**  | All VMs run `chrony` against same NTP server → consistent timestamps in Splunk. |
| **Log Retention** | 30 days hot, 90 days warm (fits free 500 MB/day limit given low-volume lab). |
| **Authentication** | Splunk admin creds rotated post-build; SSH key-based auth on Windows OpenSSH. |
| **Dashboards** | Three panels live in SOC Threat Detection dashboard: failed-logins, POST spike, 404 spike (see `dashboards/`). |
| **Alerts** | Two alerts enabled (Bruteforce, 404 Flood) – add e-mail action when SMTP available. |

---

## 4. Lessons Learned (for Final Report)

- Field extraction is critical – Apache logs needed custom extraction before reliable detection.
- Sysmon network logging only records completed handshakes; IDS or firewall logs are better for SYN scans.
- Automated blocking via host firewall is fast in a lab; in production, coordinate with network/security teams.
- Rate-limiting and WAF rules mitigate both enumeration (404) and POST-burst exfil attempts with low operational overhead.
- Dashboard storytelling (one panel per attack chain) makes recruiter demos clear and compelling.

---

## 5. Appendix – Quick Command Reference

| Purpose                      | Command |
|-------------------------------|---------|
| Start Hydra SSH brute-force   | `hydra -l arman -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.106` |
| Launch Gobuster dirbust       | `gobuster dir -u http://192.168.56.105/ -w /usr/share/wordlists/dirb/common.txt` |
| POST flood attack             | `for i in {1..500}; do curl -X POST -d "exfil_$i" http://192.168.56.105/; done` |
| Block IP on Windows           | `netsh advfirewall firewall add rule name="Block_IP" dir=in action=block remoteip=<IP>` |
| Block IP on Ubuntu            | `sudo iptables -A INPUT -s <IP> -j DROP` |

---
