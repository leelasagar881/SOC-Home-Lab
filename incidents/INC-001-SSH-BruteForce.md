Incident Report — INC-001: SSH Brute Force Attack
FieldDetailsIncident IDINC-001Date2026-05-15SeverityHighStatusResolvedAnalystBartam Leela Sagar (Shag)EnvironmentSOC Home Lab — GCP (asia-southeast1-c)Affected Assetwazuh-manager (10.148.0.20)
1. Executive Summary
A sustained SSH brute force attack was detected against the lab's Wazuh Manager VM from multiple external IPs. Wazuh Rule 100001 triggered after 5+ failed SSH authentication attempts within 60 seconds. Suricata IDS corroborated the activity via ET CINS threat intelligence signatures. No successful unauthorized access was confirmed. Source IPs were enriched using VirusTotal API (Python script) and blocked at GCP firewall level.
2. Detection Timeline
Time (IST)Event15:22:11First failed SSH login from 80.94.92.17115:22:14Wazuh Rule 5710 fired — non-existent user attempt15:22:19Suricata ET INFO SSH-2.0-Go string detected15:22:31Wazuh Rule 86601 fired — Spamhaus DROP listed IP15:23:05Analyst notified via Wazuh Dashboard15:35:00IPs enriched via VirusTotal Python script15:40:00GCP firewall rule updated — IPs blocked15:45:00No further activity — incident contained
3. IOCs
TypeValueVT ScoreCountryISPSource IP80.94.92.17115 maliciousROUnmanaged LtdSource IP45.148.10.6712 maliciousNLTechoff Srv LimitedSource IP141.98.11.4114 maliciousLTUAB Host BalticSource IP45.79.207.1119 maliciousUSAkamai Connected CloudTarget Port22 (SSH)———Target Userroot, admin———
4. SPL Investigation Queries
splindex=wazuh rule.id IN (86601, 99915, 5710, 5762)
| table _time, agent.name, data.srcip, rule.description, rule.level
| sort -_time
splindex=wazuh rule.id IN (86601, 5710)
| stats count as attempts by data.srcip
| sort -attempts
5. MITRE ATT&CK Mapping
TacticTechniqueIDCredential AccessBrute Force: Password GuessingT1110.001Initial AccessExternal Remote ServicesT1133DiscoveryNetwork Service DiscoveryT1046
6. Containment
ActionStatusSource IPs blocked via GCP firewall✅ DoneSSH root login disabled✅ DonePassword auth disabled (key-only)✅ DoneIPs enriched via VirusTotal Python script✅ Done
7. Lessons Learned

All 4 source IPs were confirmed malicious by 9–15 VirusTotal engines
Suricata Spamhaus/Dshield rules provided early warning before SSH auth failures
Python enrichment script reduced manual triage time from 20 mins to 30 seconds
