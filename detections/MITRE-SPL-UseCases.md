MITRE ATT&CK Mapped SPL Detection Use Cases

Environment: Splunk Enterprise 9.3.2 + Wazuh 4.14.5 + Suricata 8.0.4 on GCP
Index: index=wazuh (Wazuh alerts forwarded via Universal Forwarder)
Analyst: Bartam Leela Sagar | SOC L1 → L2

UC-001 | SSH Brute Force Detection
MITRE: T1110.001 — Brute Force: Password Guessing
Tactic: Credential Access
Severity: High

index=wazuh rule.groups="authentication_failed" dest_port=22
| bucket _time span=1m
| stats count as failures, dc(data.srcip) as unique_sources by _time, agent.name
| where failures >= 5
| eval risk=if(failures>=10, "Critical", "High")
| table _time, agent.name, failures, unique_sources, risk
| sort -failures

What it detects: 5+ SSH failures in a 1-minute window per agent. Flags distributed brute force when unique_sources > 1.

UC-002 | Brute Force → Successful Login
MITRE: T1110.001 + T1078
Tactic: Credential Access → Initial Access
Severity: Critical

index=wazuh rule.id=100001
| eval attacker_ip=data.srcip
| join attacker_ip [
search 
index=wazuh rule.groups="authentication_success"
    | eval attacker_ip=data.srcip
    | table attacker_ip, agent.name, _time
]
| table _time, agent.name, attacker_ip, rule.description
| sort -_time

What it detects: IP that triggered brute force also appears in successful auth — highest priority escalation.

UC-003 | Privilege Escalation — Sudo Abuse
MITRE: T1548.003
Tactic: Privilege Escalation
Severity: High
spl
index=wazuh rule.id IN (100003, 100004)
| stats count as attempts, values(rule.description) as actions by agent.name, data.dstuser
| where attempts >= 3
| eval escalation_risk=if(match(actions, "switched to root"), "Critical", "High")
| table agent.name, data.dstuser, attempts, escalation_risk, actions
| sort -attempts
UC-004 | File Integrity Monitoring — Critical File Tampering
MITRE: T1098 + T1070.006
Tactic: Persistence, Defense Evasion
Severity: Critical
spl
index=wazuh rule.groups="fim_critical" syscheck.path IN ("/etc/passwd", "/etc/shadow", "/etc/sudoers")
| stats count as changes, values(syscheck.event) as event_types, latest(_time) as last_seen by agent.name, syscheck.path
| eval days_ago=round((now()-last_seen)/86400,1)
| table agent.name, syscheck.path, changes, event_types, days_ago
| sort -changes

UC-005 | Suricata Network Intrusion — Threat Intel Correlation
MITRE: T1071
Tactic: Command and Control
Severity: High
spl
index=wazuh rule.groups="suricata"
| stats count as alert_count, values(data.alert.signature) as signatures, dc(data.dest_ip) as targets
    by data.src_ip, data.alert.category
| where alert_count >= 3
| eval threat_score=alert_count * 10
| table data.src_ip, data.alert.category, alert_count, threat_score, signatures, targets
| sort -threat_score
UC-006 | Dshield / Spamhaus Blocklisted IP
MITRE: T1071.001
Tactic: Initial Access
Severity: High
spl
index=wazuh rule.description="*Dshield*" OR rule.description="*Spamhaus*" OR rule.description="*CINS*"
| stats count as hits, dc(agent.name) as agents_affected, values(rule.description) as threat_feed
    by data.srcip
| sort -hits
| head 20
| eval priority=if(agents_affected>1, "Escalate", "Monitor")
| table data.srcip, hits, agents_affected, threat_feed, priority

UC-007 | Suspicious Process / Rootkit Detection
MITRE: T1014 + T1055
Tactic: Defense Evasion, Privilege Escalation
Severity: Critical
spl
index=wazuh rule.id IN (100007, 100008)
| eval mitre_tag=case(
    rule.id=="100007", "T1014 - Rootkit",
    rule.id=="100008", "T1055 - Process Injection",
    true(), "Unknown"
)
| table _time, agent.name, rule.description, mitre_tag, data.srcip
| sort -_time

UC-008 | Web Attack — SQLi + Directory Traversal
MITRE: T1190 + T1083
Tactic: Initial Access, Discovery
Severity: High
spl
index=wazuh rule.id IN (100009, 100010)
| stats count as attack_count, values(rule.description) as attack_types, dc(data.srcip) as sources
    by agent.name
| eval web_risk=case(
    attack_count>=10, "Critical",
    attack_count>=5, "High",
    true(), "Medium"
)
| table agent.name, attack_count, sources, attack_types, web_risk
| sort -attack_count

UC-009 | Backdoor Port Monitoring
MITRE: T1571
Tactic: Command and Control
Severity: High
spl
index=wazuh rule.id=100023
| stats count as open_events, values(data.dstport) as ports, latest(_time) as last_seen
    by agent.name, data.srcip
| eval suspicious_ports=mvfilter(match(ports, "^(4444|1337|31337|6666|9999|8888)$"))
| where isnotnull(suspicious_ports)
| table agent.name, data.srcip, suspicious_ports, open_events, last_seen
| sort -open_events

UC-010 | 24hr Alert Volume Dashboard
MITRE: All
Tactic: Operational
spl
index=wazuh earliest=-24h
| eval severity=case(
    rule.level>=12, "Critical",
    rule.level>=10, "High",
    rule.level>=7,  "Medium",
    true(),         "Low"
)
| stats count as total by severity, agent.name
| eventstats sum(total) as grand_total by agent.name
| eval pct=round((total/grand_total)*100,1)
| table agent.name, severity, total, pct
| sort agent.name, -total

Summary Table


| UC | Technique | Tactic | Severity |
|---|---|---|---|
| UC-001 | T1110.001 | Credential Access | High |
| UC-002 | T1110.001 + T1078 | Credential Access + Initial Access | Critical |
| UC-003 | T1548.003 | Privilege Escalation | High |
| UC-004 | T1098 + T1070.006 | Persistence + Defense Evasion | Critical |
| UC-005 | T1071 | Command and Control | High |
| UC-006 | T1071.001 | Initial Access | High |
| UC-007 | T1014 + T1055 | Defense Evasion + PrivEsc | Critical |
| UC-008 | T1190 + T1083 | Initial Access + Discovery | High |
| UC-009 | T1571 | Command and Control | High |
| UC-010 | All | Operational | — |

