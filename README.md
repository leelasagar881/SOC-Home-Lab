🛡️ SOC Home Lab — Wazuh + Splunk + Suricata on GCP
A fully functional enterprise-grade Security Operations Center (SOC) lab built on Google Cloud Platform, integrating Wazuh SIEM/EDR, Splunk Enterprise, and Suricata IDS for real-time threat detection and monitoring.

📐 Architecture
```
Internet Threats
│
▼
┌─────────────────────────────────────────────┐
│         Wazuh Manager VM (10.148.0.20)      │
│   ┌─────────────┐   ┌──────────────────┐   │
│   │  Suricata   │   │  Wazuh Manager   │   │
│   │  IDS (ens4) │──▶│  + Dashboard     │   │
│   └─────────────┘   └────────┬─────────┘   │
│                               │             │
│                    ┌──────────▼──────────┐  │
│                    │   Splunk UF         │  │
│                    │  (alerts.json)      │  │
└────────────────────┼─────────────────────┘
│
┌──────────▼──────────┐
│  Splunk Heavy       │
│  Forwarder          │
│  (10.148.0.19)      │
└──────────┬──────────┘
│
┌──────────▼──────────┐
│  Splunk Indexers    │
│  (10.148.0.16/17)   │
└──────────┬──────────┘
│
┌──────────▼──────────┐
│  Splunk Search Head │
│  (10.148.0.18)      │
└─────────────────────┘
Wazuh Agents installed on all 5 Splunk VMs
```

🖥️ Lab Infrastructure
VMInternal IPOSRolewazuh-manger10.148.0.20Ubuntu 22.04Wazuh Manager + Suricata IDSsplunk-clustermaster10.148.0.15CentOS Stream 9Splunk Cluster Mastersplunk-indexer110.148.0.16CentOS Stream 9Splunk Indexersplunk-indexer210.148.0.17CentOS Stream 9Splunk Indexersplunk-searchhead10.148.0.18CentOS Stream 9Splunk Search Headsplunk-heavy-forwarder10.148.0.19CentOS Stream 9Splunk Heavy Forwarder
Cloud: Google Cloud Platform (GCP) — asia-southeast1-c
Machine Type: e2-standard-2 (2 vCPU, 8GB RAM)

🔧 Components
Wazuh Manager v4.14.5

Central SIEM/EDR manager receiving alerts from all agents
Custom detection rules mapped to MITRE ATT&CK
Wazuh Dashboard for visual alert management
Filebeat → Wazuh Indexer integration

Splunk Enterprise v9.3.2

Distributed 5-node cluster (Cluster Master, 2 Indexers, Search Head, Heavy Forwarder)
Receives Wazuh alerts via Universal Forwarder
SPL detection queries for threat hunting

Suricata IDS v8.0.4

Network intrusion detection on ens4 interface
Emerging Threats ruleset (auto-updated)
Alerts forwarded to Wazuh → Splunk pipeline

Wazuh Agents

Deployed on all 5 Splunk VMs
Endpoint monitoring, FIM, CIS compliance scanning
Deployed via Ansible playbook


🎯 Custom Detection Rules (MITRE ATT&CK Mapped)
Rule IDDescriptionMITRE TechniqueLevel100001SSH Brute Force (5+ failures/60s)T1110.00110100002Brute Force + Successful LoginT1110.00112100003Failed sudo attemptT1548.00310100004User switched to rootT1548.00312100005Critical file modified (/etc/passwd, /etc/shadow)T109812100006New file created in /tmpT10598100007Rootkit/Trojan detectedT101412100008Suspicious process anomalyT105510100009SQL Injection attemptT119010100010Directory Traversal attemptT108310100023Suspicious port opened (backdoor ports)T157110100030Custom app: User login successfulT10783100031Custom app: User login failedT11108100032Custom app: Brute force (5+ failures)T1110.00110

🔍 SPL Detection Queries
All High Severity Wazuh Alerts
```spl
index=wazuh rule.level>=10
| table _time, agent.name, rule.id, rule.level, rule.description
| sort -rule.level
```
Suricata Network Threats
```spl
index=wazuh rule.groups="suricata"
| table _time, agent.name, data.src_ip, data.alert.signature, data.alert.category
| sort -_time
```
SSH Brute Force Detection
```spl
index=wazuh rule.groups="brute_force" OR rule.groups="authentication_failed"
| table _time, agent.name, rule.id, rule.description, data.srcip
| sort -_time
```
Alerts by Agent
```spl
index=wazuh
| stats count by agent.name
| sort -count
```
FIM Critical File Changes
```spl
index=wazuh rule.groups="fim_critical"
| table _time, agent.name, syscheck.path, syscheck.event, rule.description
```

📝 Custom Decoder Example
```xml
<decoder name="myapp">
<program_name>myapp</program_name>
</decoder>
<decoder name="myapp-login">
  <parent>myapp</parent>
  <prematch>logged in</prematch>
  <regex>User (\S+) logged in from (\S+) (\S+)</regex>
  <order>dstuser, srcip, status</order>
</decoder>
<decoder name="myapp-failed">
  <parent>myapp</parent>
  <prematch>failed login</prematch>
  <regex>User (\S+) failed login from (\S+)</regex>
  <order>dstuser, srcip</order>
</decoder>
\`\`\`

🤖 Ansible Agent Deployment
Deploy Wazuh agents to multiple VMs with one command:
```bash
ansible-playbook -i inventory.ini deploy_wazuh_agent.yml
```

🚨 Real Threats Detected
This lab is internet-facing and actively detecting real attacks:

Dshield Block Listed Sources — Known malicious IPs attempting connections
Spamhaus DROP Listed Traffic — Blacklisted IP traffic inbound
SSH Brute Force — Automated login attempts from multiple IPs
ET CINS Active Threat Intelligence — Poor reputation IP connections


🛠️ Key Configuration Files
FilePurpose/var/ossec/etc/rules/local_rules.xmlCustom detection + suppression rules/var/ossec/etc/decoders/local_decoder.xmlCustom log decoders/var/ossec/etc/ossec.confWazuh Manager config/etc/suricata/suricata.yamlSuricata interface + network config/opt/splunkforwarder/etc/system/local/inputs.confUF log monitoring config/opt/splunkforwarder/etc/system/local/outputs.confUF forwarding config

📚 Technologies Used

Wazuh 4.14.5
Splunk Enterprise 9.3.2
Suricata IDS 8.0.4
Google Cloud Platform (GCP)
Ansible 2.17
Ubuntu 22.04 LTS
CentOS Stream 9


👨‍💻 Author
Bartam Leela Sagar (Shag)
SOC Analyst L1 | K7 Enterprise Security, Chennai
LinkedIn

📖 References

Wazuh Documentation
Splunk Documentation
Suricata Documentation
MITRE ATT&CK Framework
