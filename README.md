# 100 Days of KQL

## Introduction

This repository documents my participation in the **100 Days of KQL** challenge.

The aim is not simply to produce 100 queries. The project is intended to improve my understanding of the Kusto Query Language while building a practical and reusable library of threat-hunting, investigation and detection content.

The roadmap provides direction rather than a fixed schedule. Queries may be reordered, replaced or expanded depending on:

- Current threat activity
- New vulnerabilities or attack techniques
- Available telemetry
- Lessons learned during the challenge
- Areas requiring additional practice
- Feedback from other participants
- Scenarios relevant to my work

The project will begin with relatively focused queries before gradually introducing additional data sources, more advanced KQL operators and cross-domain correlation.

---

## Objectives

Over the course of the 100 days, I intend to:

- Improve my ability to write and understand KQL
- Become more familiar with Microsoft Defender XDR and Microsoft Sentinel telemetry
- Develop practical threat-hunting queries
- Explore common attacker techniques and behaviours
- Map queries to MITRE ATT&CK where appropriate
- Improve my understanding of security schemas and table relationships
- Learn how to optimise queries for performance and readability
- Document potential false positives and tuning considerations
- Explore how hunting queries can become operational detections
- Build a repository that remains useful after the challenge

---

## Guiding Principles

### Practical Over Perfect

The purpose of the challenge is to improve through consistent practice.

Not every query will be a fully production-ready detection. Some may be exploratory, educational or intended to demonstrate a particular KQL technique.

Where possible, every query will still be based on a practical security scenario.

### Learn Through Hunting

KQL concepts will be introduced through real threat-hunting queries rather than isolated language exercises.

Each query should provide an opportunity to learn more about:

- KQL syntax
- Microsoft security telemetry
- Attacker behaviour
- Threat-hunting methodology
- Detection engineering

### Behaviour Over Indicators

Some queries may include indicators of compromise, but the primary focus will be attacker behaviours and techniques.

Behaviour-based queries are generally more reusable than searches limited to individual IP addresses, domains, hashes or filenames.

### Explain the Query

Each entry should include enough information for another analyst to understand:

- What the query is looking for
- Why the behaviour may be suspicious
- Which data sources are required
- How the query works
- What the results represent
- What legitimate activity may produce similar results

### Build Complexity Gradually

The project will progress from single-table endpoint queries towards:

- Multiple tables
- Joins and unions
- Dynamic data
- Process relationships
- Prevalence analysis
- Time-based correlation
- Aggregation
- Anomaly detection
- Cross-domain investigations
- Reusable functions

### Remain Flexible

This roadmap is a guideline rather than a definitive list of daily queries.

The project may change direction where a new threat, incident, vulnerability or research opportunity provides a more useful learning exercise.

---

# Proposed Roadmap

## Days 1–10: Endpoint Execution and KQL Foundations

The first section will introduce core KQL concepts through practical endpoint execution hunts.

Rather than creating queries solely to demonstrate individual operators, each query will investigate a recognisable security behaviour.

Planned and potential topics include:

1. Potential ClickFix-style command execution
2. Office applications spawning suspicious child processes
3. Suspicious PowerShell download commands
4. Encoded or obfuscated PowerShell execution
5. Suspicious Windows script-host activity
6. Execution from temporary directories
7. Execution from user-writable locations
8. Renamed Windows system utilities
9. Rare parent-child process relationships
10. Unusual process execution across the environment

KQL concepts introduced during this section may include:

- `where`
- `project`
- `order by`
- `take`
- `ago()`
- `let`
- `dynamic`
- `in~`
- `has_any`
- `contains`
- `extend`
- `case()`
- `summarize`
- `count()`
- `dcount()`

The main data source is expected to be:

- `DeviceProcessEvents`

---

## Days 11–20: Living-off-the-Land and Utility Abuse

This section will examine how legitimate Windows utilities can be abused for execution, downloading, proxy execution and system modification.

Potential topics include:

- `rundll32.exe`
- `regsvr32.exe`
- `mshta.exe`
- `certutil.exe`
- `bitsadmin.exe`
- `wmic.exe`
- `wscript.exe`
- `cscript.exe`
- `installutil.exe`
- PowerShell and command-shell proxy execution

The focus will not simply be on identifying the presence of these utilities.

Queries will examine:

- Command-line arguments
- Parent and child processes
- Execution paths
- User context
- References to remote content
- Process rarity
- Associated network activity

KQL development during this section may introduce:

- Advanced string parsing
- Regular expressions
- `parse`
- `extract`
- `split`
- Conditional fields
- Process prevalence
- Aggregation by device and user

---

## Days 21–30: Persistence and System Modification

This section will focus on activity that may allow an attacker to maintain access or alter the configuration of a device.

Potential topics include:

- Scheduled task creation
- New or modified services
- Registry run keys
- Startup folder changes
- WMI persistence
- New local accounts
- Local administrator group changes
- Logon scripts
- PowerShell profile modification
- Browser or application persistence

Likely data sources include:

- `DeviceProcessEvents`
- `DeviceRegistryEvents`
- `DeviceFileEvents`
- `DeviceEvents`

KQL development may include:

- Combining multiple event types
- `union`
- Normalising fields
- Timestamp comparisons
- Grouping related activity
- Creating reusable query variables

---

## Days 31–40: Defence Evasion and Security Control Tampering

This section will examine activity intended to weaken, bypass or avoid security controls.

Potential topics include:

- Microsoft Defender exclusions
- Security service modification
- Security tooling termination
- Event log clearing
- Firewall changes
- Logging configuration changes
- Deletion of forensic artefacts
- Suspicious file renaming
- Masquerading as system processes
- Attempts to disable monitoring or protection

Queries will aim to distinguish expected administrative activity from unusual or potentially malicious changes.

KQL development may include:

- Device and user baselines
- Historical comparisons
- Prevalence calculations
- `arg_min()`
- `arg_max()`
- `make_set()`
- `make_list()`
- First-seen and last-seen analysis

---

## Days 41–50: Identity and Authentication

This section will move beyond endpoint telemetry and focus on identity-related activity.

Potential topics include:

- Password spraying
- Repeated authentication failures
- Brute-force attempts
- Sign-ins from unusual countries
- Sign-ins from unusual networks
- Legacy authentication
- MFA failures
- MFA method changes
- New authentication method registration
- Privileged account activity

Possible data sources include:

- Microsoft Entra ID
- Microsoft Defender for Identity
- Microsoft Sentinel authentication tables
- Microsoft Defender XDR identity tables

KQL development may include:

- Time-window aggregation
- Threshold-based hunting
- User baselining
- IP address analysis
- Conditional Access context
- Geographical comparisons
- Joining identity and endpoint data

---

## Days 51–60: Email, Phishing and Business Email Compromise

This section will investigate email-based initial access and account compromise.

Potential topics include:

- Suspicious email attachments
- Malicious or unusual URLs
- High-risk attachment types
- Office execution following email delivery
- Credential-harvesting campaigns
- Adversary-in-the-middle activity
- Suspicious inbox rules
- External forwarding rules
- Unusual mailbox access
- OAuth application abuse

Potential data sources include:

- `EmailEvents`
- `EmailAttachmentInfo`
- `EmailUrlInfo`
- `UrlClickEvents`
- `CloudAppEvents`
- `DeviceProcessEvents`

KQL development may include:

- Email-to-endpoint correlation
- Joining by user
- Joining by message identifiers
- Attachment hash correlation
- URL analysis
- Multi-table investigations

---

## Days 61–70: Network Activity and Command and Control

This section will focus on suspicious network communication and possible command-and-control behaviour.

Potential topics include:

- Rare outbound connections
- Connections from unusual processes
- Newly observed domains
- Suspicious DNS requests
- Repeated beacon-like communication
- Connections to uncommon ports
- Remote administration tools
- Tunnelling utilities
- Dynamic DNS services
- Network activity following suspicious execution

Potential data sources include:

- `DeviceNetworkEvents`
- DNS telemetry
- Firewall logs
- Proxy logs
- Microsoft Sentinel network tables

KQL development may include:

- Process-to-network joins
- Domain extraction
- IP address parsing
- Time-series analysis
- Connection frequency
- Beaconing calculations
- Historical prevalence

---

## Days 71–80: Discovery and Lateral Movement

This section will examine activity performed after an attacker has gained access to a device or account.

Potential topics include:

- System discovery
- Domain discovery
- Account enumeration
- Group enumeration
- Network share discovery
- Remote service creation
- Remote PowerShell
- PsExec-style execution
- Remote Desktop activity
- SMB and administrative share access

Queries will increasingly focus on related sequences of events rather than isolated activity.

KQL development may include:

- Event sequencing
- Correlation within time windows
- `join`
- `lookup`
- `serialize`
- `prev()`
- `next()`
- Process-chain reconstruction
- Activity grouped by user or device

---

## Days 81–90: Collection, Staging and Exfiltration

This section will focus on the collection, preparation and transfer of information.

Potential topics include:

- Archive creation
- Password-protected archives
- Large file collections
- Staging files in temporary directories
- Access to sensitive file locations
- Unusual removable-media activity
- Uploads to cloud-storage platforms
- Large outbound transfers
- Command-line file-transfer utilities
- Data transfer following suspicious execution

Potential data sources include:

- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- Cloud application telemetry
- Proxy or firewall logs

KQL development may include:

- File-volume calculations
- Data-size aggregation
- Session-based analysis
- User and device baselines
- Multi-stage correlation
- Detection of unusual transfer patterns

---

## Days 91–100: Advanced Hunting and Detection Engineering

The final section will bring together the techniques developed throughout the project.

Potential topics include:

- Multi-stage attack correlation
- Cross-domain investigations
- Endpoint and identity correlation
- Email-to-endpoint attack chains
- Risk scoring
- Baseline and anomaly queries
- Reusable KQL functions
- Exposure and vulnerability context
- Ransomware behaviour
- Converting a hunting query into a detection rule

The final queries should increasingly combine:

- Endpoint telemetry
- Identity activity
- Email events
- Network communication
- File activity
- Alert evidence
- Vulnerability or exposure context

KQL development may include:

- Multiple joins
- Materialised query sections
- Reusable functions
- Weighted indicators
- Time-series anomalies
- Attack-chain reconstruction
- Query optimisation
- Detection-rule requirements

The final query should demonstrate the progress made throughout the challenge by combining several data sources into a practical investigation or detection scenario.

---

# Development Progression

The revised roadmap follows four broad stages.

## Stage One: Single-Table Hunting

The early queries will focus on understanding individual telemetry tables and writing clear behavioural searches.

## Stage Two: Context and Baselines

Queries will begin adding categorisation, prevalence, historical context and environmental baselines.

## Stage Three: Correlation

Multiple tables and event types will be connected to identify related activity.

## Stage Four: Detection Engineering

The final queries will focus on attack chains, reusable logic, optimisation and conversion into operational detections.

This progression allows the project to remain practical from Day 1 while gradually increasing the complexity of the KQL.

---

# Daily Entry Format

Each daily entry will generally include:

## Objective

A short explanation of the behaviour being investigated.

## Scenario

Why the activity may be relevant to a threat hunter, detection engineer or security operations analyst.

## Data Source

The Microsoft Defender XDR, Microsoft Sentinel or related tables required by the query.

## MITRE ATT&CK

Relevant tactics and techniques where an appropriate mapping exists.

## KQL Concepts

The operators, functions or language features used within the query.

## Query

The KQL query, including comments where useful.

```kql
// KQL query goes here
```

## How the Query Works

A brief explanation of the main filters, transformations and output fields.

## Expected Results

An explanation of what matching events may represent.

## False Positives and Limitations

Known legitimate activity and important limitations of the query.

## References

Relevant Microsoft documentation, MITRE ATT&CK pages and supporting threat research.

The exact format may change depending on the complexity of the query.

---

# Query Development Process

The proposed workflow for each query is:

1. Select a threat behaviour, investigation problem or KQL concept.
2. Research the relevant attacker technique.
3. Identify the required telemetry and tables.
4. Create an initial hunting query.
5. Review the available fields and expected results.
6. Add filtering, correlation or enrichment where useful.
7. Consider legitimate activity and false positives.
8. Optimise the query for readability and performance.
9. Document the query and its intended use.
10. Publish the completed entry.

Not every query will require every stage.

Simple queries may focus on a single behaviour or KQL feature, while later entries may require additional research, testing and correlation.

---

# Testing and Data Availability

Some queries may require Microsoft security products, data connectors or tables that are not available in every environment.

Where live testing is not possible, I will aim to:

- Validate the query syntax where possible
- Reference the relevant Microsoft schema
- Clearly identify the required tables
- Explain any assumptions made
- Note where field availability may differ
- Provide alternative approaches where appropriate

Queries should always be tested and tuned against the environment in which they will be used before being converted into production detections.

---

# Repository Structure

The repository may use a structure similar to:

```text
100-days-of-kql/
│
├── README.md
│
├── days/
│   ├── day-001-query-title.md
│   ├── day-002-query-title.md
│   ├── day-003-query-title.md
│   └── ...
│
├── queries/
│   ├── day-001-query-title.kql
│   ├── day-002-query-title.kql
│   └── ...
│
├── functions/
│   └── reusable-functions.kql
│
└── resources/
    ├── data-sources.md
    ├── kql-reference.md
    └── mitre-mappings.md
```

The repository may remain simpler during the early stages and expand as the project develops.

---

# Measuring Progress

Success will not be measured solely by completing 100 files.

By the end of the challenge, I hope to demonstrate improvement in:

- KQL syntax and query construction
- Understanding Microsoft security schemas
- Threat-hunting methodology
- Detection engineering
- Query optimisation
- Documentation
- False-positive analysis
- Cross-table correlation
- Mapping telemetry to attacker behaviour
- Turning research into practical security content

A successful outcome will be a collection of queries that can be reused, adapted and expanded after the challenge has ended.

---

# Resources

The following resources may be used throughout the project:

- [100 Days of KQL 2026 — Master Repository](https://github.com/m4nbat/100_days_of_kql_2026)
- [Must Learn KQL](https://github.com/rod-trent/MustLearnKQL)
- [Awesome KQL for Microsoft Sentinel](https://github.com/reprise99/awesome-kql-sentinel)
- [The Definitive Guide to KQL — Sample Queries](https://github.com/KQLMSPress/definitive-guide-kql)
- [Hunting Queries and Detection Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Microsoft Defender XDR Advanced Hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)
- [Kusto Query Language Documentation](https://learn.microsoft.com/en-us/kusto/query/)

---
# Linked 100 Days of KQL Repositories

The following repositories are also participating in, or providing material for, the **100 Days of KQL** initiative:

- [m4nbat — 100 Days of KQL 2026](https://github.com/m4nbat/100_days_of_kql_2026)
- [Jiayang-Lai — 100 Days of KQL](https://github.com/Jiayang-Lai/100-Days-of-KQL)
- [faslam1994 — 100 Days of KQL](https://github.com/faslam1994/100_days_of_kql)
- [JoshuaJapes — 100 Days of KQL](https://github.com/JoshuaJapes/100_days_of_kql)
- [tom564 — 100 Days KQL 2026](https://github.com/tom564/100_days_kql_2026)
- [TiiTcHY — 100 Days of KQL](https://github.com/TiiTcHY/100_Days_of_KQL/tree/main)
- [AtlSs3c — 100 Days of KQL](https://github.com/AtlSs3c/100_Days_Of_KQL_2016)
- [DazOneZero — 100 Days of KQL 2026](https://github.com/DazOneZero/100_days_of_kql_2026)

These repositories provide additional queries, approaches and perspectives from other participants completing the challenge.

---

# Disclaimer

The queries in this repository are intended for threat hunting, research and educational use.

They should be tested and tuned against the target environment before being used as production detections.

A query result does not by itself confirm malicious activity.
