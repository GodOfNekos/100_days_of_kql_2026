# 100 Days of KQL 2026 Inititave

# 100 Days of KQL — Proposed Plan

## Introduction

This document outlines my proposed approach to completing the **100 Days of KQL** challenge.

The plan is intended to provide direction and structure throughout the project. It is not a fixed schedule, and the individual topics may change as the challenge progresses.

Queries may be adjusted, reordered, replaced or expanded depending on:

- Current threat activity
- New vulnerabilities or attack techniques
- Available telemetry
- Lessons learned during the challenge
- Areas where I need additional practice
- Feedback from other participants
- Queries that are particularly relevant to my work

The overall aim is not simply to produce 100 KQL queries. It is to build a practical and reusable library of hunting, investigation and detection content while improving my understanding of Microsoft security telemetry and the Kusto Query Language.

---

## Objectives

Over the course of the 100 days, I intend to:

- Improve my ability to write and understand KQL
- Become more familiar with Microsoft Defender XDR and Microsoft Sentinel data
- Develop practical threat-hunting queries
- Explore common attacker techniques and behaviours
- Map queries to the MITRE ATT&CK framework where appropriate
- Improve my understanding of available telemetry and schema relationships
- Learn how to optimise queries for performance and readability
- Document potential false positives and tuning considerations
- Explore how hunting queries can be converted into operational detections
- Build a repository that remains useful after the challenge has ended

---

## Guiding Principles

### Practical Over Perfect

The purpose of the challenge is to improve through regular practice.

Not every query will be a fully production-ready detection. Some queries may be exploratory, educational or designed to demonstrate a particular KQL operator.

Where possible, queries will be written with practical security operations use in mind.

### Behaviour Over Indicators

Some queries may include indicators of compromise, but the primary focus will be on identifying attacker behaviours and techniques.

Behaviour-based queries are generally more reusable than searches for individual IP addresses, domains, hashes or filenames.

### Explain the Query

Each query should include enough context for another analyst to understand:

- What the query is looking for
- Why the activity may be suspicious
- Which data sources are required
- How the query works
- What the results represent
- What legitimate activity may produce similar results
- How the query could be tuned or expanded

### Build Complexity Gradually

The early queries will focus on common tables, operators and detection scenarios.

Later queries will increasingly introduce:

- Multiple tables
- Joins
- Unions
- Dynamic data
- Process relationships
- Prevalence analysis
- Time-based correlation
- Aggregation
- Anomaly detection
- Cross-domain investigation
- Reusable functions

### Remain Flexible

This roadmap is a guideline rather than a definitive list of daily queries.

The project may change direction where a new topic, incident, vulnerability or research opportunity provides a more useful learning exercise.

---

# Proposed Roadmap

## Days 1–10: KQL Foundations

The opening section will focus on building a strong understanding of the core language and the structure of Microsoft security telemetry.

Potential topics include:

- Filtering data with `where`
- Selecting and renaming fields with `project`
- Sorting and limiting results
- Using time ranges effectively
- Summarising activity
- Counting unique values
- Creating calculated fields
- Working with strings
- Using variables with `let`
- Understanding common Microsoft Defender tables

The queries during this stage may be relatively simple, but they will establish patterns used throughout the remainder of the project.

---

## Days 11–20: Suspicious Process Execution

This section will focus on endpoint process activity and common execution techniques.

Potential scenarios include:

- Office applications spawning command interpreters
- PowerShell execution
- Encoded or obfuscated PowerShell
- Command-line download activity
- Suspicious script interpreter use
- Execution from temporary directories
- Execution from user-writable locations
- Unusual parent and child process relationships
- Renamed system utilities
- Rare process execution across the environment

The primary data source is expected to be `DeviceProcessEvents`, with additional context added from other endpoint tables where useful.

---

## Days 21–30: Living-off-the-Land Techniques

This section will explore the abuse of legitimate Windows utilities and administrative tools.

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
- Other living-off-the-land binaries and scripts

The focus will be on identifying unusual arguments, process relationships, network activity and execution locations rather than alerting solely on the presence of the utility.

---

## Days 31–40: Persistence and Privilege Escalation

This stage will examine techniques used by attackers to maintain access or obtain additional privileges.

Potential topics include:

- Scheduled task creation
- New or modified services
- Registry run keys
- Startup folder modifications
- WMI event subscriptions
- Account creation
- Local administrator group changes
- Suspicious token or privilege use
- UAC bypass techniques
- Logon scripts and other persistence mechanisms

Queries may correlate process, registry, account and event data to provide additional context.

---

## Days 41–50: Defence Evasion

This section will focus on activity intended to weaken, bypass or avoid security controls.

Potential topics include:

- Microsoft Defender exclusions
- Security service modification
- Security tooling termination
- Event log clearing
- Firewall changes
- Tampering with logging
- Deletion of forensic artefacts
- Suspicious file renaming
- Masquerading as system processes
- Attempts to disable monitoring or protection

Where possible, queries will distinguish legitimate administrative activity from activity that is unusual for the device, user or organisation.

---

## Days 51–60: Identity and Authentication

This section will focus on identity-based attacks and suspicious authentication behaviour.

Potential topics include:

- Password spraying
- Brute-force attempts
- Impossible or unusual travel
- Sign-ins from unusual countries or networks
- Legacy authentication
- MFA failures
- MFA method changes
- New credential or authentication method registration
- Privileged account activity
- Suspicious sign-ins followed by administrative actions

Queries may use Microsoft Entra ID, Defender for Identity and Sentinel data, depending on the available telemetry.

---

## Days 61–70: Email, Phishing and Business Email Compromise

This stage will explore email-based initial access and account compromise.

Potential topics include:

- Suspicious email attachments
- Malicious or unusual URLs
- Office applications launched from email content
- Credential-harvesting campaigns
- Adversary-in-the-middle activity
- Suspicious inbox rules
- Email forwarding rules
- Unusual mailbox access
- OAuth application abuse
- Business email compromise behaviours

The aim will be to connect email events with endpoint, identity and cloud activity where possible.

---

## Days 71–80: Network Activity and Command and Control

This section will focus on suspicious network communications and possible command-and-control behaviour.

Potential topics include:

- Rare outbound connections
- Connections from unusual processes
- Newly observed domains
- Suspicious DNS requests
- Repeated beacon-like communications
- Connections to uncommon ports
- Remote administration tools
- Tunnelling utilities
- Public file-sharing services
- Network activity following suspicious process execution

Queries may introduce time-series analysis, prevalence calculations and endpoint-to-network correlation.

---

## Days 81–90: Discovery, Lateral Movement and Exfiltration

This section will examine activity that may occur after an attacker has established access.

Potential topics include:

- System and domain discovery
- Account and group enumeration
- Network share discovery
- Remote service use
- Remote PowerShell
- PsExec-style activity
- RDP activity
- Archive creation
- Large or unusual file transfers
- Uploads to cloud storage or external services

The queries will increasingly focus on attack chains rather than isolated events.

---

## Days 91–100: Advanced Hunting and Detection Engineering

The final section will bring together the techniques and lessons developed throughout the challenge.

Potential topics include:

- Multi-stage attack correlation
- Cross-domain queries
- Endpoint and identity correlation
- Email-to-endpoint attack chains
- Risk scoring
- Baseline and anomaly queries
- Reusable KQL functions
- Exposure and vulnerability context
- Ransomware behaviours
- Converting a hunting query into a detection rule

The final query should ideally combine several data sources and demonstrate the progress made during the challenge.

---

# Proposed Daily Format

Each daily entry will aim to include the following sections.

## Title

A concise description of the behaviour or activity being investigated.

## Objective

A summary of what the query is intended to identify.

## Scenario

An explanation of why the activity may be relevant to a threat hunter, detection engineer or security operations analyst.

## Data Sources

The tables and security products required to run the query.

## MITRE ATT&CK Mapping

Relevant tactics and techniques where an appropriate mapping exists.

## Query

The KQL query itself, with comments where additional explanation is useful.

```kql
// KQL query goes here
```

## Query Explanation

A breakdown of the main stages and operators used within the query.

## Expected Results

An explanation of the data returned and how it may be interpreted.

## Tuning and False Positives

Examples of legitimate activity that may produce similar results, along with potential tuning recommendations.

## Validation

Notes on how the query was tested or how it could be safely reproduced.

## Detection Opportunities

Considerations for converting the query into:

- A Microsoft Defender custom detection
- A Microsoft Sentinel analytics rule
- A scheduled hunting query
- An investigation or enrichment query
- A reusable function

## References

Links to relevant documentation, threat research, MITRE ATT&CK pages or other supporting material.

---

# Query Development Process

The proposed workflow for each query is:

1. Select a threat behaviour, investigation problem or KQL concept.
2. Research the relevant attacker technique.
3. Identify the required telemetry and tables.
4. Create an initial broad hunting query.
5. Review the results and available fields.
6. Add filtering, correlation or enrichment.
7. Consider legitimate administrative activity and false positives.
8. Optimise the query for readability and performance.
9. Document the query and its intended use.
10. Publish the completed entry.

Not every query will pass through every stage. Simpler educational queries may focus primarily on demonstrating a language feature, while more advanced queries may require extensive research and testing.

---

# Testing and Data Availability

Some queries may require Microsoft security products, data connectors or tables that are not available in every environment.

Where live testing is not possible, I will aim to:

- Validate the query syntax where possible
- Reference the relevant Microsoft schema
- Clearly identify the required tables
- Explain any assumptions made
- Note that field availability may differ between environments
- Provide alternative tables or approaches where appropriate

Queries should always be tested and tuned against the environment in which they will be used before being converted into production detections.

---

# Repository Organisation

The repository may use a structure similar to the following:

```text
100-days-of-kql/
│
├── README.md
├── 100_DAY_PLAN.md
├── CONTRIBUTING.md
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
├── sample-data/
│   └── README.md
│
└── resources/
    ├── data-sources.md
    ├── kql-reference.md
    └── mitre-mappings.md
```

The structure may remain simpler at the beginning and expand as the project develops.

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

A successful outcome would be a collection of queries that can be reused, adapted and expanded after the 100 days have ended.

---

# Final Note

This plan represents my current direction for the challenge.

It is deliberately broad and flexible. The topics, order and complexity of the queries may change as my understanding develops and as new research opportunities emerge.

The purpose of the project is to learn through consistent practice, share useful security content and build something that has value beyond the challenge itself.
````
 
# Resources to get started:
- 2025 Organiser: [DE-TH-Aura/100DaysOfKQL at main · SecurityAura/DE-TH-Aura](https://github.com/SecurityAura/DE-TH-Aura/tree/main/100DaysOfKQL)
- Must Learn KQL: [rod-trent/MustLearnKQL: Code included as part of the MustLearnKQL blog series](https://github.com/rod-trent/MustLearnKQL)
- [reprise99/awesome-kql-sentinel: A curated list of blogs, videos, tutorials, queries and anything el…](https://github.com/reprise99/awesome-kql-sentinel)
- [KQLMSPress/definitive-guide-kql: Sample queries and data as part of the Microsoft Press book, The D…](https://github.com/KQLMSPress/definitive-guide-kql)
- [Bert-JanP/Hunting-Queries-Detection-Rules: KQL Queries. Defender For Endpoint and Azure Sentinel Hu…](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)
- [HybridBrothers/Hunting-Queries-Detection-Rules: The purpose of this repository is to share KQL quer…](https://github.com/HybridBrothers/Hunting-Queries-Detection-Rules)
- [m4nbat/KustQueryLanguage_kql: Cyber Defence related kusto queries for use in Azure Sentinel and Def…](https://github.com/m4nbat/KustQueryLanguage_kql)
etc.

# Linked repos:
- https://github.com/m4nbat/100_days_of_kql_2026
- https://github.com/Jiayang-Lai/100-Days-of-KQL
- https://github.com/faslam1994/100_days_of_kql
- https://github.com/JoshuaJapes/100_days_of_kql
- https://github.com/tom564/100_days_kql_2026
- https://github.com/TiiTcHY/100_Days_of_KQL/tree/main
- https://github.com/AtlSs3c/100_Days_Of_KQL_2016
- https://github.com/DazOneZero/100_days_of_kql_2026
- https://github.com/GodOfNekos/100_days_of_kql_2026

# #100DaysOfKQL2026 Master repo with instructions: 
https://github.com/m4nbat/100_days_of_kql_2026/
