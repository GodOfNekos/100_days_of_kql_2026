# Day 6 — Execution from Temporary Directories

Day 6 broadens the endpoint-execution focus by looking for executable files launched directly from temporary directories.

This remains a single-table query using `DeviceProcessEvents`, but introduces aggregation and basic prevalence analysis to help distinguish rare executions from activity seen across multiple devices.

---

## Objective

Identify executable files launched from Windows temporary directories and prioritise processes that are rare within the environment.

Examples may include:

```text
C:\Users\User\AppData\Local\Temp\update.exe
```

```text
C:\Windows\Temp\service.exe
```

```text
C:\Temp\installer.exe
```

Temporary directories are commonly used by legitimate applications and installers.

They may also be used by attackers to stage and execute payloads because these locations are frequently writable and may contain large amounts of short-lived activity.

---

## Data Source

This query uses:

- `DeviceProcessEvents`

The table contains process creation and command-line telemetry from Microsoft Defender for Endpoint.

---

## MITRE ATT&CK

- **T1204.002 — User Execution: Malicious File**

Additional techniques may apply depending on how the file reached the device and what it does after execution.

---

## KQL Concepts

Day 6 introduces or reinforces:

- `let`
- `ago()`
- `where`
- `tolower()`
- `contains`
- `case()`
- `extend`
- `summarize`
- `count()`
- `dcount()`
- `min()`
- `arg_max()`
- `project-rename`
- `project`
- `order by`

The main new concept is using `summarize` to group related process executions and calculate how frequently each file appears across the environment.

---

## KQL Query

```kql
// Day 6 - Execution from Temporary Directories
// Identifies executable files launched from temporary directories
// and summarises their prevalence across the environment.

let Lookback = 7d;

DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| extend NormalisedFolderPath = tolower(FolderPath)
| extend TempLocation = case(
    NormalisedFolderPath contains "\\appdata\\local\\temp\\",
        "User temporary directory",
    NormalisedFolderPath contains "\\windows\\temp\\",
        "Windows temporary directory",
    NormalisedFolderPath contains "\\temp\\",
        "Other temporary directory",
    NormalisedFolderPath contains "\\tmp\\",
        "Other temporary directory",
    "Other"
)
| where TempLocation != "Other"
| summarize
    ExecutionCount = count(),
    DeviceCount = dcount(DeviceId),
    UserCount = dcount(AccountName),
    FirstSeen = min(Timestamp),
    arg_max(
        Timestamp,
        DeviceName,
        AccountDomain,
        AccountName,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        ProcessCommandLine,
        ProcessId,
        ProcessUniqueId,
        DeviceId,
        ReportId
    )
    by FileName, FolderPath, SHA1, TempLocation
| project-rename LastSeen = Timestamp
| extend Prevalence = case(
    DeviceCount == 1 and ExecutionCount <= 3,
        "Rare",
    DeviceCount <= 3 and ExecutionCount <= 20,
        "Limited",
    "Common"
)
| project
    LastSeen,
    FirstSeen,
    Prevalence,
    ExecutionCount,
    DeviceCount,
    UserCount,
    TempLocation,
    DeviceName,
    AccountDomain,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    SHA1,
    ProcessId,
    ProcessUniqueId,
    DeviceId,
    ReportId
| order by
    DeviceCount asc,
    ExecutionCount asc,
    LastSeen desc
```

---

## How the Query Works

The query begins by searching process activity from the previous seven days:

```kql
| where Timestamp >= ago(Lookback)
```

The executable path is converted to lowercase to make the location comparisons consistent:

```kql
| extend NormalisedFolderPath = tolower(FolderPath)
```

The `case()` function then assigns each matching process to a temporary-directory category:

| Path contains | Temporary location |
|---|---|
| `\AppData\Local\Temp\` | User temporary directory |
| `\Windows\Temp\` | Windows temporary directory |
| `\Temp\` | Other temporary directory |
| `\Tmp\` | Other temporary directory |

Processes outside these locations are removed from the results.

---

## Summarising the Activity

The `summarize` operator groups executions by:

- Filename
- Folder path
- SHA1 hash
- Temporary-directory category

It then calculates:

```kql
ExecutionCount = count()
```

The total number of matching process executions.

```kql
DeviceCount = dcount(DeviceId)
```

The approximate number of distinct devices where the process was observed.

```kql
UserCount = dcount(AccountName)
```

The approximate number of distinct user accounts associated with the activity.

```kql
FirstSeen = min(Timestamp)
```

The earliest matching event during the lookback period.

The `arg_max()` function retains information from the most recent event in each group, including:

- Device
- Account
- Parent process
- Command line
- Process identifiers

The returned `Timestamp` is renamed to `LastSeen`.

---

## Prevalence Categories

The query assigns each result a basic prevalence category:

| Conditions | Prevalence |
|---|---|
| One device and no more than three executions | Rare |
| Up to three devices and no more than twenty executions | Limited |
| Anything more widespread | Common |

These thresholds are starting points rather than universal risk ratings.

A rare process executing from a temporary directory may deserve earlier investigation, but rarity alone does not prove that the process is malicious.

---

## Expected Results

The query may identify activity such as:

```text
C:\Users\User\AppData\Local\Temp\invoice.exe
```

```text
C:\Windows\Temp\update_service.exe
```

```text
C:\Temp\remote_tool.exe
```

The output will also show how many times the file executed, how many devices observed it and when it was first and most recently seen.

Results categorised as `Rare` or `Limited` may be useful starting points for investigation.

---

## Potential False Positives

Legitimate results may include:

- Software installers
- Application updates
- Browser updates
- Device-management tools
- Temporary setup programs
- Self-extracting archives
- Software deployment platforms
- Helpdesk utilities
- Security tools
- Internally developed applications

A process that is rare within the seven-day lookback period may still be legitimate.

Known software publishers, hashes, paths and command-line patterns can be excluded after review.

---

## Limitations

This query does not prove that a process launched from a temporary directory is malicious.

It may also miss:

- Payloads copied elsewhere before execution
- Scripts executed by an interpreter stored in a trusted location
- Fileless or memory-only execution
- Processes running under renamed or deleted paths
- Temporary directories that do not contain `Temp` or `Tmp`
- Malicious files executed from Downloads, Desktop or other user-writable locations

The prevalence values only represent activity observed during the selected lookback period.

A file marked as `Rare` may have been common before that period, while a widespread malicious payload could be categorised as `Common`.

---

## References

- [Microsoft Defender XDR — DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Microsoft Learn — summarize Operator](https://learn.microsoft.com/en-us/kusto/query/summarize-operator)
- [Microsoft Learn — arg_max()](https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function)
- [MITRE ATT&CK — T1204.002: User Execution — Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK — User Execution Detection Strategy](https://attack.mitre.org/detectionstrategies/DET0294/)

---

## Disclaimer

This query is intended for threat hunting, research and educational use.

It should be tested and tuned against the target environment before being used as a production detection.
