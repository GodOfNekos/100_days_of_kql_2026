# Day 7 — Execution from User-Writable Locations

Day 7 expands the location-based hunting introduced on Day 6 by looking for processes executed from broader user-writable or user-controlled directories.

Temporary directories are excluded from this query because they were covered separately on Day 6.

---

## Objective

Identify executable files launched from locations commonly used to store downloaded, synchronised or user-controlled content.

Examples may include:

```text
C:\Users\User\Downloads\invoice.exe
```

```text
C:\Users\User\Desktop\update.exe
```

```text
C:\Users\User\AppData\Roaming\service.exe
```

```text
C:\$Recycle.Bin\payload.exe
```

These locations are commonly used by legitimate applications and users.

They may also be used by attackers to stage and execute malicious files because they are often accessible without requiring administrative privileges.

---

## Data Source

This query uses:

- `DeviceProcessEvents`

The table contains process creation and command-line telemetry from Microsoft Defender for Endpoint.

---

## MITRE ATT&CK

- **T1204.002 — User Execution: Malicious File**

Additional techniques may apply depending on how the file arrived on the device and what it does after execution.

---

## KQL Concepts

Day 7 introduces or reinforces:

- `let`
- `dynamic`
- `ago()`
- `where`
- `tolower()`
- `contains`
- `!contains`
- `in~`
- `case()`
- `extend`
- `strcat()`
- `project`
- `order by`

The main focus is combining the execution location with parent-process context to make each result easier to interpret.

---

## KQL Query

```kql
// Day 7 - Execution from User-Writable Locations
// Identifies processes launched from user-controlled or
// potentially writable locations outside temporary directories.

let Lookback = 7d;

let OfficeAndEmailProcesses = dynamic([
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
    "msaccess.exe",
    "mspub.exe",
    "visio.exe"
]);

let BrowserProcesses = dynamic([
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe"
]);

let DocumentAndArchiveProcesses = dynamic([
    "acrord32.exe",
    "acrobat.exe",
    "foxitpdfreader.exe",
    "7zfm.exe",
    "7zg.exe",
    "winrar.exe"
]);

let ShellAndScriptProcesses = dynamic([
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
]);

DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| extend NormalisedFolderPath = tolower(FolderPath)
| where NormalisedFolderPath !contains "\\appdata\\local\\temp\\"
| where NormalisedFolderPath !contains "\\windows\\temp\\"
| where NormalisedFolderPath !contains "\\temp\\"
| where NormalisedFolderPath !contains "\\tmp\\"
| extend WritableLocation = case(
    NormalisedFolderPath contains "\\downloads\\",
        "Downloads directory",
    NormalisedFolderPath contains "\\desktop\\",
        "Desktop directory",
    NormalisedFolderPath contains "\\users\\public\\",
        "Public user directory",
    NormalisedFolderPath contains "\\$recycle.bin\\",
        "Recycle Bin",
    NormalisedFolderPath contains "\\appdata\\roaming\\",
        "Roaming AppData",
    NormalisedFolderPath contains "\\appdata\\local\\",
        "Local AppData",
    NormalisedFolderPath contains "\\programdata\\",
        "ProgramData",
    NormalisedFolderPath contains "\\onedrive",
        "OneDrive-synchronised directory",
    "Other"
)
| where WritableLocation != "Other"
| extend ParentContext = case(
    InitiatingProcessFileName in~ (OfficeAndEmailProcesses),
        "Office or email application",
    InitiatingProcessFileName in~ (BrowserProcesses),
        "Web browser",
    InitiatingProcessFileName in~ (DocumentAndArchiveProcesses),
        "Document reader or archive utility",
    InitiatingProcessFileName in~ (ShellAndScriptProcesses),
        "Shell or script interpreter",
    InitiatingProcessFileName =~ "explorer.exe",
        "Windows Explorer",
    "Other"
)
| extend ReviewContext = case(
    WritableLocation == "Recycle Bin",
        "Process executed from the Recycle Bin",
    ParentContext != "Other",
        strcat(
            ParentContext,
            " launched a process from ",
            WritableLocation
        ),
    ProcessTokenElevation =~ "TokenElevationTypeFull",
        strcat(
            "Elevated process executed from ",
            WritableLocation
        ),
    strcat(
        "Process executed from ",
        WritableLocation
    )
)
| project
    Timestamp,
    DeviceName,
    AccountDomain,
    AccountName,
    WritableLocation,
    ParentContext,
    ReviewContext,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessVersionInfoCompanyName,
    ProcessVersionInfoProductName,
    ProcessVersionInfoOriginalFileName,
    ProcessIntegrityLevel,
    ProcessTokenElevation,
    IsProcessRemoteSession,
    SHA1,
    ProcessId,
    ProcessUniqueId,
    InitiatingProcessId,
    InitiatingProcessUniqueId,
    DeviceId,
    ReportId
| order by Timestamp desc
```

---

## How the Query Works

The query searches process activity from the previous seven days:

```kql
| where Timestamp >= ago(Lookback)
```

The executable path is converted to lowercase to keep path comparisons consistent:

```kql
| extend NormalisedFolderPath = tolower(FolderPath)
```

Temporary directories are then excluded because they were investigated on Day 6:

```kql
| where NormalisedFolderPath !contains "\\temp\\"
| where NormalisedFolderPath !contains "\\tmp\\"
```

The `case()` function assigns each remaining process to a location category.

---

## Location Categories

| Path contains | Location category |
|---|---|
| `\Downloads\` | Downloads directory |
| `\Desktop\` | Desktop directory |
| `\Users\Public\` | Public user directory |
| `\$Recycle.Bin\` | Recycle Bin |
| `\AppData\Roaming\` | Roaming AppData |
| `\AppData\Local\` | Local AppData |
| `\ProgramData\` | ProgramData |
| `\OneDrive` | OneDrive-synchronised directory |

These locations are not automatically suspicious.

For example, many applications legitimately install or update themselves inside AppData, while business files may commonly be opened from OneDrive.

---

## Parent-Process Context

The query categorises the process responsible for launching the executable:

| Parent process type | Parent context |
|---|---|
| Word, Excel, Outlook or another Office application | Office or email application |
| Chrome, Edge, Firefox or another browser | Web browser |
| PDF reader or archive utility | Document reader or archive utility |
| PowerShell, Command Prompt or script host | Shell or script interpreter |
| `explorer.exe` | Windows Explorer |
| Anything else | Other |

This context may help identify how the executable was launched.

For example:

```text
chrome.exe
    └── C:\Users\User\Downloads\update.exe
```

may indicate that a recently downloaded file was executed through the browser or its download interface.

Similarly:

```text
winrar.exe
    └── C:\Users\User\Downloads\invoice.exe
```

may indicate execution following extraction from an archive.

---

## Review Context

The `ReviewContext` column combines the location and parent-process information into a readable explanation.

Examples include:

```text
Web browser launched a process from Downloads directory
```

```text
Document reader or archive utility launched a process from Desktop directory
```

```text
Shell or script interpreter launched a process from Roaming AppData
```

```text
Process executed from the Recycle Bin
```

The `strcat()` function is used to combine the different text values.

These descriptions provide context but should not be treated as severity ratings.

---

## Expected Results

The query may identify activity such as:

```text
C:\Users\User\Downloads\setup.exe
```

```text
C:\Users\User\Desktop\invoice.exe
```

```text
C:\Users\User\AppData\Roaming\update.exe
```

```text
C:\Users\Public\Documents\remote-tool.exe
```

```text
C:\ProgramData\Application\service.exe
```

```text
C:\$Recycle.Bin\S-1-5-21-...\payload.exe
```

Results should be reviewed alongside:

- The complete executable path
- The file hash
- The original filename
- The software company information
- The parent process
- The user account
- The process command line
- The process elevation level
- Whether the process was launched through a remote session
- Subsequent process, file and network activity

---

## Potential False Positives

Legitimate results may include:

- Software installed per user
- Application auto-updaters
- Browser downloads
- Portable applications
- OneDrive-synchronised applications or files
- Software deployment packages
- Helpdesk tools
- Internally developed applications
- Approved remote-support utilities
- Applications installed within AppData
- Programs extracted from legitimate archives
- Security testing

AppData and ProgramData may produce a particularly large number of legitimate results.

Known publishers, hashes, paths and command-line patterns can be excluded after they have been reviewed.

---

## Limitations

This query does not prove that a file executed from a user-writable location is malicious.

It may also miss:

- Payloads copied into trusted directories before execution
- Scripts launched through an interpreter in a trusted directory
- Fileless or memory-only execution
- Executables stored in user-writable locations not covered by the query
- Network shares and removable media
- Malicious files launched under renamed paths
- Files deleted immediately after execution

`FolderPath` identifies where the executable ran from. It does not necessarily reveal where the file was originally downloaded or created.

Permissions may also differ between devices. A directory identified by this query may not be writable by every user in every environment.

---

## References

- [Microsoft Defender XDR — DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Microsoft Learn — contains Operator](https://learn.microsoft.com/en-us/kusto/query/contains-operator)
- [Microsoft Learn — case()](https://learn.microsoft.com/en-us/kusto/query/case-function)
- [Microsoft Learn — tolower()](https://learn.microsoft.com/en-us/kusto/query/tolower-function)
- [Microsoft Learn — strcat()](https://learn.microsoft.com/en-us/kusto/query/strcat-function)
- [MITRE ATT&CK — T1204.002: User Execution — Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK — User Execution Detection Strategy](https://attack.mitre.org/detectionstrategies/DET0294/)

---

## Disclaimer

This query is intended for threat hunting, research and educational use.

It should be tested and tuned against the target environment before being used as a production detection.
