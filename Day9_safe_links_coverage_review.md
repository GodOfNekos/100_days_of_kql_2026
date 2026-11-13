# Day 9 - Safe Links Coverage Review

Day 9 builds on Day 8. Instead of starting from browser activity, it starts from every delivered email that contained links and checks what evidence exists that Microsoft Defender for Office 365 scanned and protected those links.

Each message is given a status, so the results read as a prioritised review list rather than a raw event dump.

---

## Objective

For a chosen time window, identify delivered email with links where Safe Links protection may not have applied, and rank them by how concerning the gap is.

This is useful:

- After a Safe Links policy change
- After a reported Microsoft 365 service issue affecting URL scanning
- As a periodic check that link protection is working as expected

---

## Scenario

Defender for Office 365 scans URLs before delivery and, through Safe Links, again at the time of click. If either step is missing, users may receive or open links that were never checked.

Gaps can appear when:

- URL scanning didn't produce a record for a message
- A Safe Links click returned an error page or was still scanning
- A user clicked through a Safe Links warning
- A link was opened from Outlook without being rewritten

---

## Data Source

This query uses:

- `EmailEvents` - delivered inbound messages with URLs
- `EmailUrlInfo` - URL scan and extraction records
- `UrlClickEvents` - clicks checked by Safe Links
- `DeviceEvents` - Outlook launching a browser to open a URL (Microsoft Defender for Endpoint)

Email tables require Microsoft Defender for Office 365. `DeviceEvents` requires devices onboarded to Microsoft Defender for Endpoint.

---

## MITRE ATT&CK

- **T1566.002 - Phishing: Spearphishing Link**
- **T1204.001 - User Execution: Malicious Link**

As with Day 8, the query identifies gaps in a protective control rather than malicious links directly.

---

## KQL Concepts

Day 9 introduces or reinforces:

- `let`
- `ago()` and `now()`
- `between`
- `summarize` with `count()`, `countif()`, `dcount()` and `sum()`
- `make_set()`
- `take_any()`
- `parse_url()`
- `join kind=leftouter`
- `join kind=inner`
- `distinct`
- `coalesce()`
- `case()`
- `startswith` and `!startswith`

The main focus is building several evidence sets, joining them back onto one list of messages with `leftouter` joins, and turning the combined evidence into a single status with `case()`.

---

## KQL Query

```kql
// Day 9 - Safe Links Coverage Review
// Delivered email with links, ranked by how much evidence there is that
// Safe Links scanned and protected those links during the review window.

// Review window: last 24 hours by default.
// For a specific period use datetime(), for example datetime(2026-01-01T09:00:00Z).
let WindowStart = ago(24h);
let WindowEnd = now();

// Sending domains to leave out after review (exact domain match, case-insensitive)
let ExcludedDomains = dynamic([]);

// Delivered inbound messages that contained URLs
let Msgs = EmailEvents
    | where Timestamp between (WindowStart .. WindowEnd)
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered" and UrlCount > 0
    | where SenderFromDomain !in~ (ExcludedDomains)
    | extend Upn = tolower(RecipientEmailAddress)
    | project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, Upn, Subject,
              UrlCount, LatestDeliveryLocation, ThreatTypes, DetectionMethods;

// URL scan/extraction evidence
let UrlScan = EmailUrlInfo
    | where Timestamp between ((WindowStart - 1h) .. WindowEnd)
    | summarize ScannedUrls = dcount(Url), ScannedDomains = make_set(UrlDomain, 50) by NetworkMessageId;

// Safe Links click-time evidence
let SLClicks = UrlClickEvents
    | where Timestamp between (WindowStart .. WindowEnd)
    | extend Upn = tolower(AccountUpn)
    | summarize SafeLinksClicks = count(),
                SLProblemClicks = countif(ActionType in ("UrlErrorPage","UrlScanInProgress") or IsClickedThrough == true),
                SLActions = make_set(ActionType)
      by NetworkMessageId, Upn;

// Links opened from Outlook that were NOT Safe Links wrapped (needs Defender for Endpoint)
let UnwrappedClicks = DeviceEvents
    | where Timestamp between (WindowStart .. WindowEnd)
    | where ActionType == "BrowserLaunchedToOpenUrl"
    | where InitiatingProcessFileName in~ ("outlook.exe","olk.exe")
    | where RemoteUrl startswith "http" and RemoteUrl !contains "safelinks.protection.outlook.com"
    | extend Upn = tolower(InitiatingProcessAccountUpn), UrlDomain = tostring(parse_url(RemoteUrl).Host)
    | summarize Clicks = count(), ExampleUrl = take_any(RemoteUrl) by Upn, UrlDomain;

let UnwrappedByMsg = Msgs
    | join kind=inner (EmailUrlInfo
        | where Timestamp between ((WindowStart - 1h) .. WindowEnd)
        | distinct NetworkMessageId, UrlDomain) on NetworkMessageId
    | distinct NetworkMessageId, Upn, UrlDomain
    | join kind=inner UnwrappedClicks on Upn, UrlDomain
    | summarize UnwrappedClicks = sum(Clicks), UnwrappedUrls = make_set(ExampleUrl, 20) by NetworkMessageId, Upn;

Msgs
| join kind=leftouter UrlScan on NetworkMessageId
| join kind=leftouter SLClicks on NetworkMessageId, Upn
| join kind=leftouter UnwrappedByMsg on NetworkMessageId, Upn
| extend ScannedUrls = coalesce(ScannedUrls, 0),
         SafeLinksClicks = coalesce(SafeLinksClicks, 0),
         SLProblemClicks = coalesce(SLProblemClicks, 0),
         UnwrappedClicks = coalesce(UnwrappedClicks, 0)
| extend Status = case(
    UnwrappedClicks > 0,        "1-CRITICAL: Unwrapped link clicked - URL NOT rewritten",
    ScannedUrls == 0,           "2-HIGH: URLs present but no URL scan record",
    SLProblemClicks > 0,        "3-HIGH: Safe Links click-time error / clicked through",
    ScannedUrls < UrlCount,     "4-REVIEW: Fewer URLs scanned than in message",
                                "5-OK: URLs scanned")
| where Status !startswith "5-OK"
| project Timestamp, Status, Recipient = Upn, SenderFromAddress, Subject, InternetMessageId, NetworkMessageId,
          UrlCount, ScannedUrls, SafeLinksClicks, SLProblemClicks, SLActions,
          UnwrappedClicks, UnwrappedUrls, ScannedDomains, LatestDeliveryLocation, ThreatTypes, DetectionMethods
| order by Status asc, Timestamp asc
```

---

## How the Query Works

**1. The messages to review (`Msgs`)**

Delivered inbound email in the window that contained at least one URL (`UrlCount > 0`). This is the base list every other part is joined back onto.

**2. Evidence sets**

Three separate summaries are built, each keyed so it can be joined back onto the messages:

| Evidence set | Source | What it shows |
|---|---|---|
| `UrlScan` | `EmailUrlInfo` | How many distinct URLs were recorded for each message |
| `SLClicks` | `UrlClickEvents` | Safe Links clicks per message and user, and how many had a problem |
| `UnwrappedByMsg` | `DeviceEvents` + `EmailUrlInfo` | Links opened from Outlook without a Safe Links address, matched to messages by user and domain |

`UrlScan` and `UnwrappedByMsg` look back one hour before the window start, so URLs recorded slightly before delivery are still counted.

**3. Combining the evidence**

`leftouter` joins keep every message, even those with no evidence in a set. Missing values are then set to zero with `coalesce()`:

```kql
| extend ScannedUrls = coalesce(ScannedUrls, 0)
```

**4. Status**

`case()` checks the conditions in order and assigns the first one that applies:

| Status | Meaning |
|---|---|
| 1-CRITICAL | A link from the message was opened from Outlook without being rewritten |
| 2-HIGH | The message had URLs but no URL scan record exists |
| 3-HIGH | A Safe Links click returned an error, was still scanning, or the user clicked through a warning |
| 4-REVIEW | Fewer URLs were recorded than the message contained |
| 5-OK | URLs were scanned, nothing else flagged (filtered out) |

The number prefix makes `order by Status asc` list the most serious results first.

---

## Assumptions to Verify

Some values used in this query are not listed on the Microsoft Learn schema pages, which only give examples or point to the in-portal schema reference:

- `UrlErrorPage` and `UrlScanInProgress` as `UrlClickEvents` `ActionType` values
- `BrowserLaunchedToOpenUrl` as a `DeviceEvents` `ActionType` value

If a value doesn't exist in an environment, the related status will silently never trigger. Check which values are present before relying on the results:

```kql
UrlClickEvents
| where Timestamp > ago(7d)
| summarize count() by ActionType
```

```kql
DeviceEvents
| where Timestamp > ago(7d)
| summarize count() by ActionType
| where ActionType has "Browser"
```

---

## Expected Results

Results are messages that need review, most serious first.

- **1-CRITICAL** rows are the strongest signal: a user opened a link from the message in Outlook, and the URL opened was not a Safe Links address.
- **2-HIGH** rows may indicate a scanning gap, or a difference in how the URL tables recorded the message.
- **3-HIGH** rows show Safe Links did see the click, but it errored, was still scanning, or the user chose to continue past a warning.
- **4-REVIEW** rows are usually explained by how URLs are counted, but are worth sampling.

---

## Potential False Positives

Legitimate results may include:

- Policies configured with "Do not rewrite URLs, do checks via SafeLinks API only", where unwrapped links are expected in supported Outlook clients
- URLs on the "Do not rewrite the following URLs" list
- SharePoint and OneDrive links, which Safe Links no longer wraps by design
- Users clicking through warnings on sites that were later confirmed safe

Reviewed sending domains can be added to `ExcludedDomains`:

```kql
let ExcludedDomains = dynamic(["example.com", "vendor.com"]);
```

---

## Limitations

This query does not prove that Safe Links failed or that a link was malicious.

- `UnwrappedByMsg` matches by user and domain, not by exact URL, so a visit to the same domain from another source can be attributed to a message.
- `dcount()` returns an estimate. `UrlCount` and `EmailUrlInfo` may also count URLs differently, which is why mismatches are only marked for review.
- Users whose email address differs from the account name recorded on the device (for example, an alias) won't match in the endpoint correlation.
- Devices not onboarded to Defender for Endpoint, including personal phones, are not covered by the `DeviceEvents` check.
- For clicks from Drafts and Sent Items, `NetworkMessageId` may be unavailable in `UrlClickEvents`, so those clicks won't join to messages.

---

## References

- [Microsoft Defender for Office 365 - Safe Links overview](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)
- [Microsoft Defender XDR - EmailEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)
- [Microsoft Defender XDR - EmailUrlInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table)
- [Microsoft Defender XDR - UrlClickEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table)
- [Microsoft Defender XDR - DeviceEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)
- [Microsoft Learn - join operator](https://learn.microsoft.com/en-us/kusto/query/join-operator)
- [Microsoft Learn - coalesce()](https://learn.microsoft.com/en-us/kusto/query/coalesce-function)
- [Microsoft Learn - countif()](https://learn.microsoft.com/en-us/kusto/query/countif-aggregation-function)
- [Microsoft Learn - parse_url()](https://learn.microsoft.com/en-us/kusto/query/parse-url-function)
- [Microsoft Learn - case()](https://learn.microsoft.com/en-us/kusto/query/case-function)
- [MITRE ATT&CK - T1566.002: Phishing - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK - T1204.001: User Execution - Malicious Link](https://attack.mitre.org/techniques/T1204/001/)

---

## Disclaimer

This query is intended for threat hunting, research and educational use.

It should be tested and tuned against the target environment before being used as a production detection.
