# Day 8 - Email Links Opened Without Safe Links

Day 8 brings an email topic forward from the Days 51-60 block. It looks for links from delivered email that a user went on to open in a browser, where Microsoft Defender for Office 365 Safe Links shows no sign of having checked the click.

This is a step up in complexity from Days 1-7: it correlates four tables across email and endpoint telemetry rather than searching a single table.

---

## Objective

Identify email links that were opened without Safe Links time-of-click protection.

Safe Links can only record the clicks it sees. A user who copies a link into the browser, opens the email in a client that doesn't support Safe Links, or falls outside the Safe Links policy reaches the site with no time-of-click check at all.

The query therefore looks for an absence: a browser visit that matches a link in the user's email, with no Safe Links record for that click.

---

## Scenario

Safe Links checks a URL at the moment it is clicked, so a link that was harmless when the email arrived but weaponised later can still be blocked.

That protection only applies when the click passes through Safe Links. Gaps can appear when:

- A user copies and pastes a link instead of clicking it
- A mail client without Safe Links support is used
- A URL is on the policy's "Do not rewrite the following URLs" list
- A user isn't covered by a Safe Links policy
- Another service wraps links before Defender for Office 365 processes them

Finding these clicks shows where users are exposed to links that were never checked at time of click.

---

## Data Source

This query uses:

- `EmailEvents` - delivered inbound messages and their recipients
- `EmailUrlInfo` - the URLs found in each message
- `UrlClickEvents` - clicks checked by Safe Links
- `DeviceNetworkEvents` - browser network activity from Microsoft Defender for Endpoint

Email tables require Microsoft Defender for Office 365. `DeviceNetworkEvents` requires devices onboarded to Microsoft Defender for Endpoint.

---

## MITRE ATT&CK

- **T1566.002 - Phishing: Spearphishing Link**
- **T1204.001 - User Execution: Malicious Link**

The query does not detect malicious links by itself. It identifies link clicks that bypassed a control designed to catch them.

---

## KQL Concepts

Day 8 introduces or reinforces:

- `let`
- `dynamic`
- `ago()`
- `join kind=inner`
- `join kind=leftanti`
- Joining on multiple columns with `$left` and `$right`
- `between`
- `extract()` with a regular expression
- `bin()`
- `distinct`
- `summarize`
- `min()`
- `make_set()`
- `in~`
- `endswith`

The main focus is correlation: matching email data to endpoint data by user, domain and time, then using anti-joins to remove the clicks Safe Links did handle.

---

## KQL Query

```kql
// Day 8 - Email Links Opened Without Safe Links
// Email links clicked in a browser with no sign that Safe Links checked the click.
// Signals that Safe Links DID handle a click, both excluded here:
//   1. a UrlClickEvents record for that user and that email (wrapped links, and
//      unwrapped links checked through the Outlook Safe Links API)
//   2. the device contacting the Safe Links host just before the visit (a wrapped click)

let lookback = 7d;
let clickWindow = 2h;   // how soon after delivery a visit counts as following the email

let Browsers = dynamic([
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "iexplore.exe"
]);

// Sending domains to leave out after review (exact domain match, case-insensitive)
let ExcludedDomains = dynamic([]);

let EmailLinks =
    EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
    | where SenderFromDomain !in~ (ExcludedDomains)
    | project DeliveryTime = Timestamp, NetworkMessageId,
              Recipient = tolower(RecipientEmailAddress), SenderFromAddress, Subject
    | join kind=inner (
        EmailUrlInfo
        | where Timestamp > ago(lookback)
        | project NetworkMessageId, Url, UrlDomain = tolower(UrlDomain)
      ) on NetworkMessageId
    // SharePoint and OneDrive links are never wrapped by design; drop them to cut noise
    | where not(UrlDomain endswith "sharepoint.com" or UrlDomain endswith "onedrive.com");

let DeviceVisits =
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where InitiatingProcessFileName in~ (Browsers)   // drops Outlook rendering images on open
    | where isnotempty(RemoteUrl) and isnotempty(InitiatingProcessAccountUpn)
    | project VisitTime = Timestamp, DeviceName, InitiatingProcessFileName,
              VisitUser = tolower(InitiatingProcessAccountUpn),
              VisitDomain = tolower(extract(@"^(?:[a-zA-Z]+://)?([^/:]+)", 1, RemoteUrl));

let SafeLinksClicks =
    UrlClickEvents
    | where Timestamp > ago(lookback)
    | distinct Recipient = tolower(AccountUpn), NetworkMessageId;

// 5-minute bins: a hop and visit straddling a bin edge can slip through (limit of a cheap match)
let SafeLinksHops =
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteUrl has "safelinks.protection.outlook.com"
    | distinct DeviceName, HopBin = bin(Timestamp, 5m);

EmailLinks
| join kind=inner DeviceVisits
    on $left.Recipient == $right.VisitUser, $left.UrlDomain == $right.VisitDomain
| where VisitTime between (DeliveryTime .. (DeliveryTime + clickWindow))
| join kind=leftanti SafeLinksClicks on Recipient, NetworkMessageId
| extend HopBin = bin(VisitTime, 5m)
| join kind=leftanti SafeLinksHops on DeviceName, HopBin
| summarize FirstVisit = min(VisitTime), Visits = count(),
            Devices = make_set(DeviceName, 5), Browsers = make_set(InitiatingProcessFileName, 5),
            Urls = make_set(Url, 5)
    by Recipient, NetworkMessageId, SenderFromAddress, Subject, UrlDomain, DeliveryTime
| order by FirstVisit desc
```

---

## How the Query Works

The query is built from four parts, then combined.

**1. Which links were users sent? (`EmailLinks`)**

Delivered inbound email from the last seven days is joined to the URLs found in each message:

```kql
| join kind=inner (EmailUrlInfo ...) on NetworkMessageId
```

`NetworkMessageId` is the shared identifier for a message across the email tables. SharePoint and OneDrive links are removed because Safe Links no longer wraps them by design.

**2. Did the user then visit that site? (`DeviceVisits`)**

Browser network activity is taken from `DeviceNetworkEvents`. Outlook is deliberately left out: opening an email makes Outlook download its images from the sender's servers, which would look like a visit even though nothing was clicked.

`RemoteUrl` can hold either a full URL or just a host name, so `extract()` pulls out the host either way:

```kql
VisitDomain = tolower(extract(@"^(?:[a-zA-Z]+://)?([^/:]+)", 1, RemoteUrl))
```

A visit is matched to an email when it is the same user, the same domain, and within two hours of delivery:

```kql
| join kind=inner DeviceVisits
    on $left.Recipient == $right.VisitUser, $left.UrlDomain == $right.VisitDomain
| where VisitTime between (DeliveryTime .. (DeliveryTime + clickWindow))
```

**3. Remove clicks Safe Links handled**

Safe Links leaves two kinds of evidence, and either one rules a click out.

- **A click record.** Every click Safe Links checks is written to `UrlClickEvents`. That includes wrapped links and unwrapped links checked through the Safe Links API in supported Outlook clients. A `leftanti` join keeps only rows with no matching record for that user and message:

```kql
| join kind=leftanti SafeLinksClicks on Recipient, NetworkMessageId
```

- **A wrapped-link hop.** A wrapped link sends the browser to the Safe Links service first, then on to the real site. If the same device contacted the Safe Links host in the same five-minute window, the click went through Safe Links:

```kql
| extend HopBin = bin(VisitTime, 5m)
| join kind=leftanti SafeLinksHops on DeviceName, HopBin
```

**4. Summarise**

The remaining activity is grouped per recipient, message and domain, with the first visit time, number of visits, devices, browsers and the original URLs.

---

## Expected Results

Each row is a link from a delivered email that the recipient's browser reached soon after delivery, with no evidence of a Safe Links check.

Common explanations include:

- The user copied the link into the browser instead of clicking it
- The email was read in a client without Safe Links support
- The URL is on the policy's "Do not rewrite" list
- The user is not covered by a Safe Links policy

Results should be reviewed alongside:

- The user's Safe Links policy coverage
- The mail client used to read the message
- The original URL and its reputation
- The sender and whether the message was later reported or removed
- Subsequent device activity after the visit

---

## Potential False Positives

The match is on domain, not on the exact URL, because network telemetry usually only records the host name.

Legitimate results may include:

- A user visiting a popular domain independently (for example, receiving a newsletter from a site they also browse directly)
- Large shared platforms and content delivery networks
- Internal or partner sites users visit throughout the day

Reviewed sending domains can be added to `ExcludedDomains`:

```kql
let ExcludedDomains = dynamic(["example.com", "vendor.com"]);
```

---

## Limitations

This query does not prove that a link was malicious or that Safe Links failed.

It may also miss:

- Clicks made later than the `clickWindow` after delivery
- Users whose email address differs from the account name recorded on the device (for example, an alias)
- Clicks from devices not onboarded to Defender for Endpoint, including personal phones
- Links where the visited host differs from the domain in the email, such as a redirect to another site

The five-minute bins are approximate. A Safe Links hop and a visit either side of a bin boundary will not match, so a protected click can occasionally appear as a result.

If a policy uses "Do not rewrite URLs, do checks via SafeLinks API only", clicks in supported Outlook clients produce `UrlClickEvents` records but no wrapped-link hop. The click-record check covers this case.

---

## References

- [Microsoft Defender for Office 365 - Safe Links overview](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)
- [Microsoft Defender XDR - EmailEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)
- [Microsoft Defender XDR - EmailUrlInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table)
- [Microsoft Defender XDR - UrlClickEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table)
- [Microsoft Defender XDR - DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [Microsoft Learn - join operator](https://learn.microsoft.com/en-us/kusto/query/join-operator)
- [Microsoft Learn - extract()](https://learn.microsoft.com/en-us/kusto/query/extract-function)
- [Microsoft Learn - bin()](https://learn.microsoft.com/en-us/kusto/query/bin-function)
- [MITRE ATT&CK - T1566.002: Phishing - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK - T1204.001: User Execution - Malicious Link](https://attack.mitre.org/techniques/T1204/001/)

---

## Disclaimer

This query is intended for threat hunting, research and educational use.

It should be tested and tuned against the target environment before being used as a production detection.
