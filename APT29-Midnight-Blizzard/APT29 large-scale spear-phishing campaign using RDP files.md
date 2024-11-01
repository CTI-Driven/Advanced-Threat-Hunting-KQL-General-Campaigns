# APT29 (Midnight Blizzard) large-scale spear-phishing campaign using RDP files

# Summary:
This advanced hunting query monitors domains and files associated with the ongoing APT29 (Midnight Blizzard) spear-phishing campaign. The campaign targets individuals in government, academia, defense, NGOs, and other sectors, aiming to deliver malicious RDP files for unauthorized access.

## Attribution & Threat Actor
- APT29 (Midnight Blizzard)

## Detection Opportunities (KQL):

```kusto
//Replace "Timestamp" with "TimeGenerated" when running this KQL query in Microsoft Sentinel.
let RdpFiles = externaldata(MD5: string , RdpFileName: string, Campaign: string, Ref: string )[@"https://raw.githubusercontent.com/CTI-Driven/Advanced-Threat-Hunting-KQL-General-Campaigns/refs/heads/main/APT29-Midnight-Blizzard/APT29-Midnight-Blizzard-RdpFileName.csv"] with (format="csv", ignoreFirstRecord=True);
let Domains = externaldata(Domains: string , Campaign: string, Ref: string)[@"https://raw.githubusercontent.com/CTI-Driven/Advanced-Threat-Hunting-KQL-General-Campaigns/refs/heads/main/APT29-Midnight-Blizzard/APT29-Midnight-Blizzard-Domains.csv"] with (format="csv", ignoreFirstRecord=True);
let RdpFilesName    =(RdpFiles | where isnotempty(RdpFileName) | distinct RdpFileName);
let RdpFilesMd5     =(RdpFiles | where isnotempty(MD5) | distinct MD5);
let DomainNames     =(Domains | where isnotempty(Domains) | distinct Domains);
let timeframe = 24hr;
let NetworkEvents =( DeviceNetworkEvents
| where Timestamp >= ago(timeframe)
| where ActionType in ("DnsConnectionInspected","ConnectionSuccess","ConnectionFailed")
| extend AdditionalFields_info = parse_json(AdditionalFields)
| where (AdditionalFields_info.query in~(DomainNames) or RemoteUrl in~(DomainNames)));
let UserClickEvents = (union  UrlClickEvents, EmailUrlInfo | where Timestamp >= ago(timeframe) | where Url has_any (DomainNames) or UrlDomain in~ (DomainNames));
let RdpFileEvents   = (DeviceFileEvents | where Timestamp >= ago(timeframe) | where FileName in~ (RdpFilesName) or MD5 in~ (RdpFilesMd5));
// Combine all detections
let Suspicious_APT29_Midnight_Blizzard_Activities= (
    union NetworkEvents, UserClickEvents, RdpFileEvents
    | summarize arg_max(Timestamp, *) by DeviceId
    | order by Timestamp asc
);Suspicious_APT29_Midnight_Blizzard_Activities
```

## ATT&CK Techniques:
1. **Resource Development**
    - **T1583.001 - Acquire Infrastructure: Domains**
2. **Initial Access**
    - **T1566.001 - Phishing: Spearphishing Attachment**
3. **Execution**
    - **T1204.002 - User Execution: Malicious File**  
4. **Discovery and Collection**
    - **T1083 - File and Directory Discovery**
    - **T1135 - Network Share Discovery**
    - **T1120 - Peripheral Device Discovery**
    - **T1115 - Clipboard Datal**

## References:
- https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/
- https://cert.gov.ua/article/6281076
- https://aws.amazon.com/blogs/security/amazon-identified-internet-domains-abused-by-apt29/
