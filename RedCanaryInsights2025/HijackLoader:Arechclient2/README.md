# Encoded PowerShell Execution Leading to Payloads Deployment and Arechclient2, aka SectopRAT(``Remote access tool (RAT) that also contains information stealer capabilities``)
## Summary

This hunting query detects encoded PowerShell commands that initiate external network connections and drop archive or executable payloads to disk—a behavior pattern commonly observed in the early stages of infections involving loaders, HijackLoader, and remote access tools (RATs). These actions are typically followed by Command and Control (C2) communication, enabling threat actors to deploy follow-on payloads such as info-stealers or ransomware.

## Threat Scope

- PowerShell commands containing base64-encoded strings
- PowerShell initiating external network connections (e.g., HTTP/S, TCP)
- PowerShell writing archive or executable files (e.g., `.exe`, `.zip`) to disk
- Subsequent C2 communication, often observed in Arechclient2 infections

## ATT&CK Techniques

| Tactic              | Technique Name                          | Technique ID |
|---------------------|------------------------------------------|--------------|
| Execution           | PowerShell                              | T1059.001    |
| Defense Evasion     | Deobfuscate/Decode Files or Information | T1140        |
| Command and Control | Non-Standard Port                       | T1571        |

## Detection Opportunities

### Encoded PowerShell Execution Leading to Payloads Deployment and Arechclient2, aka SectopRAT Connectivity

```kql
let timeframe = 24hr;
let Deobfuscated_command_has_external_netconn=( DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where ProcessVersionInfoInternalFileName =="POWERSHELL"
| where ProcessCommandLine matches regex @'(\s+-((?i)encod?e?d?c?o?m?m?a?n?d?|e|en|enc|ec|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman)\s).*'
| extend DecodedCommand = replace(@'\x00','', base64_decode_tostring(extract("[A-Za-z0-9+/]{50,}[=]{0,2}",0 , ProcessCommandLine)))
| join kind=inner ( DeviceNetworkEvents
                    | where Timestamp > ago(timeframe)
                    | where (ActionType=="ConnectionSuccess" and RemoteIPType == "Public" and InitiatingProcessUniqueId!="0")
                    ) on $left.DeviceName==$right.DeviceName and $left.ProcessUniqueId == $right.InitiatingProcessUniqueId
| distinct  process_execution_timestamp=Timestamp,external_netconn_timestamp=Timestamp1,DeviceName,LocalIP,LocalPort,ProcessCommandLine,DecodedCommand,InitiatingProcessCommandLine,AccountName,AccountDomain,ActionType1,RemoteIP,RemotePort,RemoteUrl);
DeviceFileEvents
| where Timestamp > ago(timeframe)
| where ActionType has_any("FileCreated")
| extend FileType = tostring(parse_json(AdditionalFields).FileType)
| where FileType has_any ("Zip","PortableExecutable") and (isnotempty(FileOriginReferrerUrl) or isnotempty(FileOriginUrl))
| join kind=inner (Deobfuscated_command_has_external_netconn) on DeviceName
| where Timestamp between (process_execution_timestamp .. +20m)
| join kind=leftouter (
DeviceNetworkEvents
| where Timestamp > ago(timeframe)
| where (Protocol == "Tcp"
         and InitiatingProcessFileName endswith ".exe"
         and RemotePort in ("15647","15678","15649","15847")
         and RemoteIPType == "Public")
) on DeviceName
```

## References:
- [Red Canary: April 2025 Threat Intelligence Insights](https://redcanary.com/blog/threat-intelligence/intelligence-insights-april-2025/)
