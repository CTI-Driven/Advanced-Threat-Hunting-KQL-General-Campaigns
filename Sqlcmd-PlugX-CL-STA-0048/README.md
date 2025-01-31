# CL-STA-0048: An Espionage Operation Against High-Value Targets in South Asia, including a telecommunications organization.
 
## Summary
The advanced hunting queries below are designed to detect notable TTPs linked to an unidentified Chinese threat actor, tracked as CL-STA-0048 by the Palo Alto Networks Threat Research Center. This actor has been observed targeting high-value organizations in South Asia, including a telecommunications company.
## ATT&CK Techniques in Scope:
- **The Abuse of Sqlcmd.exe for Data Exfiltration**
  - T1005: Data from Local System
  - T1048: Exfiltration Over Alternative Protocol
 
- **PlugX Loader DLL Sideloading**
  - T1574.002: DLL Side-Loading
 
## Detection Opportunities
 
### The Abuse of Sqlcmd.exe for Data Exfiltration (KQL)
```kql
// Replace "Timestamp" with "TimeGenerated" when running this KQL query in Microsoft Sentinel.
let timeframe = 24hr;
let sqlcmdoptions1 = dynamic(["sqlcmd"," S", " Q ","SELECT "," >"]);
let sqlcmdoptions2 = dynamic(["sqlcmd","-S", "-Q ","SELECT "," >"]);
let sqlcmdoptions3 = dynamic(["sqlcmd","-S", "-Q ","SELECT "," O "]);
let sqlcmdoptions4 = dynamic(["sqlcmd","-S", "-Q ","SELECT ","-O "]);
DeviceProcessEvents
| where Timestamp >= ago(timeframe)
| where  ProcessCommandLine has_all (sqlcmdoptions1)
      or ProcessCommandLine has_all (sqlcmdoptions2)
      or ProcessCommandLine has_all (sqlcmdoptions3)
      or ProcessCommandLine has_all (sqlcmdoptions4)
```
 
### PlugX Loader DLL Sideloading (KQL)
```kql
// Replace "Timestamp" with "TimeGenerated" when running this KQL query in Microsoft Sentinel.
let timeframe = 24hr;
DeviceFileEvents
| where Timestamp >= ago(timeframe)
| where ActionType == "FileCreated" and FileName =="Acrobat.dll" and InitiatingProcessFolderPath != "c:\\windows\\system32\\msiexec.exe"
| join kind=inner (DeviceImageLoadEvents
| where ActionType =="ImageLoaded" and FileName =="Acrobat.dll"
| invoke FileProfile() | where not(Signer has_any ("Adobe Inc.","Adobe Systems, Incorporated"))) on FileName
```
 
## References:
- [https://unit42.paloaltonetworks.com/espionage-campaign-targets-south-asian-entities/](https://unit42.paloaltonetworks.com/espionage-campaign-targets-south-asian-entities/)
