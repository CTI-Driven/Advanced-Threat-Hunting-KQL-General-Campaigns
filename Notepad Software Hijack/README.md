# Notepad++ Software Hijack — KQL Advanced Hunting 

## Summary
This advanced hunting KQL query hunts for indicators of the recent Notepad++ software hijacking campaign involving abuse of the trusted updater (gup.exe).

## TTPs and Threat Hunting Hypothesis in Scope

- **`gup.exe` making network connections to domains other than** `notepad-plus-plus.org`, `github.com`, or `release-assets.githubusercontent.com`.
- **`gup.exe` spawning unusual child processes;** under normal behavior, it should only spawn `explorer.exe` or legitimate Notepad++ installer processes with valid GlobalSign digital signatures.
- **Suspicious files such as** `update.exe`, `AutoUpdater.exe`, or other anomalous executables written by `gup.exe` to the user TEMP directory.
- **DLL sideloading involving** `BluetoothService.exe` loading a malicious `log.dll` backdoor.
- **Indicators of** Cobalt Strike beaconing and/or Metasploit downloader command-and-control activity.  

## ATT&CK Techniques

| Tactic              | Technique Name                          | Technique ID |
|---------------------|-----------------------------------------|--------------|
| Execution           | Command and Scripting Interpreter       | T1059        |
| Defense Evasion     | Masquerading                            | T1036        |
| Command and Control | Ingress Tool Transfer                   | T1105        |
| Persistence,Pri,Def | Hijack Execution Flow: DLL              | T1574.001    |
| Command and Control | Encrypted Channel                       | T1573        |
| Exfiltration        | Exfiltration Over C2 Channel            | T1041        |

### Hunting Opportunities (KQL)

```kql
// gup.exe making network requests for other than:
// notepad-plus-plus.org, github.com and release-assets.githubusercontent.com,
// along with any related alerts tied to those events.
let NotepadDomain = "notepad-plus-plus.org";
let BrowserProcesses = dynamic([
    @"\chrome\application\chrome.exe",
    @"\edge\application\msedge.exe",
    @"\firefox\application\firefox.exe",
    @"\Program Files\Internet Explorer\iexplore.exe"
]);
let BeaconC2ServerDomain = dynamic([
    "cdncheck.it.com",
    "safe-dns.it.com",
    "api.skycloudcenter.com"
]);
let timeframe = 90d;
let GupNetworkSuspicious = (
    DeviceNetworkEvents
    | where Timestamp >= ago(timeframe)
    | extend Hypothesis = "Suspicious gup.exe network connection"
    | where isnotempty(DeviceId)
    | where ActionType == "ConnectionSuccess"
    | where isnotempty(RemoteUrl) and RemoteIPType == "Public"
    | where RemoteUrl !contains NotepadDomain
    | where InitiatingProcessParentFileName == "notepad++.exe"
    | where InitiatingProcessFolderPath contains @"\updater\gup.exe"
        or InitiatingProcessVersionInfoFileDescription == "WinGup for Notepad++"
    | where not(InitiatingProcessCommandLine has_any (".githubusercontent.com", "github.com"))
        and not(RemoteUrl has_any (".githubusercontent.com", "github.com"))
    | join kind=leftouter (
        AlertEvidence
        | where Timestamp >= ago(timeframe)
        | where isnotempty(DeviceId)
    ) on DeviceId
);
// gup.exe for unusual process subspawns — it should only spawn explorer.exe,
// and npp* themed Notepad++ installers. For 8.8.8 and 8.8.7 they should have
// valid digital signatures signed by GlobalSign.
let GupUnusualChildProcs = (
    DeviceProcessEvents
    | where Timestamp >= ago(timeframe)
    | extend Hypothesis = "Suspicious gup.exe child process"
    | where InitiatingProcessFileName == "gup.exe"
        and InitiatingProcessVersionInfoProductName == "WinGup for Notepad++"
    | where not(FolderPath has_any (BrowserProcesses))
        and not(FolderPath has_any ("C:\\Windows\\explorer.exe"))
    | invoke FileProfile()
    | where IsCertificateValid != "1"
        and not(Issuer has_any ("GlobalSign", "Notepad++ Root Certificate"))
);
// Files called update.exe or AutoUpdater.exe in the user TEMP folder, where gup.exe has written a file.
let GupTempUpdaters = (
    DeviceFileEvents
    | where Timestamp >= ago(timeframe)
    | extend Hypothesis = "gup.exe temp updater file activity"
    | where ActionType in~ ("FileRenamed", "FileCreated")
    | where InitiatingProcessFileName == "gup.exe"
        or InitiatingProcessVersionInfoProductName == "WinGup for Notepad++"
    | where FolderPath has "\\Temp\\"
        and (FolderPath endswith "AutoUpdater.exe"
            or FolderPath endswith "update.exe")
);
//DLL sideloading BluetoothService.exe -> log.dll
let GupDLLSideloading = (
    DeviceImageLoadEvents
    | where Timestamp >= ago(timeframe)
    | extend Hypothesis = "DLL sideloading BluetoothService.exe -> log.dll"
    | where FileName =~ "log.dll"
        and (InitiatingProcessFileName startswith "BluetoothService"
            or InitiatingProcessVersionInfoFileDescription contains "Bitdefender ")
            or ( SHA256 =~ "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad"
                 and InitiatingProcessSHA256 =~ "2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924")
);
//Cobalt Strike Beacon C2 server and/or Metasploit downloader
let GupC2AndDownloaderserver= (
    DeviceNetworkEvents
    | where Timestamp >= ago(timeframe)
    | extend Hypothesis = "Cobalt Strike Beacon C2 server and/or Metasploit downloader"
    | where RemoteUrl has_any (BeaconC2ServerDomain)
);
// All Combine
let Suspicious_notepad_gup_Activities = (
    union GupNetworkSuspicious, GupUnusualChildProcs, GupTempUpdaters, GupDLLSideloading, GupC2AndDownloaderserver
    | summarize arg_max(Timestamp, *) by DeviceId
    | order by Timestamp asc
    | project-reorder Hypothesis
);Suspicious_notepad_gup_Activities

```

## References:
- [rapid7](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)
- [doublepulsar](https://doublepulsar.com/small-numbers-of-notepad-users-reporting-security-woes-371d7a3fd2d9)
- [securelist](https://securelist.com/notepad-supply-chain-attack/118708/)
