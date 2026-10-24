# PHP2Shell: CVE-2026-109618 and CVE-2026-109619 Post-Exploitation Hunting on PHP Web Servers

## Summary

These advanced hunting queries detect post-exploitation behavior on PHP web servers affected by two critical PHP core vulnerabilities, CVE-2026-109618 and CVE-2026-109619, nicknamed “PHP2Shell”. The PHP security team rated both CVSS v4.0 9.2 and scheduled fixes for 21 October 2026 at 14:00 UTC.

Exploitation in the wild has been confirmed. On 24 October 2026, honeypot packet captures and process telemetry showed Apache workers (uid 33) starting /bin/sh after a four-stage multipart POST chain, followed by id, curl, wget and php -r callbacks to the attacker’s infrastructure. The observed chain is consistent with CVE-2026-109618. The records do not show a separate CVE-2026-109619 path.

The queries cover the process, file and network activity that follows a successful exploit: shells, interpreters and download tools spawned by a PHP or web server worker, reverse shell strings, files written to web roots, and connections to known source IPs. They do not detect the exploit requests themselves. Those need web server or packet logs, because the exploit stages produce PHP out-of-memory errors and worker crashes, and HTTP 200 responses are not a success signal.

Source IPs are hosting-provider addresses that can be reassigned. Treat them as hunting leads, not blocklists.


## ATT&CK Techniques in Scope:

* **PHP Worker Process Spawning Shells, Interpreters and Tools**
   * T1059: Command and Scripting Interpreter
   * T1105: Ingress Tool Transfer
   * T1033: System Owner/User Discovery
   * T1082: System Information Discovery
   * T1016: System Network Configuration Discovery
* **Reverse Shell Patterns Under PHP**
   * T1059.004: Unix Shell
* **Script Files Written to Web Roots**
   * T1505.003: Server Software Component: Web Shell
* **Exposure Assessment (context only, no detection)**
   * T1190: Exploit Public-Facing Application

## Detection Opportunities

### Exposure: Internet-Facing Devices With PHP Installed (KQL)

```kusto
//The software inventory list identifies devices where PHP is installed, but it does not confirm that PHP is actively used or running.
let LatestDeviceInfo =
    DeviceInfo
    | summarize arg_max(Timestamp, IsInternetFacing) by DeviceId
    | project DeviceId, IsInternetFacing;
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("CVE-2026-109618", "CVE-2026-109619")
| join kind=leftouter LatestDeviceInfo on DeviceId
| project DeviceName, DeviceId, OSPlatform, SoftwareName, SoftwareVersion,
          CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing
| order by IsInternetFacing desc, DeviceName asc
```

### Devices observed running PHP based on DeviceProcessEvents telemetry (PHP is actively used or running on the device)

```kusto
// I recommend starting with the list of devices where PHP process execution was observed in DeviceProcessEvents and does confirm that PHP is actively used or running
let ProcessLookback = 7d;
let ObservedPhpExecution =
    DeviceProcessEvents
    | where Timestamp >= ago(ProcessLookback)
    | where FileName matches regex
        @"(?i)^php([0-9.]*)?(-fpm|-cgi)?([0-9.]*)?(\.exe)?$"
    | summarize
        LastSeenTime_PhpExecution = max(Timestamp),
        ExecutedPhpProcesses = make_set(FileName, 20),
        PhpExecutablePaths = make_set_if(
            FolderPath,
            isnotempty(FolderPath),
            20
        )
        by DeviceId;
let LatestDeviceInfo =
    DeviceInfo
    | summarize arg_max(Timestamp, IsInternetFacing) by DeviceId
    | project DeviceId, IsInternetFacing;
DeviceTvmSoftwareInventory
| where isnotempty(DeviceName)
| where SoftwareName matches regex
    @"(?i)^php[0-9]*(\.[0-9]+)*(_for_linux)?$"
| join kind=inner ObservedPhpExecution on DeviceId
| join kind=leftouter LatestDeviceInfo on DeviceId
| summarize
    SoftwareVersion = make_set_if(
        SoftwareVersion,
        isnotempty(SoftwareVersion),
        50
    ),
    LastSeenTime_PhpExecution = max(LastSeenTime_PhpExecution),
    ExecutedPhpProcesses = take_any(ExecutedPhpProcesses),
    PhpExecutablePaths = take_any(PhpExecutablePaths),
    IsInternetFacing = any(IsInternetFacing)
    by DeviceName, DeviceId, OSPlatform, SoftwareName
| project
    DeviceName,
    OSPlatform,
    SoftwareName,
    SoftwareVersion,
    LastSeenTime_PhpExecution,
    ExecutedPhpProcesses,
    PhpExecutablePaths,
    IsInternetFacing
| order by IsInternetFacing desc, LastSeenTime_PhpExecution desc
```

### PHP Worker Spawning Shells, Interpreters, Download Tools and Recon Commands (KQL)

```kusto
let timeframe = 7d;
let PhpHostsIsInternetFacing =
    DeviceTvmSoftwareVulnerabilities
    | where CveId has_any ("CVE-2026-109618","CVE-2026-109619")
    | distinct DeviceId
    | join kind=inner (
        DeviceInfo
        | where Timestamp >= ago(7d)
        | where IsInternetFacing
        | distinct DeviceId
    ) on DeviceId
    | project DeviceId;
let PhpWorker = @"(?i)^(php-fpm[\d.]*|php-cgi[\d.]*)(\.exe)?$";
let WebServer = dynamic(["httpd","apache2"]);
let ShellRx = @"(?i)^(sh|dash|bash|cmd\.exe|powershell\.exe)$";
DeviceProcessEvents
| where Timestamp >= ago(timeframe)
| where DeviceId  has_any (PhpHostsIsInternetFacing)
| where InitiatingProcessAccountName !~ "root"
| extend ParentIsPhp = InitiatingProcessFileName matches regex PhpWorker
                    or InitiatingProcessFileName in~ (WebServer)
| extend GrandParentIsPhp = InitiatingProcessParentFileName matches regex PhpWorker
                         or InitiatingProcessParentFileName in~ (WebServer)
| extend ParentIsShell = InitiatingProcessFileName matches regex ShellRx
| where ParentIsPhp or (GrandParentIsPhp and ParentIsShell)
| extend Category = case(
    FileName matches regex ShellRx, "Shell",
    FileName matches regex @"(?i)^(python[\d.]*|perl[\d.]*|php[\d.]*)(\.exe)?$", "Interpreter",
    FileName matches regex @"(?i)^(curl|wget|nc(\..+)?|certutil)(\.exe)?$", "Download or network tool",
    FileName matches regex @"(?i)^(whoami|id|uname|ipconfig)(\.exe)?$", "Recon command",
    "")
| where isnotempty(Category)
| project Timestamp, DeviceName, DeviceId, Category, AccountName,
          InitiatingProcessAccountName,
          InitiatingProcessParentFileName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Reverse Shell Patterns Under PHP (KQL)

```kusto
let timeframe = 7d;
let PhpHostsIsInternetFacing =
    DeviceTvmSoftwareVulnerabilities
    | where CveId has_any ("CVE-2026-109618","CVE-2026-109619")
    | distinct DeviceId
    | join kind=inner (
        DeviceInfo
        | where Timestamp >= ago(7d)
        | where IsInternetFacing
        | distinct DeviceId
    ) on DeviceId
    | project DeviceId;
let PhpWorker = @"(?i)^(php-fpm[\d.]*|php-cgi[\d.]*)(\.exe)?$";
let WebServer = dynamic(["httpd","apache2"]);
let Shells = dynamic(["sh","dash","bash","cmd.exe","powershell.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(timeframe)
| where DeviceId has_any (PhpHostsIsInternetFacing)
| where InitiatingProcessAccountName !~ "root"
| extend ParentIsPhp = InitiatingProcessFileName matches regex PhpWorker
                    or InitiatingProcessFileName in~ (WebServer)
| extend GrandParentIsPhp = InitiatingProcessParentFileName matches regex PhpWorker
                         or InitiatingProcessParentFileName in~ (WebServer)
| where ParentIsPhp or (GrandParentIsPhp and InitiatingProcessFileName in~ (Shells))
| where ProcessCommandLine matches regex @"(?i)/dev/tcp/|fsockopen|mkfifo"
| project Timestamp, DeviceName, DeviceId, AccountName,
          InitiatingProcessParentFileName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Script Files Written to Web Roots by PHP or a Shell Under PHP (KQL)

```kusto
let timeframe = 24hr;
let PhpHostsIsInternetFacing =
    DeviceTvmSoftwareVulnerabilities
    | where CveId has_any ("CVE-2026-109618","CVE-2026-109619")
    | distinct DeviceId
    | join kind=inner (
        DeviceInfo
        | where Timestamp >= ago(7d)
        | where IsInternetFacing
        | distinct DeviceId
    ) on DeviceId
    | project DeviceId;
let WebRoots = dynamic(["/var/www/", \\inetpub\\wwwroot\\]);
let PhpWorker = @"(?i)^(php-fpm[\d.]*|php-cgi[\d.]*)(\.exe)?$";
let WebServer = dynamic(["httpd","apache2"]);
let Shells = dynamic(["sh","dash","bash","cmd.exe","powershell.exe"]);
let ScriptExt = @"(?i)\.(php\d*|phtml|phar|pht|ph|asp|aspx|ashx|asmx|jsp|jspx|pl|py|cgi|sh)$";
DeviceFileEvents
| extend EventTime = coalesce(column_ifexists("Timestamp", datetime(null)),column_ifexists("TimeGenerated", datetime(null)))
| where EventTime >= ago(timeframe)
| where DeviceId has_any (PhpHostsIsInternetFacing)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FolderPath has_any (WebRoots)
| where FileName matches regex @"(?i)\.(php\d*|phtml|phar|pht|ph|asp|aspx|ashx|asmx|jsp|jspx|pl|py|cgi|sh)$"
| extend ByPhp = InitiatingProcessFileName matches regex PhpWorker
              or InitiatingProcessFileName in~ (WebServer)
| extend ByShellUnderPhp = InitiatingProcessFileName in~ (Shells)
              and (InitiatingProcessParentFileName matches regex PhpWorker
                   or InitiatingProcessParentFileName in~ (WebServer))
| where ByPhp or ByShellUnderPhp
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Files = dcount(FileName),
            Samples = make_set(FolderPath, 25), Hashes = make_set(SHA256, 25)
            by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by FirstSeen desc
```

## References:

* https://www.php.net/archive/2026.php#2026-10-20-1
* https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
* https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
* https://cert.europa.eu/publications/security-advisories/2026-018/
* https://github.com/Neo23x0/process-watcher/blob/main/emerging-threats/php-rce-october-26/README.md
* https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-22-to-24-initial-attempts.md
