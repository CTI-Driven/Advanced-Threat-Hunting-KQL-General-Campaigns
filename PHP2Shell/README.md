# PHP2Shell: CVE-2026-109618 and CVE-2026-109619 Post-Exploitation Hunting on PHP Web Servers

## Summary

The advanced hunting queries below are designed to detect expected post-exploitation behavior on PHP web servers, following the disclosure of two critical PHP core vulnerabilities reported as CVE-2026-109618 and CVE-2026-109619 and nicknamed "PHP2Shell". The PHP security team rated both CVSS v4.0 9.2 and scheduled fixes for 21 October 2026 at 14:00 UTC.


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
// Any device flagged internet-facing at any point in the timeframe is included.
// "contains" is used so packages such as libapache2-mod-php8.x match. Review the matched software list.
// The CVE column will be empty until CVE-2026-109618 and CVE-2026-109619 exist in Defender vulnerability data.
let timeframe = 7d;
DeviceTvmSoftwareInventory
| where SoftwareName contains "php"
| join kind=inner (
    DeviceInfo
    | extend EventTime = coalesce(column_ifexists("Timestamp", datetime(null)),column_ifexists("TimeGenerated", datetime(null)))
    | where EventTime >= ago(timeframe)
    | where IsInternetFacing
    | summarize arg_max(Timestamp, IsInternetFacing, PublicIP) by DeviceId
) on DeviceId
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilities
    | where CveId in ("CVE-2026-109618", "CVE-2026-109619")
    | summarize ImpactedCves = make_set(CveId) by DeviceId
) on DeviceId
| distinct DeviceName, IsInternetFacing, OSPlatform, PublicIP, SoftwareName, SoftwareVersion, tostring(ImpactedCves)
| order by DeviceName asc
```

### PHP Worker Spawning Shells, Interpreters, Download Tools and Recon Commands (KQL)

```kusto
let timeframe = 7d;
let ScopeToPhpHosts = true;
let PhpHostsIsInternetFacing =
    DeviceTvmSoftwareInventory
    | where SoftwareName contains "php"
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
| extend EventTime = coalesce(column_ifexists("Timestamp", datetime(null)),column_ifexists("TimeGenerated", datetime(null)))
| where EventTime >= ago(timeframe)
| where not(ScopeToPhpHosts) or DeviceId in (PhpHostsIsInternetFacing)
| extend ParentIsPhp = InitiatingProcessFileName matches regex PhpWorker
                    or InitiatingProcessFileName in~ (WebServer)
| extend GrandParentIsPhp = InitiatingProcessParentFileName matches regex PhpWorker
                         or InitiatingProcessParentFileName in~ (WebServer)
| extend ParentIsShell = InitiatingProcessFileName matches regex ShellRx
| where ParentIsPhp or (GrandParentIsPhp and ParentIsShell)
| extend Category = case(
    FileName matches regex ShellRx, "Shell",
    FileName matches regex @"(?i)^(python[\d.]*|perl[\d.]*)(\.exe)?$", "Interpreter",
    FileName matches regex @"(?i)^(curl|wget|nc(\..+)?|certutil)(\.exe)?$", "Download or network tool",
    FileName matches regex @"(?i)^(whoami|id|uname|ipconfig)(\.exe)?$", "Recon command",
    "")
| where isnotempty(Category)
| project Timestamp, DeviceName, DeviceId, Category, AccountName,
          InitiatingProcessParentFileName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Reverse Shell Patterns Under PHP (KQL)

```kusto
let timeframe = 7d;
let PhpHostsIsInternetFacing =
    DeviceTvmSoftwareInventory
    | where SoftwareName contains "php"
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
| extend EventTime = coalesce(column_ifexists("Timestamp", datetime(null)),column_ifexists("TimeGenerated", datetime(null)))
| where EventTime >= ago(timeframe)
| where DeviceId has_any (PhpHostsIsInternetFacing)
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
// Set WebRoots to your real document roots. Expect noise from CMS updates, plugin installs and deployments.
// The .sh, .py and .pl extensions are noisy in web roots that hold ordinary scripts.
let timeframe = 7d;
let PhpHostsIsInternetFacing =
    DeviceTvmSoftwareInventory
    | where SoftwareName contains "php"
    | distinct DeviceId
    | join kind=inner (
        DeviceInfo
        | where Timestamp >= ago(7d)
        | where IsInternetFacing
        | distinct DeviceId
    ) on DeviceId
    | project DeviceId;
let WebRoots = dynamic(["/var/www/", "\\inetpub\\wwwroot\\"]);
let PhpWorker = @"(?i)^(php-fpm[\d.]*|php-cgi[\d.]*)(\.exe)?$";
let WebServer = dynamic(["httpd","apache2"]);
let Shells = dynamic(["sh","dash","bash","cmd.exe","powershell.exe"]);
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
