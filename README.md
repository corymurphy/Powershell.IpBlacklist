# Powershell.IpBlocklist

This will Blocklist any ip using the windows firewall that has failed authentication for x times over y time period.

## How to install
Run the following in an elevated powershell session. This will setup the script and create a scheduled task.
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;$out=[System.IO.Path]::Combine($env:TEMP,'Initialize-IpBlocklist.ps1');Invoke-WebRequest -Uri:'https://raw.githubusercontent.com/corymurphy/Powershell.IpBlocklist/master/Initialize-IpBlocklist.ps1' -OutFile:$out;. $out;
```
