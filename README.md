# Powershell.IpBlacklist


## How to install
Run the following in an elevated powershell session.
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;$out=[System.IO.Path]::Combine($env:TEMP,'Initialize-IpBlacklist.ps1');Invoke-WebRequest -Uri:'https://raw.githubusercontent.com/corymurphy/Powershell.IpBlacklist/master/Initialize-IpBlacklist.ps1' -OutFile:$out;. $out;
```
