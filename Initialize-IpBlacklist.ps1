[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

$installPath = New-Item -Path ($env:ProgramFiles) -Name 'Powershell.IpBlacklist' -ItemType Directory -Force -ErrorAction SilentlyContinue;

$scriptPath = [System.IO.Path]::Combine($installPath.FullName, 'Invoke-IpBlacklistJobCached.ps1');

Invoke-WebRequest -Uri:'https://raw.githubusercontent.com/corymurphy/Powershell.IpBlacklist/master/Invoke-IpBlacklistJobCached.ps1' -OutFile:$scriptPath

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $scriptPath -WorkingDirectory 'C:\Program Files\Powershell.IpBlacklist';

$triggerDefault = New-ScheduledTaskTrigger -AtStartup ;

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

Register-ScheduledTask -User 'SYSTEM' -Trigger:$triggerDefault -Action:$action -Settings:$settings -TaskName 'Powershell.IpBlacklist' -Force;

$task = Get-ScheduledTask 'Powershell.IpBlacklist';

$trigger = $task.Triggers | Select-Object -First 1;

$trigger.Repetition.Interval = 'PT1H';

Set-ScheduledTask -InputObject $task;
