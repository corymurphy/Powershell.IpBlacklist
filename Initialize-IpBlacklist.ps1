[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

$type = @"

using System;
using System.Text;
using System.Runtime.InteropServices;

namespace PowershellIpBlackList
{
    public static class Utils
    {
        const int MAX_PATH = 255;

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern int GetShortPathName(
            [MarshalAs(UnmanagedType.LPTStr)]
            string path,
            [MarshalAs(UnmanagedType.LPTStr)]
            StringBuilder shortPath,
            int shortPathLength
            );

        public static string GetShortPath(string path) {
            var shortPath = new StringBuilder(MAX_PATH);
            GetShortPathName(path, shortPath, MAX_PATH);
            return shortPath.ToString();
        }
    }
}
"@

Add-Type -TypeDefinition $type

$name = 'Powershell.IpBlacklist';

$programFilesShortName = [PowershellIpBlackList.Utils]::GetShortPath($env:ProgramFiles);

$installPath = New-Item -Path ($programFilesShortName) -Name $name -ItemType Directory -Force -ErrorAction SilentlyContinue;

$scriptPath = [System.IO.Path]::Combine($installPath.FullName, 'Invoke-IpBlacklistJobCached.ps1');

Invoke-WebRequest -Uri:'https://raw.githubusercontent.com/corymurphy/Powershell.IpBlacklist/master/Invoke-IpBlacklistJobCached.ps1' -OutFile:$scriptPath

$working = [System.IO.Path]::Combine($programFilesShortName, $name);

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $scriptPath -WorkingDirectory $working;

$triggerDefault = New-ScheduledTaskTrigger -AtStartup ;

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

Register-ScheduledTask -User 'SYSTEM' -Trigger:$triggerDefault -Action:$action -Settings:$settings -TaskName 'Powershell.IpBlacklist' -Force;

$task = Get-ScheduledTask 'Powershell.IpBlacklist';

$trigger = $task.Triggers | Select-Object -First 1;

$trigger.Repetition.Interval = 'PT1H';

Set-ScheduledTask -InputObject $task | Out-Null;
