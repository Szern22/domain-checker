# Registers a Windows scheduled task that runs the domain check every morning.
# Run once:  powershell -ExecutionPolicy Bypass -File setup_schedule.ps1
# Remove:    Unregister-ScheduledTask -TaskName DomainCheck -Confirm:$false
param([string]$Time = "08:00")

$bat = Join-Path $PSScriptRoot "run_daily.bat"
$action   = New-ScheduledTaskAction -Execute $bat -WorkingDirectory $PSScriptRoot
$trigger  = New-ScheduledTaskTrigger -Daily -At $Time
# StartWhenAvailable: if the laptop was off at 08:00, run as soon as it is back on.
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "DomainCheck" -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Write-Host "Scheduled task 'DomainCheck' runs daily at $Time. Test it now with:  Start-ScheduledTask -TaskName DomainCheck"
