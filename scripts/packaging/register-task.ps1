# Register a Scheduled Task that runs `rusty-imap-mcp daemon` at user logon.
param(
    [string] $BinaryPath = "$env:LOCALAPPDATA\Programs\rusty-imap-mcp\rusty-imap-mcp.exe",
    [string] $TaskName = "rusty-imap-mcp"
)

$action  = New-ScheduledTaskAction -Execute $BinaryPath -Argument "daemon"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User $env:USERNAME
Write-Host "Registered task '$TaskName'. It will start at next logon, or run 'Start-ScheduledTask -TaskName $TaskName' now."
