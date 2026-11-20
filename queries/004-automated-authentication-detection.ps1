
# Lab 6 - Automated Windows Authentication Detection
# Microsoft Sentinel SOC Lab
# Read-only local security monitoring

$StartTime = (Get-Date).AddDays(-7)
$FailureThreshold = 5

Write-Host "`n=== SOC Authentication Detection ===" -ForegroundColor Cyan

$Events = @(
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4624,4625
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue
)

$Results = foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = $Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventID = $Event.Id
        Account = $Data['TargetUserName']
        LogonType = $Data['LogonType']
        SourceIP = $Data['IpAddress']
    }
}

Write-Host "`n[1] Authentication Summary"

$Results |
    Group-Object EventID |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host "`n[2] Repeated Failed Logons"

$Failures = @($Results | Where-Object {
    $_.EventID -eq 4625
})

$Failures |
    Group-Object Account |
    Where-Object { $_.Count -ge $FailureThreshold } |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host "`n[3] Remote Desktop Logons"

$Results |
    Where-Object {
        $_.EventID -eq 4624 -and
        $_.LogonType -eq '10'
    } |
    Select-Object TimeCreated, Account, SourceIP |
    Format-Table -AutoSize

Write-Host "`n=== Detection Complete ===" -ForegroundColor Green
