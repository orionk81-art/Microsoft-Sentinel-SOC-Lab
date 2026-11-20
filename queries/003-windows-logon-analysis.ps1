
# Lab 4 - Windows Authentication Analysis
# Event ID: 4624 (Successful Logon)
# Data Source: Local Windows Security Event Log
# Purpose: Analyze logon types over the last 7 days

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
    StartTime = (Get-Date).AddDays(-7)
} -MaxEvents 500 -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Host "No matching events found."
    return
}

$results = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }

    [PSCustomObject]@{
        LogonType = $data['LogonType']
    }
}

$results |
    Group-Object LogonType |
    Sort-Object Count -Descending |
    Select-Object Name, Count |
    Format-Table -AutoSize
