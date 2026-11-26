param([Parameter(Mandatory)][string]$Dll)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$started = [DateTimeOffset]::UtcNow
$case = Join-Path $env:RUNNER_TEMP ('hexsuture-amsi-' + [Guid]::NewGuid().ToString('N') + '.db')
$defender = Get-MpComputerStatus
if (!$defender.AntivirusEnabled -or !$defender.RealTimeProtectionEnabled -or !$defender.BehaviorMonitorEnabled) {
    throw 'The AMSI demonstration requires active Defender, real-time protection and behavior monitoring.'
}

try {
    # Microsoft's fixed, harmless test marker submitted to Windows PowerShell's AMSI integration.
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $testOutput = & $powershell -NoProfile -NonInteractive -Command {
        $ErrorActionPreference = 'Stop'
        $marker = 'AMSI Test Sample: ' + '7e72c3ce-861b-4339-8740-0ac1484c1386'
        Invoke-Expression $marker
    } 2>&1
    $testExit = $LASTEXITCODE
    $blocked = (($testOutput -join ' ') -match 'ScriptContainedMaliciousContent')
    Write-Host "AMSI test process exit=$testExit, reported block=$blocked."

    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $null = & dotnet $Dll fileless collect $case --minutes 10
        if ($LASTEXITCODE -ne 0) { throw 'The Defender event collection reported a gap.' }
        $report = & dotnet $Dll show $case | ConvertFrom-Json
        $finding = $report.fileless | Where-Object {
            $_.mode -eq 'live' -and $_.kind -eq 'amsi' -and
            $_.threatName -eq 'Virus:Win32/MpTest!amsi' -and [DateTimeOffset]$_.detectedUtc -ge $started
        } | Select-Object -First 1
        if ($finding) {
            if ($finding.source -eq 'unknown') { throw 'Defender did not supply an identifiable source.' }
            Write-Host "AMSI demonstration: source=$($finding.source), process=$($finding.processName), remediation=$($finding.remediation)."
            return
        }
        Start-Sleep -Seconds 4
    }
    throw 'No live event for the Microsoft AMSI test marker was collected.'
}
finally {
    if (Test-Path -LiteralPath $case) { Remove-Item -LiteralPath $case }
}
