param([Parameter(Mandatory)][string]$Dll)

$ErrorActionPreference = 'Stop'
$dllPath = (Resolve-Path -LiteralPath $Dll).Path
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
$name = 'HexSuture-Test-' + [Guid]::NewGuid().ToString('N')
$case = Join-Path $env:RUNNER_TEMP ($name + '.db')
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$permissions = 'O:{0}G:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{0})' -f $sid

function Invoke-HexSuture {
    param([bool]$Success, [string[]]$Arguments)
    $output = & dotnet $dllPath @Arguments 2>&1
    $message = $output -join [Environment]::NewLine
    if (($LASTEXITCODE -eq 0) -ne $Success) { throw $message }
    return $message
}

$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = 'Harmless test task without triggers.'
$definition.Principal.UserId = $sid
$definition.Principal.LogonType = 3
$definition.Principal.RunLevel = 0
$definition.Settings.Enabled = $true
$action = $definition.Actions.Create(0)
$action.Path = Join-Path $env:SystemRoot 'System32\cmd.exe'
$action.Arguments = '/c exit 0'

$created = $false
try {
    $null = $folder.RegisterTaskDefinition($name, $definition, 2, $sid, $null, 3, $permissions)
    $created = $true
    $review = Invoke-HexSuture $true @('task','review',$case,("\$name"),'--reason','Test task') | ConvertFrom-Json
    $null = Invoke-HexSuture $false @('task','disable',$case,$review.id)
    if (!$folder.GetTask($name).Enabled) { throw 'A task was disabled without approval.' }

    $definition.RegistrationInfo.Description = 'Updated harmless fixture description.'
    $null = $folder.RegisterTaskDefinition($name, $definition, 4, $sid, $null, 3, $permissions)
    $errorText = Invoke-HexSuture $false @('task','disable',$case,$review.id,'--approve')
    if ($errorText -notmatch 'identity changed' -or !$folder.GetTask($name).Enabled) {
        throw 'The changed task was not safely rejected.'
    }

    $review = Invoke-HexSuture $true @('task','review',$case,("\$name"),'--reason','Updated test task') | ConvertFrom-Json
    $disabled = Invoke-HexSuture $true @('task','disable',$case,$review.id,'--approve') | ConvertFrom-Json
    $retried = Invoke-HexSuture $true @('task','disable',$case,$review.id,'--approve') | ConvertFrom-Json
    if ($folder.GetTask($name).Enabled -or $disabled.state -ne 'disabled' -or $disabled.history.Count -ne $retried.history.Count) {
        throw 'The task was not disabled once.'
    }
    $null = Invoke-HexSuture $false @('task','verify',$case,$review.id)
    $null = Invoke-HexSuture $false @('task','remove',$case,$review.id,'--approve')

    $rollback = Invoke-HexSuture $true @('task','rollback',$case,$review.id,'--approve') | ConvertFrom-Json
    if (!$folder.GetTask($name).Enabled -or $rollback.state -ne 'rolled-back') {
        throw 'Rollback did not restore the enabled state.'
    }
    Write-Host 'Live Task Scheduler checks passed for approval, changed definitions, disable, retry, reboot gate and rollback.'
}
finally {
    if ($created) { $folder.DeleteTask($name, 0) }
    if (Test-Path -LiteralPath $case) { Remove-Item -LiteralPath $case }
}
