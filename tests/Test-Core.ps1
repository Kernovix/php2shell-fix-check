# Native assertions; no Pester or network needed. Author: Kernovix.
param([string]$ScriptPath=(Join-Path $PSScriptRoot '../PHP-Audit.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $ScriptPath),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
foreach($name in @('Expand-Scope','Get-VersionState','Get-Classification','Convert-SafeCell','Convert-CsvSafe')){
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if(-not $definition){throw "Missing function: $name"}
    . ([scriptblock]::Create($definition.Extent.Text))
}
$count=0
function Check([bool]$Condition,[string]$Name){if(-not $Condition){throw "Assertion failed: $Name"};$script:count++}
Check (@(Expand-Scope @('192.0.2.0/24') 4096).Count -eq 254) 'CIDR /24'
Check (@(Expand-Scope @('192.0.2.0/31') 2).Count -eq 2) 'CIDR /31'
Check (@(Expand-Scope @('192.0.2.1/32') 1).Count -eq 1) 'CIDR /32'
Check (@(Expand-Scope @('192.0.2.10-12,192.0.2.11') 4).Count -eq 3) 'range deduplication'
Check ((@(Expand-Scope @('web-app.example,WEB-APP.example') 2) -join ',') -ceq 'web-app.example') 'DNS names with hyphens'
Check ((@(Expand-Scope @('app.example=192.0.2.1') 2) -join ',') -ceq 'app.example=192.0.2.1') 'SNI pin'
foreach($bad in @('https://example.com/','999.1.1.1','-bad.example','192.0.2.2-1','192.0.2.0/8','name=999.1.1.1','name=1.2.3.4=5.6.7.8','name=010.0.0.1')){
    $rejected=$false;try{$null=Expand-Scope @($bad) 4096}catch{$rejected=$true};Check $rejected "reject $bad"
}
Check ((Convert-CsvSafe '-') -ceq '') 'unknown sentinel becomes blank'
Check ((Convert-CsvSafe '=1+1') -ceq "'=1+1") 'spreadsheet formula protected'
foreach($svc in @('CLI','PHP-BINARY','PACKAGE','Docker')){Check ((Get-Classification 8.3.1 $svc $false UNKNOWN UNKNOWN) -eq 'INCONCLUSIVO') "no runtime inference from $svc"}
# Exercise the actual worker's Invoke-Command splat, with no remoting/network.
$assignment=$ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$worker'},$true)
$worker=$assignment.Right.Expression.ScriptBlock.GetScriptBlock()
function New-PSSessionOption {param($OpenTimeout,$OperationTimeout) @{} }
function Invoke-Command {
    [CmdletBinding()]param($ComputerName,[switch]$UseSSL,[switch]$AsJob,$SessionOption,$ScriptBlock,$Credential,[int]$Port)
    $script:remoteBound=@{};foreach($key in $PSBoundParameters.Keys){$script:remoteBound[$key]=$PSBoundParameters[$key]}
    throw 'Expected test interception before WinRM connects'
}
foreach($ssl in @($false,$true)){
    $null=& $worker localhost @() @() 1 5 $null $true $ssl 0 $false '{}'
    Check (-not $script:remoteBound.ContainsKey('Port')) "unspecified WinRM Port omitted, SSL=$ssl"
}
$null=& $worker localhost @() @() 1 5 $null $true $true 5999 $false '{}'
Check ($script:remoteBound.Port -eq 5999) 'custom WinRM Port passed'
Write-Output "CORE PASS: $count assertions; PowerShell $($PSVersionTable.PSVersion)"
