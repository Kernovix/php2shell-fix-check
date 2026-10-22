#requires -Version 5.1
<#
.SYNOPSIS
PHP2Shell Fix Check. Read-only audit / Auditoria de leitura. Targets + language (pt/en).
.NOTES
Author / Autor: Kernovix
.EXAMPLE
.\PHP-Audit.ps1 '192.168.1.0/24' pt
.EXAMPLE
.\PHP-Audit.ps1 '192.168.1.10-30' en
.EXAMPLE
.\PHP-Audit.ps1 -SelfTest -Language en
#>
[CmdletBinding()]
param(
    [Parameter(Position=0)][string[]]$Targets = @(),
    [Parameter(Position=1)][ValidateSet('pt','en','')][string]$Language = '',
    [string]$TargetsFile,
    [ValidateRange(1,65535)][int[]]$Ports = @(80,443,8080,8443),
    [ValidateRange(1,65535)][int[]]$TlsPorts = @(443,8443),
    [ValidateRange(1,64)][int]$Concurrency = 8,
    [ValidateRange(1,60)][int]$TimeoutSeconds = 3,
    [ValidateRange(5,600)][int]$RemoteTimeoutSeconds = 45,
    [ValidateRange(1,65536)][int]$MaxHosts = 4096,
    [string[]]$PublicTargets = @(),
    [PSCredential]$Credential,
    [switch]$RemoteCurrentUser,
    [switch]$UseSSL,
    [ValidateRange(0,65535)][int]$WinRMPort = 0,
    [switch]$InsecureTls,
    [switch]$LocalInventory,
    [string]$EvidenceFile,
    [string]$Simulate,
    [switch]$SelfTest,
    [string]$OutDir = ''
)
$ErrorActionPreference = 'Stop'
$Cves = 'CVE-2026-109618; CVE-2026-109619'
$Today = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
if (-not $OutDir) { $OutDir=Join-Path $PSScriptRoot 'reports' }
$isIseHost = $null -ne (Get-Variable -Name psISE -ValueOnly -ErrorAction SilentlyContinue)
if (-not $Targets.Count -and -not $TargetsFile -and -not $Simulate -and -not $SelfTest -and -not $LocalInventory -and
    ($isIseHost -or ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected))) {
    $Targets = @((Read-Host 'IPs / DNS / Rede / Network (ex.: 192.168.1.0/24 ou/or app.example.com)'))
}
if (-not $Language -and -not $SelfTest -and -not $Simulate -and
    ($isIseHost -or ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected))) {
    $Language=(Read-Host 'Idioma do relatorio / Report language [pt/en] (pt)').Trim().ToLowerInvariant()
}
if (-not $Language) { $Language='pt' }
if ($Language -notin @('pt','en')) { throw 'Idioma / Language: pt ou/or en' }
$Text = @{
 'title' = @('PHP2Shell Fix Check — Auditoria PHP','PHP2Shell Fix Check — PHP Audit')
 'date' = @('Data UTC','UTC date')
 'scope' = @('Alvos','Targets')
 'hosts' = @('IPs analisados','IPs checked')
 'results' = @('Resultados','Results')
 'attention' = @('Precisam de atenção','Need attention')
 'unknown' = @('Inconclusivos','Inconclusive')
 'host' = @('IP / Nome','IP / Hostname')
 'service' = @('Serviço','Service')
 'app' = @('Aplicação','Application')
 'php' = @('PHP','PHP')
 'status' = @('Estado','Status')
 'action' = @('O que fazer','What to do')
 'details' = @('Ver detalhes','View details')
 'os' = @('Sistema operativo','Operating system')
 'runtime' = @('Runtime','Runtime')
 'package' = @('Pacote','Package')
 'cves' = @('CVEs','CVEs')
 'risk' = @('Risco','Risk')
 'reachable' = @('Acessível pela rede','Network reachable')
 'public' = @('Exposição pública','Public exposure')
 'evidence' = @('Evidências','Evidence')
 'recommendation' = @('Recomendação','Recommendation')
 'vulnerable' = @('VULNERÁVEL CONFIRMADO','VULNERABLE (CONFIRMED)')
 'fixed' = @('CORRIGIDO','FIXED')
 'potential' = @('POTENCIALMENTE VULNERÁVEL','POTENTIALLY VULNERABLE')
 'inconclusive' = @('INCONCLUSIVO','INCONCLUSIVE')
 'high' = @('ALTO','HIGH')
 'critical' = @('CRÍTICO','CRITICAL')
 'low' = @('BAIXO (estas CVEs)','LOW (these CVEs)')
 'undetermined' = @('POR DETERMINAR','UNDETERMINED')
 'yes' = @('SIM','YES')
 'na' = @('Não associado a uma porta web','Not linked to a web port')
 'unknownValue' = @('Desconhecido','Unknown')
 'declared' = @('SIM (informado pelo técnico)','YES (reported by technician)')
 'hint' = @('indício','hint')
 'simulated' = @('SIMULAÇÃO — dados fictícios, sem auditoria de uma rede real.','SIMULATION — fictional data, no real network audit.')
 'explain' = @('Uma versão antiga pode ter correções do fornecedor. Sem prova suficiente, o resultado é INCONCLUSIVO. Uma linha corrigida não certifica todo o servidor.','An older version may contain vendor fixes. Without sufficient evidence, the result is INCONCLUSIVE. A fixed row does not certify the entire server.')
 'next' = @('Priorize os resultados que precisam de atenção. Confirme o runtime web e as correções do fornecedor antes de atualizar.','Prioritize results that need attention. Confirm the web runtime and vendor fixes before updating.')
 'fixAction' = @('Guardar a confirmação e verificar os restantes sites e runtimes.','Keep the confirmation and check other sites and runtimes.')
 'unknownAction' = @('Confirmar o PHP usado pelo site e verificar as duas CVEs com o fornecedor.','Confirm the PHP runtime used by the site and check both CVEs with the vendor.')
 'oldAction' = @('Verificar possíveis backports e atualizar o runtime web se necessário.','Check for vendor backports and update the web runtime if needed.')
 'vulnAction' = @('Atualizar o runtime afetado e acordar restrição temporária de acesso.','Update the affected runtime and agree on temporary access restrictions.')
 'limits' = @('Limites','Limitations')
 'limitText' = @('Só os IPs e portas indicados são verificados. Sites por nome/SNI, proxies e instalações ocultas podem não ser identificados. Exposição pública é informada pelo técnico, não testada da Internet. Não há exploits nem alterações nos servidores.','Only the specified IPs and ports are checked. Name-based/SNI sites, proxies and hidden installations may be missed. Public exposure is technician-reported, not tested from the Internet. No exploits or server changes are performed.')
 'versions' = @('Referência: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. PHP ≤8.1: confirmar suporte e backports. CLI e banners não provam que o site está corrigido.','Reference: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. PHP ≤8.1: check support and backports. CLI versions and banners do not prove a website is fixed.')
 'source' = @('Aviso oficial do PHP','Official PHP advisory')
 'done' = @('Relatórios guardados em','Reports saved to')
 'scanning' = @('A verificar','Checking')
 'tests' = @('Testes internos aprovados','Internal tests passed')
}
function T([string]$Key) { if ($Language -eq 'en') { return $Text[$Key][1] }; return $Text[$Key][0] }
function Translate-Detail([string]$Value) {
 if ($Language -ne 'en') { return $Value }
 $Value=$Value.Replace('TCP aberto','TCP open')
 $Value=$Value.Replace('sem banner PHP','no PHP banner')
 $Value=$Value.Replace('limitado a','limited to')
 $Value=$Value.Replace('sem redirects','no redirects')
 $Value=$Value.Replace('certificado TLS nao validado','TLS certificate not validated')
 $Value=$Value.Replace('Processo ativo','Running process')
 $Value=$Value.Replace('executavel=','executable=')
 $Value=$Value.Replace('versao via procfs quando permitida','version via procfs where permitted')
 $Value=$Value.Replace('pacote em disco nao comprova workers atualizados','on-disk package does not prove workers are updated')
 $Value=$Value.Replace('Sem resposta nas portas testadas; host desligado/filtrado ou servicos noutras portas; PHP nao excluido','No response on tested ports; host offline/filtered or services on other ports; PHP is not ruled out')
 $Value=$Value.Replace('Inventario limitado aos privilegios da conta; processos/pacotes/conteineres podem estar ocultos','Inventory limited by account permissions; processes/packages/containers may be hidden')
 $Value=$Value.Replace('dpkg instalado; backport e runtime carregado por confirmar','Installed dpkg package; backport and loaded runtime unconfirmed')
 $Value=$Value.Replace('RPM instalado; fornecedor/stream e runtime carregado por confirmar','Installed RPM package; vendor/stream and loaded runtime unconfirmed')
 $Value=$Value.Replace('PHP_VERSION via -n; sem ligacao ao servico web','PHP_VERSION via -n; not linked to a web service')
 $Value=$Value.Replace('PHP_VERSION via -n; CLI nao comprova runtime web','PHP_VERSION via -n; CLI does not prove the web runtime')
 $Value=$Value.Replace('Modulo PHP mapeado; disco/pacote nao comprova workers atualizados','Mapped PHP module; disk/package does not prove workers are updated')
 $Value=$Value.Replace('Imagem=','Image=')
 $Value=$Value.Replace('portas=','ports=')
 $Value=$Value.Replace('PHP interno e digest carregado por confirmar','Container PHP and loaded digest unconfirmed')
 $Value=$Value.Replace('versao PHP/digest carregado por confirmar','PHP version/loaded digest unconfirmed')
 $Value=$Value.Replace('conclusao=','completion=')
 $Value=$Value.Replace('recebido','received')
 $Value=$Value.Replace('parcial-ou-indisponivel','partial-or-unavailable')
 $Value=$Value.Replace('permissoes limitam cobertura','permissions limit coverage')
 $Value=$Value.Replace('Falha interna do worker; recolha incompleta','Worker failure; incomplete collection')
 $Value=$Value.Replace('Worker falhou ou excedeu tempo; recolha incompleta','Worker failed or timed out; incomplete collection')
 $Value=$Value.Replace('TCP aberto; HTTP/TLS com erro, timeout ou corpo incompleto; sem versao fiavel','TCP open; HTTP/TLS failed, timed out or body incomplete; no reliable version')
 $Value=$Value.Replace('HTTP/TLS com erro, timeout ou corpo incompleto; sem versao fiavel','HTTP/TLS failed, timed out or body incomplete; no reliable version')
 $Value=$Value.Replace('Processo ativo; executavel=','Running process; executable=')
 $Value=$Value.Replace('versao carregada por confirmar','loaded version unconfirmed')
 $Value=$Value.Replace('Sem acesso ao inventario de processos; cobertura parcial','Process inventory unavailable; partial coverage')
 $Value=$Value.Replace('conforme nome do servico','according to service name')
 $Value=$Value.Replace('Handler FastCGI configurado; pools, workers e sites por validar','FastCGI handler configured; pools, workers and sites unconfirmed')
 $Value=$Value.Replace('IIS detetado; configuracao sem acesso ou nao interpretavel','IIS detected; configuration unavailable or unreadable')
 $Value=$Value.Replace('Versao do ficheiro em disco; nao comprova versao dos workers em memoria','On-disk file version; does not prove in-memory worker versions')
 $Value=$Value.Replace('Versao PHP indisponivel ou sem permissao','PHP version unavailable or access denied')
 $Value=$Value.Replace('Docker sem acesso; conteineres por confirmar','Docker unavailable; containers unconfirmed')
 $Value=$Value.Replace('Inventario limitado aos privilegios da conta; nao implica cobertura de todas as instalacoes','Inventory limited by account permissions; does not imply all installations were covered')
 $Value=$Value.Replace('Recolha concluida=','Collection complete=')
 $Value=$Value.Replace('falha ou permissoes insuficientes implicam cobertura parcial','failure or insufficient permissions mean partial coverage')
 $Value=$Value.Replace('Confirmacao revista:','Reviewed confirmation:')
 $Value=$Value.Replace('Confirmacao rejeitada: backport exige pacote/build exato','Confirmation rejected: backport requires exact package/build')
 $Value=$Value.Replace('Confirmacao ignorada: desatualizada, divergente ou incompleta','Confirmation ignored: stale, mismatched or incomplete')
 $Value=$Value.Replace('estados CVE individuais:','individual CVE states:')
 $Value=$Value.Replace('versao CLI/banner/pacote nao comprova runtime web corrigido','CLI/banner/package version does not prove the web runtime is fixed')
 $Value=$Value.Replace('SIMULADO:','SIMULATED:')
 $Value=$Value.Replace('banner antigo','old banner')
 $Value=$Value.Replace('runtime validado pelo tecnico','runtime verified by technician')
 $Value=$Value.Replace('apenas CLI','CLI only')
 $Value=$Value.Replace('sem backport; runtime confirmado','no backport; runtime confirmed')
 $Value=$Value.Replace('runtime sem backport','runtime without backport')
 $Value=$Value.Replace('sem versao','no version')
 $Value=$Value.Replace('portas filtradas','filtered ports')
 $Value=$Value.Replace('banner corrigido nao comprova runtime','fixed banner does not prove the runtime')
 return $Value
}
$ObservationFields = @('IP','Hostname','OS','Service','Runtime','Application','PHPVersion','Package','Reachable','Evidence')
$EvidenceFields = @('IP','Service','Runtime','PHPVersion','Package','CVE109618','CVE109619','RuntimeVerified','ReviewedAt','ReviewedBy','Advisory')
if ($Ports.Count -eq 0 -or $Ports.Count -gt 64) { throw 'Indique entre 1 e 64 portas.' }


function Expand-Scope([string[]]$Scope,[int]$Limit){
    function IpNumber([string]$Address){
        if($Address -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'){throw "Invalid IPv4: $Address"}
        [long]$v=0;for($j=1;$j -le 4;$j++){$o=[int]$Matches[$j];if($o -gt 255 -or ($Matches[$j].Length -gt 1 -and $Matches[$j].StartsWith('0'))){throw "Invalid or ambiguous IPv4: $Address"};$v=$v*256+$o};$v
    }
    function DnsName([string]$Name){
        if($Name.Length -gt 253 -or $Name -match '^[\d.]+$'){return $false}
        foreach($part in $Name.Split('.')){if($part -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'){return $false}};$true
    }
    $seen=@{}
    foreach($line in $Scope){foreach($token in (($line -replace '#.*$','') -split '[,\s]+'|Where-Object {$_})){
        $dns=$false
        if($token.Contains('=')){
            $pair=$token.Split('=');if($pair.Count -ne 2 -or -not (DnsName $pair[0])){throw "Invalid DNS=IPv4 target: $token"};$null=IpNumber $pair[1];$target=$token.ToLowerInvariant();$dns=$true
        }elseif($token -match '^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){0,3}\d{1,3}$'){
            $range=$token.Split('-');[long]$lo=IpNumber $range[0]
            if($range[1] -match '^\d{1,3}$'){if([int]$range[1] -gt 255){throw 'Invalid range'};[long]$hi=[math]::Floor($lo/256)*256+[int]$range[1]}else{[long]$hi=IpNumber $range[1]}
        }elseif($token.Contains('/') -or $token -match '^[\d.]+$'){
            $parts=$token.Split('/');if($parts.Count -gt 2){throw 'Invalid CIDR'};[long]$v=IpNumber $parts[0];$prefix=32
            if($parts.Count -eq 2){if($parts[1] -notmatch '^\d{1,2}$' -or [int]$parts[1] -gt 32){throw 'Invalid CIDR'};$prefix=[int]$parts[1]}
            [long]$size=[math]::Pow(2,32-$prefix);if($size -gt $Limit){throw 'CIDR exceeds MaxHosts'}
            [long]$lo=[math]::Floor($v/$size)*$size;[long]$hi=$lo+$size-1;if($prefix -lt 31){$lo++;$hi--}
        }else{if(-not (DnsName $token)){throw "Invalid DNS target: $token"};$target=$token.ToLowerInvariant();$dns=$true}
        if($dns){if(-not $seen.ContainsKey($target)){$seen[$target]=$true;if($seen.Count -gt $Limit){throw 'Too many targets'};$target};continue}
        if($hi -lt $lo -or $hi-$lo+1 -gt $Limit){throw 'Invalid or excessive range'}
        for([long]$n=$lo;$n -le $hi;$n++){$target='{0}.{1}.{2}.{3}' -f ([math]::Floor($n/16777216)),([math]::Floor($n/65536)%256),([math]::Floor($n/256)%256),($n%256);if(-not $seen.ContainsKey($target)){$seen[$target]=$true;if($seen.Count -gt $Limit){throw 'Too many targets'};$target}}
    }}
}

function Get-VersionState([string]$Version) {
    if ($Version -notmatch '^(\d{1,2})\.(\d{1,2})\.(\d{1,4})$') { return 'UNKNOWN' }
    $major=[int]$Matches[1]; $minor=[int]$Matches[2]; $patch=[int]$Matches[3]
    if ($major -lt 8 -or ($major -eq 8 -and $minor -le 1)) { return 'LEGACY' }
    $floors = @{ '8.2'=35; '8.3'=36; '8.4'=27; '8.5'=12 }
    $branch="$major.$minor"
    if (-not $floors.ContainsKey($branch)) { return 'UNKNOWN' }
    if ($patch -ge $floors[$branch]) { return 'FIXED_VERSION' }
    return 'BELOW'
}
function Get-Classification([string]$Version,[string]$Service,[bool]$Verified,[string]$A,[string]$B) {
    if ($Verified) {
        if ($A -eq 'AFFECTED' -or $B -eq 'AFFECTED') { return 'VULNERAVEL' }
        if ($A -eq 'FIXED' -and $B -eq 'FIXED') { return 'CORRIGIDO' }
    }
    $state=Get-VersionState $Version
    if ($Service -notmatch '^(CLI|PHP-BINARY|PACKAGE|Docker|Podman|SERVICE|COLLECTION|LOCAL|WinRM|SSH|DISCOVERY)$' -and $state -in @('BELOW','LEGACY')) { return 'POTENCIALMENTE VULNERAVEL' }
    return 'INCONCLUSIVO'
}
function New-Observation($IP,$Hostname,$OS,$Service,$Runtime,$Application,$PHPVersion,$Package,$Reachable,$Evidence) {
    [pscustomobject][ordered]@{IP=$IP;Hostname=$Hostname;OS=$OS;Service=$Service;Runtime=$Runtime;Application=$Application;PHPVersion=$PHPVersion;Package=$Package;Reachable=$Reachable;Evidence=$Evidence}
}
function Read-Protocol([string]$Path,[string[]]$Fields) {
    $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8)
    $extended=@($ObservationFields)+@('Address','DiscoveryCode','HTTPStatus','TLSValidation','ErrorCode','ErrorDetail','RedirectTo','Confidence')
    if($Fields.Count -eq 10 -and $lines.Count -gt 0 -and $lines[0] -ceq ($extended -join "`t")){$Fields=$extended}
    if ($lines.Count -lt 1 -or $lines[0] -cne ($Fields -join "`t")) { throw "Cabecalho TSV invalido: $Path" }
    foreach ($line in $lines | Select-Object -Skip 1) {
        $cells=$line.Split([char]9)
        if ($cells.Count -ne $Fields.Count -or @($cells | Where-Object { $_ -eq '' }).Count) { throw "Linha TSV invalida: $Path" }
        $row=[ordered]@{}
        for ($i=0;$i -lt $Fields.Count;$i++) { $row[$Fields[$i]]=$cells[$i] }
        [pscustomobject]$row
    }
}
function Convert-SafeCell($Value) {
    if ([string]$Value -eq '-') { return '' }
    $s=([string]$Value -replace '[\x00-\x1f\x7f]', ' ')
    if ($s.Length -gt 5000) { $s=$s.Substring(0,5000) }
    return $s
}
function Convert-CsvSafe($Value) {
    $s=Convert-SafeCell $Value
    if ($s -match '^\s*[=+@-]') { $s="'$s" }
    return $s
}

$observations=@(); $evidence=@()
if ($SelfTest) {
    $cases=@{
        '8.2.34'='BELOW';'8.2.35'='FIXED_VERSION';'8.2.36'='FIXED_VERSION';
        '8.3.35'='BELOW';'8.3.36'='FIXED_VERSION';'8.4.26'='BELOW';'8.4.27'='FIXED_VERSION';
        '8.5.11'='BELOW';'8.5.12'='FIXED_VERSION';'8.1.34'='LEGACY';'7.4.33'='LEGACY';
        '8.6.0'='UNKNOWN';'8.5.12RC1'='UNKNOWN';'-'='UNKNOWN'
    }
    foreach ($v in $cases.Keys) { if ((Get-VersionState $v) -ne $cases[$v]) { throw "Teste versao: $v" } }
    $checks=@(
        @('8.5.12','CLI',$false,'UNKNOWN','UNKNOWN','INCONCLUSIVO'),
        @('8.5.11','CLI',$false,'UNKNOWN','UNKNOWN','INCONCLUSIVO'),
        @('8.5.12','HTTPS',$false,'UNKNOWN','UNKNOWN','INCONCLUSIVO'),
        @('8.3.6','PHP-FPM',$true,'FIXED','FIXED','CORRIGIDO'),
        @('8.3.6','PHP-FPM',$false,'FIXED','FIXED','POTENCIALMENTE VULNERAVEL'),
        @('8.3.6','PHP-FPM',$true,'AFFECTED','FIXED','VULNERAVEL'),
        @('-','HTTPS',$false,'UNKNOWN','UNKNOWN','INCONCLUSIVO')
    )
    foreach ($c in $checks) { if ((Get-Classification $c[0] $c[1] $c[2] $c[3] $c[4]) -ne $c[5]) { throw 'Teste de classificacao falhou.' } }
    $observations=@(
        (New-Observation '192.0.2.10' 'wp.example' Linux HTTP:80 web:80 WordPress 8.3.35 - SIMULADO 'SIMULADO: banner antigo'),
        (New-Observation '192.0.2.11' 'app.example' Ubuntu HTTPS:443 web:443 Nextcloud 8.3.6 'php8.3-fpm=SIMULADO' SIMULADO 'SIMULADO: runtime validado pelo tecnico'),
        (New-Observation '192.0.2.12' 'cli.example' Windows CLI cli:php - 8.5.12 - SIMULADO 'SIMULADO: apenas CLI'),
        (New-Observation '192.0.2.13' 'old.example' Linux PHP-FPM process:123 - 8.4.26 - SIMULADO 'SIMULADO: runtime sem backport'),
        (New-Observation '192.0.2.14' 'hidden.example' - HTTPS:443 web:443 Joomla - - SIMULADO 'SIMULADO: sem versao'),
        (New-Observation '192.0.2.15' 'offline.example' - DISCOVERY host - - - SIMULADO 'SIMULADO: portas filtradas'),
        (New-Observation '192.0.2.16' 'new.example' Linux HTTPS:443 web:443 - 8.5.12 - SIMULADO 'SIMULADO: banner corrigido nao comprova runtime')
    )
    $evidence=@(
        [pscustomobject]@{IP='192.0.2.11';Service='HTTPS:443';Runtime='web:443';PHPVersion='8.3.6';Package='php8.3-fpm=SIMULADO';CVE109618='FIXED';CVE109619='FIXED';RuntimeVerified='TRUE';ReviewedAt=$Today;ReviewedBy='Tecnico SIMULADO';Advisory='https://example.invalid/advisory-SIMULADO'},
        [pscustomobject]@{IP='192.0.2.13';Service='PHP-FPM';Runtime='process:123';PHPVersion='8.4.26';Package='-';CVE109618='AFFECTED';CVE109619='AFFECTED';RuntimeVerified='TRUE';ReviewedAt=$Today;ReviewedBy='Tecnico SIMULADO';Advisory='https://example.invalid/advisory-SIMULADO'}
    )
    Write-Host 'OK: 14 testes de versao + 7 de classificacao.'
} elseif ($Simulate) {
    $observations=@(Read-Protocol $Simulate $ObservationFields)
    if (-not $observations.Count) { throw 'Observacoes vazias.' }
}
if ($EvidenceFile) { $evidence=@(Read-Protocol $EvidenceFile $EvidenceFields) }
$evidenceMap=@{}
foreach ($e in $evidence) {
    if ($e.CVE109618 -cnotmatch '^(FIXED|AFFECTED|UNKNOWN)$' -or $e.CVE109619 -cnotmatch '^(FIXED|AFFECTED|UNKNOWN)$' -or $e.RuntimeVerified -cnotmatch '^(TRUE|FALSE)$') { throw 'Estado de evidencia invalido.' }
    $key="$($e.IP)|$($e.Service)|$($e.Runtime)"
    if ($evidenceMap.ContainsKey($key)) { throw 'Evidencias duplicadas.' }
    $evidenceMap[$key]=$e
}
$publicMap=@{}
foreach ($ip in @(Expand-Scope $PublicTargets $MaxHosts)) { $publicMap[$ip]=$true }

# Executed only inside the explicitly authenticated WinRM session.
$remoteCollector = {
    $ErrorActionPreference='Stop'
    function Obs($Service,$Runtime,$Version,$Package,$Detail) {
        [pscustomobject]@{Service=$Service;Runtime=$Runtime;PHPVersion=$Version;Package=$Package;Evidence=$Detail}
    }
    function Inventory-Cim($Class) {
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) { Get-CimInstance -ClassName $Class -OperationTimeoutSec 5 -ErrorAction Stop }
        else { Get-WmiObject -Class $Class -ErrorAction Stop }
    }
    $os='Windows';try { $os=(Inventory-Cim Win32_OperatingSystem).Caption } catch {}
    [pscustomobject]@{Service='META';Runtime='OS';PHPVersion='-';Package='-';Evidence=$os}
    [pscustomobject]@{Service='META';Runtime='HOST';PHPVersion='-';Package='-';Evidence=$env:COMPUTERNAME}
    $paths=@{}
    foreach ($cmd in @(Get-Command php.exe -All -ErrorAction SilentlyContinue)) { if ($cmd.Source) { $paths[$cmd.Source]=$true } }
    foreach ($path in @('C:\PHP\php.exe','C:\PHP\php-cgi.exe','C:\Program Files\PHP\php.exe','C:\Program Files (x86)\PHP\php.exe','C:\xampp\php\php.exe','C:\laragon\bin\php\php.exe')) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { $paths[$path]=$true }
    }
    foreach($base in @('C:\wamp64\bin\php','C:\wamp\bin\php','C:\laragon\bin\php')){
        if(Test-Path -LiteralPath $base){foreach($dir in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue|Select-Object -First 32)){foreach($name in @('php.exe','php-cgi.exe')){$candidate=Join-Path $dir.FullName $name;if(Test-Path -LiteralPath $candidate -PathType Leaf){$paths[$candidate]=$true}}}}
    }
    try {
        foreach($svc in @(Inventory-Cim Win32_Service|Where-Object {$_.Name -match 'php|apache|nginx|W3SVC|docker' -or $_.PathName -match 'php[^\\]*\.exe'})){
            $exe='';if($svc.PathName -match '^"([^"\r\n]+\.exe)"'){$exe=$Matches[1]}elseif($svc.PathName -match '^([^"\r\n]+?\.exe)(?:\s|$)'){$exe=$Matches[1]}
            Obs SERVICE "service:$($svc.Name)" '-' '-' "Service=$($svc.Name); state=$($svc.State); executable=$exe"
            if($exe -match 'php[^\\]*\.exe$' -and (Test-Path -LiteralPath $exe -PathType Leaf)){$paths[$exe]=$true}
        }
    }catch{Obs COLLECTION services '-' '-' 'Service inventory unavailable; partial coverage'}
    try {
        foreach ($p in @(Inventory-Cim Win32_Process | Where-Object { $_.Name -match '^(php.*|httpd|nginx|w3wp|frankenphp|lsphp)\.exe$' })) {
            $name=$p.Name; $path=$p.ExecutablePath
            $v='-';if($path -and $name -match '^php'){try{$v=(Get-Item -LiteralPath $path).VersionInfo.ProductVersion;if($v -notmatch '^\d+\.\d+\.\d+[\w.+-]*$'){$v='-'}}catch{}}
            $service=$name;if($name -ieq 'php.exe'){$service='CLI'}
            Obs $service "process:$($p.ProcessId)" $v '-' "Running process; executable=$path; disk file version does not prove loaded worker version"
            if ($path -and $name -match '^php') { $paths[$path]=$true }
        }
    } catch { Obs COLLECTION processes '-' '-' 'Sem acesso ao inventario de processos; cobertura parcial' }
    foreach ($s in @(Get-Service -Name W3SVC,WAS,Apache*,nginx*,*php*fpm*,docker -ErrorAction SilentlyContinue)) {
        Obs SERVICE "service:$($s.Name)" '-' '-' "$($s.Name): $($s.Status); IIS/Apache/Nginx/PHP-FPM/Docker conforme nome do servico"
    }
    # Read executable paths only. Never emit IIS arguments, environment or auth config.
    $iis=Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path -LiteralPath $iis) {
        try {
            [xml]$xml=Get-Content -LiteralPath $iis -Raw
            foreach ($entry in @($xml.configuration.'system.webServer'.fastCgi.application)) {
                if ($entry -and $entry.fullPath -match 'php[^\\]*\.exe$') {
                    $path=[Environment]::ExpandEnvironmentVariables([string]$entry.fullPath)
                    Obs IIS-FastCGI "iis:$path" '-' '-' 'Handler FastCGI configurado; pools, workers e sites por validar'
                    if (Test-Path -LiteralPath $path -PathType Leaf) { $paths[$path]=$true }
                }
            }
        } catch { Obs COLLECTION iis-config '-' '-' 'IIS detetado; configuracao sem acesso ou nao interpretavel' }
    }
    foreach ($path in @($paths.Keys | Sort-Object | Select-Object -First 32)) {
        try {
            if ([IO.Path]::GetFileName($path) -ieq 'php.exe') {
                $query=New-Object Diagnostics.Process
                try{
                    $query.StartInfo.FileName=$path;$query.StartInfo.Arguments='-n -r "echo PHP_VERSION;"';$query.StartInfo.UseShellExecute=$false;$query.StartInfo.CreateNoWindow=$true;$query.StartInfo.RedirectStandardOutput=$true;$query.StartInfo.RedirectStandardError=$true
                    $null=$query.Start();$stdout=$query.StandardOutput.ReadToEndAsync();$stderr=$query.StandardError.ReadToEndAsync()
                    if(-not $query.WaitForExit(5000)){$query.Kill();throw 'PHP query timed out (only the spawned query is terminated)'}
                    $v=$stdout.Result.Trim()
                }finally{$query.Dispose()}
                if ($v -notmatch '^\d+\.\d+\.\d+[\w.+-]*$') { $v='-' }
                Obs CLI "cli:$path" $v '-' 'PHP_VERSION via -n; CLI nao comprova runtime web'
            } else {
                $v=(Get-Item -LiteralPath $path).VersionInfo.ProductVersion
                if ($v -notmatch '^\d+\.\d+\.\d+[\w.+-]*$') { $v='-' }
                Obs PHP-BINARY "binary:$path" $v '-' 'Versao do ficheiro em disco; nao comprova versao dos workers em memoria'
            }
        } catch { Obs COLLECTION "binary:$path" '-' '-' 'Versao PHP indisponivel ou sem permissao' }
    }
    foreach($reg in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')){
        foreach($pkg in @(Get-ItemProperty -Path $reg -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -match '^PHP(?:\s|$)'}|Select-Object -First 32)){
            Obs PACKAGE "package:$($pkg.DisplayName)" '-' "$($pkg.DisplayName)=$($pkg.DisplayVersion)" 'Installed package metadata; web runtime unconfirmed'
        }
    }
    if (Get-Command docker.exe -ErrorAction SilentlyContinue) {
        try {
            $query=New-Object Diagnostics.Process
            try {
                $query.StartInfo.FileName=(Get-Command docker.exe).Source
                $query.StartInfo.Arguments='-H npipe:////./pipe/docker_engine ps --format "{{.ID}}|{{.Image}}|{{.Ports}}"'
                $query.StartInfo.UseShellExecute=$false;$query.StartInfo.CreateNoWindow=$true;$query.StartInfo.RedirectStandardOutput=$true;$query.StartInfo.RedirectStandardError=$true
                $null=$query.Start();$stdout=$query.StandardOutput.ReadToEndAsync();$stderr=$query.StandardError.ReadToEndAsync()
                if(-not $query.WaitForExit(5000)){$query.Kill();throw 'Local Docker metadata query timed out'}
                if($query.ExitCode -ne 0){throw 'Local Docker metadata unavailable'}
                $dockerLines=@($stdout.Result -split '\r?\n'|Where-Object {$_}|Select-Object -First 100)
            } finally {$query.Dispose()}
            foreach ($line in $dockerLines) {
                $parts=$line -split '\|',3
                Obs Docker "docker:$($parts[0])" '-' '-' "Imagem=$($parts[1]); portas=$($parts[2]); versao PHP/digest carregado por confirmar"
            }
        } catch { Obs COLLECTION docker '-' '-' 'Docker sem acesso; conteineres por confirmar' }
    }
    Obs META COMPLETE '-' '-' 'Inventario limitado aos privilegios da conta; nao implica cobertura de todas as instalacoes'
}

# Native per-request transport: works in Windows PowerShell 5.1 and PowerShell 7.
# SslStream supplies SNI and OS certificate validation without global callbacks.
if (-not ('PhpAuditTransportV2' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Collections.Generic;
public class PhpAuditReplyV2 {
    public string Address="", ErrorCode="", ErrorDetail="", Tls="NOT_APPLICABLE", CertificateErrors="";
    public int Status=0;
    public bool TcpOpen=false, BodyTruncated=false;
    public string Body="";
    public Dictionary<string,string> Headers=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
}
public static class PhpAuditTransportV2 {
    static void Await(IAsyncResult task, int milliseconds) {
        using (var handle=task.AsyncWaitHandle) { if(!handle.WaitOne(milliseconds)) throw new TimeoutException("Operation deadline exceeded"); }
    }
    static int ReadByte(Stream s) { int b=s.ReadByte(); if(b<0) throw new IOException("Unexpected end of HTTP response"); return b; }
    static string Line(Stream s, int limit) {
        var b=new MemoryStream();
        for(int i=0;i<limit;i++) { int c=ReadByte(s); if(c==10) return Encoding.ASCII.GetString(b.ToArray()).TrimEnd('\r'); b.WriteByte((byte)c); }
        throw new IOException("HTTP line exceeds limit");
    }
    static void Body(Stream s, PhpAuditReplyV2 r) {
        string length,encoding; long remaining=-1;
        if(r.Status==204 || r.Status==304 || (r.Status>=100 && r.Status<200)) return;
        bool chunked=r.Headers.TryGetValue("Transfer-Encoding",out encoding) && encoding.ToLowerInvariant().Contains("chunked");
        if(r.Headers.TryGetValue("Content-Length",out length) && (!Int64.TryParse(length,out remaining) || remaining<0)) throw new IOException("Invalid Content-Length");
        var output=new MemoryStream(); byte[] buffer=new byte[4096];
        try {
            while(output.Length<65536) {
                if(chunked) {
                    string size=Line(s,1024).Split(';')[0]; long chunk;
                    if(!Int64.TryParse(size,System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out chunk) || chunk<0) throw new IOException("Invalid chunk size");
                    if(chunk==0) return;
                    while(chunk>0 && output.Length<65536) { int n=s.Read(buffer,0,(int)Math.Min(Math.Min(chunk,buffer.Length),65536-output.Length)); if(n==0) throw new IOException("Incomplete chunk"); output.Write(buffer,0,n); chunk-=n; }
                    if(output.Length>=65536) break;
                    if(ReadByte(s)!=13 || ReadByte(s)!=10) throw new IOException("Invalid chunk delimiter");
                } else {
                    if(remaining==0) return;
                    int want=(int)Math.Min(buffer.Length,65536-output.Length); if(remaining>=0) want=(int)Math.Min(want,remaining);
                    int n=s.Read(buffer,0,want); if(n==0) { if(remaining>0) throw new IOException("Incomplete HTTP body"); return; }
                    output.Write(buffer,0,n); if(remaining>=0) remaining-=n;
                }
            }
            r.BodyTruncated=true;
        } finally { r.Body=Encoding.UTF8.GetString(output.ToArray()); output.Dispose(); }
    }
    public static PhpAuditReplyV2 Probe(string host,string pinned,int port,bool tls,int seconds,bool insecure) {
        var r=new PhpAuditReplyV2(); TcpClient tcp=null; Stream stream=null; string phase="DNS"; var watch=System.Diagnostics.Stopwatch.StartNew();
        var deadline=new System.Threading.Timer(delegate(object state){try{if(tcp!=null)tcp.Close();}catch{}},null,seconds*3000,System.Threading.Timeout.Infinite);
        if(tls) r.Tls=insecure ? "DISABLED" : "UNVERIFIED";
        try {
            IPAddress address;
            if(!IPAddress.TryParse(String.IsNullOrEmpty(pinned)?host:pinned,out address)) {
                var lookup=Dns.BeginGetHostAddresses(host,null,null); Await(lookup,seconds*1000);
                address=null; foreach(var item in Dns.EndGetHostAddresses(lookup)) if(item.AddressFamily==AddressFamily.InterNetwork) { address=item; break; }
                if(address==null) throw new SocketException((int)SocketError.HostNotFound);
            }
            r.Address=address.ToString(); phase="TCP";
            tcp=new TcpClient(AddressFamily.InterNetwork);
            var connect=tcp.BeginConnect(address,port,null,null); Await(connect,seconds*1000); tcp.EndConnect(connect); r.TcpOpen=true;
            tcp.ReceiveTimeout=seconds*1000; tcp.SendTimeout=seconds*1000;
            stream=tcp.GetStream(); stream.ReadTimeout=seconds*1000; stream.WriteTimeout=seconds*1000;
            if(tls) {
                phase="TLS";
                var ssl=new SslStream(stream,false,delegate(object sender,X509Certificate cert,X509Chain chain,SslPolicyErrors errors) {
                    if(errors!=SslPolicyErrors.None) {
                        r.CertificateErrors=errors.ToString();
                        if(chain!=null) foreach(var status in chain.ChainStatus) r.CertificateErrors+="; "+status.Status.ToString();
                    }
                    return insecure || errors==SslPolicyErrors.None;
                });
                stream=ssl; ssl.ReadTimeout=seconds*1000; ssl.WriteTimeout=seconds*1000;
                var handshake=ssl.BeginAuthenticateAsClient(host,null,SslProtocols.None,false,null,null); Await(handshake,seconds*1000); ssl.EndAuthenticateAsClient(handshake);
                r.Tls=insecure ? "DISABLED" : "VALIDATED";
            }
            phase="HTTP";
            var request=Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: "+host+":"+port+"\r\nUser-Agent: PHP-Audit/2.0 (authorized read-only inventory)\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
            stream.Write(request,0,request.Length);
            int total=0,interim=0;
            do {
                string status=Line(stream,8192); total+=status.Length;
                var parts=status.Split(' '); int code;
                if(parts.Length<2 || !parts[0].StartsWith("HTTP/1.") || !Int32.TryParse(parts[1],out code) || code<100 || code>599) throw new IOException("Invalid HTTP status line");
                r.Status=code; r.Headers.Clear(); string line;
                while((line=Line(stream,8192)).Length>0) {
                    total+=line.Length+2; if(total>32768) throw new IOException("Response headers exceed 32 KiB");
                    int colon=line.IndexOf(':'); if(colon<1) throw new IOException("Malformed HTTP header");
                    string key=line.Substring(0,colon).Trim(),value=line.Substring(colon+1).Trim(),existing;
                    r.Headers[key]=r.Headers.TryGetValue(key,out existing) ? existing+", "+value : value;
                }
                if(++interim>6) throw new IOException("Too many interim responses");
            } while(r.Status>=100 && r.Status<200 && r.Status!=101);
            phase="BODY"; Body(stream,r);
        } catch(Exception e) {
            bool timed=e is TimeoutException || watch.ElapsedMilliseconds>=seconds*3000;
            for(Exception inner=e;inner!=null;inner=inner.InnerException) {
                var socket=inner as SocketException;
                if(socket!=null && socket.SocketErrorCode==SocketError.TimedOut) timed=true;
                if(socket!=null && socket.SocketErrorCode==SocketError.ConnectionRefused) r.ErrorCode="TCP_REFUSED";
                if(r.ErrorDetail.Length<1800) r.ErrorDetail+=(r.ErrorDetail.Length==0 ? "" : " -> ")+inner.GetType().Name+": "+inner.Message;
            }
            if(phase=="TLS" && r.CertificateErrors.Length>0 && !insecure) { r.Tls="FAILED"; r.ErrorCode="TLS_CERTIFICATE_INVALID"; r.ErrorDetail=r.CertificateErrors+"; "+r.ErrorDetail; }
            else if(r.ErrorCode.Length==0) r.ErrorCode=phase=="DNS" ? "DNS_FAILURE" : timed ? phase+"_TIMEOUT" : phase=="TLS" ? "TLS_HANDSHAKE_FAILED" : phase+"_FAILED";
        } finally { deadline.Dispose(); if(stream!=null) stream.Dispose(); if(tcp!=null) tcp.Close(); }
        return r;
    }
}
'@
}

$worker = {
    param($Target,$Ports,$TlsPorts,$TimeoutSeconds,$RemoteTimeoutSeconds,$Credential,$RemoteCurrentUser,$UseSSL,$WinRMPort,$InsecureTls,$CollectorText)
    $ErrorActionPreference='Stop'
    $hostName=$Target; $pinned=''; if($Target.Contains('=')) { $hostName,$pinned=$Target.Split('=',2) }
    $rows=New-Object 'System.Collections.Generic.List[object]'; $failures=New-Object 'System.Collections.Generic.List[string]'; $any=$false
    function Safe([string]$s) {
        $s=$s -replace '[\x00-\x1f\x7f]',' '
        $s=$s -replace '(?i)(https?://)[^/\s@]+@','$1[redacted]@'
        $s=$s -replace '(?i)(https?://[^?\s]+)\?[^\s]*','$1?[redacted]'
        $s=$s -replace '(?i)((?:authorization|cookie)\s*[:=]\s*).*','$1[redacted]'
        $s=$s -replace '(?i)((?:password|passwd|token|secret|authorization|cookie)\s*[:=]\s*)\S+','$1[redacted]'
        if($s.Length -gt 2000){$s=$s.Substring(0,2000)}; $s
    }
    function Row($Service,$Runtime,$App,$Version,$Package,$Reachable,$Detail) {
        [pscustomobject]@{IP=$Target;Hostname=$hostName;OS='-';Service=$Service;Runtime=$Runtime;Application=$App;PHPVersion=$Version;Package=$Package;Reachable=$Reachable;Evidence=(Safe $Detail);Address='-';DiscoveryCode='';HTTPStatus='';TLSValidation='';ErrorCode='';ErrorDetail='';RedirectTo='';Confidence='LOW'}
    }
    foreach($port in $Ports){
        $tls=$TlsPorts -contains $port; $scheme='HTTP'; if($tls){$scheme='HTTPS'}
        $reply=[PhpAuditTransportV2]::Probe($hostName,$pinned,$port,$tls,$TimeoutSeconds,$InsecureTls)
        if(-not $reply.TcpOpen){$failures.Add("${port}: $($reply.ErrorCode); $(Safe $reply.ErrorDetail)"); continue}
        $any=$true; $version='-';$apps='-';$phpHint=$false
        $server='';$powered='';$cookie='';$location=''
        if($reply.Headers.ContainsKey('Server')){$server=$reply.Headers['Server']}
        if($reply.Headers.ContainsKey('X-Powered-By')){$powered=$reply.Headers['X-Powered-By']}
        if($reply.Headers.ContainsKey('Set-Cookie')){$cookie=$reply.Headers['Set-Cookie']}
        if($reply.Headers.ContainsKey('Location')){$location=$reply.Headers['Location']}
        if("$server $powered" -match '(?i)PHP/([0-9]+\.[0-9]+\.[0-9]+[^ ;,\r\n]*)'){$version=$Matches[1]}
        $cookieNames=@([regex]::Matches($cookie,'(?:^|[,;]\s*)([A-Za-z0-9_]+)=') | ForEach-Object {$_.Groups[1].Value}) -join ' '
        $fingerprint="$($reply.Body) $server $powered $cookieNames"
        $patterns=[ordered]@{WordPress='wp-content/|wp-includes/|generator[^>]*WordPress';Nextcloud='nextcloud|nc_sameSiteCookies';Joomla='joomla|/media/system/';Drupal='drupal|data-drupal|/sites/default/';Laravel='laravel|laravel_session';Magento='magento|/static/version[0-9]+/|mage/cookies';MediaWiki='mediawiki|mw-config|wgCanonicalNamespace';phpBB='phpbb';WHMCS='whmcs|/templates/six/|/templates/twenty-one/'}
        $found=@(foreach($name in $patterns.Keys){if($fingerprint -match $patterns[$name]){"$name (indicio)"}})
        if($found.Count){$apps=$found -join '; ';$phpHint=$true}
        if("$server $powered $cookieNames" -match '(?i)\bPHP\b|PHPSESSID'){$phpHint=$true}
        $discovery='PHP_NOT_IDENTIFIED'; if($phpHint){$discovery='PHP_NO_VERSION'}; if($version -ne '-'){$discovery='PHP_VERSION_IDENTIFIED'}
        if(-not $reply.Status){$discovery='CONNECTION_ERROR'}
        $o=Row "${scheme}:$port" "web:$port" $apps $version '-' SIM "TCP open; HTTP=$($reply.Status); bounded GET / (64 KiB); no redirects; bodyTruncated=$($reply.BodyTruncated)"
        $o.Address=$reply.Address;$o.DiscoveryCode=$discovery;$o.HTTPStatus=if($reply.Status){[string]$reply.Status}else{''};$o.TLSValidation=$reply.Tls
        $o.ErrorCode=$reply.ErrorCode;$o.ErrorDetail=Safe $reply.ErrorDetail
        if($reply.Status -ge 300 -and $reply.Status -lt 400 -and $location){
            # Only origin/path are retained; credentials, query strings and fragments are discarded.
            try {$u=New-Object Uri (New-Object Uri ("$($scheme.ToLower())://${hostName}:$port/")), $location;$uriBuilder=New-Object UriBuilder $u;$uriBuilder.UserName='';$uriBuilder.Password='';$uriBuilder.Query='';$uriBuilder.Fragment='';$o.RedirectTo=$uriBuilder.Uri.GetLeftPart([UriPartial]::Path)} catch {$o.RedirectTo='[invalid Location]'}
        }
        if($reply.Status){$o.Confidence='MEDIUM'}
        if($reply.Tls -eq 'DISABLED'){$o.Confidence='LOW';$o.Evidence+='; TLS validation explicitly disabled; no trust assurance'}
        $rows.Add($o)
    }
    if(-not $any){
        $o=Row DISCOVERY host '-' '-' '-' DESCONHECIDO 'No web service detected on tested ports; PHP is not ruled out'
        $o.DiscoveryCode='NO_WEB_SERVICE';$o.ErrorCode='NO_TCP_RESPONSE';$o.ErrorDetail=Safe ($failures -join ' | ')
        if(($failures -join ' ') -match 'DNS_FAILURE'){$o.DiscoveryCode='CONNECTION_ERROR';$o.ErrorCode='DNS_FAILURE'}
        if($pinned){$o.Address=$pinned}elseif($hostName -match '^\d+\.\d+\.\d+\.\d+$'){$o.Address=$hostName}
        $rows.Add($o)
    }
    if($Credential -or $RemoteCurrentUser){
        $remoteJob=$null;$remoteOS='-';$remoteHost=$hostName;$complete=$false;$errorText=''
        try {
            $parameters=@{ComputerName=$hostName;UseSSL=[bool]$UseSSL;AsJob=$true;ErrorAction='Stop';SessionOption=(New-PSSessionOption -OpenTimeout ($TimeoutSeconds*1000) -OperationTimeout ($RemoteTimeoutSeconds*1000));ScriptBlock=[scriptblock]::Create($CollectorText)}
            # 0 means unspecified. Let WinRM select its native HTTP/HTTPS default.
            if($WinRMPort -gt 0){$parameters.Port=$WinRMPort}
            if($Credential){$parameters.Credential=$Credential}
            $remoteJob=Invoke-Command @parameters
            $null=Wait-Job $remoteJob -Timeout $RemoteTimeoutSeconds
            $remoteRows=@(Receive-Job $remoteJob -ErrorAction SilentlyContinue)
            $complete=$remoteJob.State -eq 'Completed' -and @($remoteRows|Where-Object {$_.Service -eq 'META' -and $_.Runtime -eq 'COMPLETE'}).Count -gt 0
            if(-not $complete){$errorText='WinRM incomplete or timed out';if($remoteJob.ChildJobs.Count -and $remoteJob.ChildJobs[0].JobStateInfo.Reason){$errorText=Safe $remoteJob.ChildJobs[0].JobStateInfo.Reason.Message}}
            foreach($r in $remoteRows){
                if($r.Service -eq 'META'){if($r.Runtime -eq 'OS'){$remoteOS=$r.Evidence};if($r.Runtime -eq 'HOST'){$remoteHost=$r.Evidence};continue}
                $o=Row $r.Service $r.Runtime '-' $r.PHPVersion $r.Package NA $r.Evidence;$rows.Add($o)
            }
        } catch {$errorText=Safe $_.Exception.Message}
        finally {if($remoteJob){Stop-Job $remoteJob -ErrorAction SilentlyContinue;Remove-Job $remoteJob -Force -ErrorAction SilentlyContinue}}
        $o=Row WinRM inventory '-' '-' '-' NA "Collector finished=$complete; completeness is not guaranteed; permissions limit coverage"
        if(-not $complete){$o.ErrorCode='WINRM_FAILED';$o.ErrorDetail=$errorText};$rows.Add($o)
        foreach($r in $rows){$r.Hostname=$remoteHost;$r.OS=$remoteOS}
    }
    $rows.ToArray()
}

if(-not $SelfTest -and -not $Simulate){
    $scope=@($Targets);if($TargetsFile){$scope+=@(Get-Content -LiteralPath $TargetsFile -Encoding UTF8)}
    $ips=@(Expand-Scope $scope $MaxHosts)
    if(-not $ips.Count -and -not $LocalInventory){throw 'Indique alvos / Provide targets (or -LocalInventory).'}
    Write-Host "$(T scanning): $($ips.Count) targets; concurrency=$Concurrency"
    $pool=[RunspaceFactory]::CreateRunspacePool(1,$Concurrency);$pool.Open()
    $pending=New-Object 'System.Collections.Generic.Queue[string]';foreach($ip in $ips){$pending.Enqueue($ip)}
    $jobs=New-Object 'System.Collections.Generic.List[object]';$collected=New-Object 'System.Collections.Generic.List[object]'
    try {
        while($pending.Count -or $jobs.Count){
            while($pending.Count -and $jobs.Count -lt $Concurrency){
                $ip=$pending.Dequeue();$ps=[PowerShell]::Create();$ps.RunspacePool=$pool
                $null=$ps.AddScript($worker.ToString()).AddArgument($ip).AddArgument($Ports).AddArgument($TlsPorts).AddArgument($TimeoutSeconds).AddArgument($RemoteTimeoutSeconds).AddArgument($Credential).AddArgument([bool]$RemoteCurrentUser).AddArgument([bool]$UseSSL).AddArgument($WinRMPort).AddArgument([bool]$InsecureTls).AddArgument($remoteCollector.ToString())
                $jobs.Add(@{PS=$ps;Handle=$ps.BeginInvoke();Target=$ip})
            }
            foreach($entry in @($jobs.ToArray())){
                if(-not $entry.Handle.IsCompleted){continue}
                try {$items=@($entry.PS.EndInvoke($entry.Handle));foreach($o in $items){$collected.Add($o)};if(-not $items.Count -or $entry.PS.HadErrors){throw 'Incomplete worker'}}
                catch {$o=New-Observation $entry.Target '-' '-' DISCOVERY host '-' '-' '-' DESCONHECIDO 'Worker failed; partial coverage';$o|Add-Member ErrorCode WORKER_FAILED;$o|Add-Member ErrorDetail (Convert-SafeCell $_.Exception.Message);$collected.Add($o)}
                finally {$entry.PS.Dispose();$null=$jobs.Remove($entry)}
            }
            if($jobs.Count){Start-Sleep -Milliseconds 80}
        }
    } finally {foreach($entry in $jobs){$entry.PS.Stop();$entry.PS.Dispose()};$pool.Close();$pool.Dispose()}
    if($LocalInventory){
        $complete=$false
        try {
            foreach($r in @(& $remoteCollector)){
                if($r.Service -eq 'META'){if($r.Runtime -eq 'COMPLETE'){$complete=$true};continue}
                $collected.Add((New-Observation local $env:COMPUTERNAME ([Environment]::OSVersion.VersionString) $r.Service $r.Runtime '-' $r.PHPVersion $r.Package NA $r.Evidence))
            }
            $collected.Add((New-Observation local $env:COMPUTERNAME Windows LOCAL inventory '-' '-' '-' NA "Local collector finished=$complete; completeness is not guaranteed; permissions limit coverage"))
        } catch {$o=New-Observation local $env:COMPUTERNAME Windows LOCAL inventory '-' '-' '-' NA 'Local inventory failed';$o|Add-Member ErrorCode LOCAL_FAILED;$o|Add-Member ErrorDetail (Convert-SafeCell $_.Exception.Message);$collected.Add($o)}
    }
    $observations=@($collected.ToArray()|Sort-Object IP,Service,Runtime)
}

# Discovery and CVE assessment are deliberately independent.
$labels=@{
 target=@('Alvo','Target');address=@('IP','IP');discovery=@('Descoberta','Discovery');vulnerability=@('Vulnerabilidade','Vulnerability');confidence=@('Confiança na evidência PHP','Confidence in PHP evidence');group=@('Secção','Section');error=@('Erro técnico','Technical error');errorCode=@('Código de erro','Error code');http=@('HTTP','HTTP');tls=@('Validação TLS','TLS validation');redirect=@('Redirecionamento (não seguido)','Redirect (not followed)');
 webGroup=@('Serviços web e candidatos','Web services and candidates');inventoryGroup=@('Inventário local/remoto','Local/remote inventory');noWebGroup=@('Alvos sem serviço web detetado','Targets without a detected web service');errorsGroup=@('Erros de ligação/recolha','Connection/collection errors');
 targetCount=@('Alvos analisados','Targets checked');tcpCount=@('Portas TCP abertas candidatas','Candidate open TCP ports');webCount=@('Respostas HTTP/HTTPS','HTTP/HTTPS responses');webHosts=@('Alvos com resposta web','Targets with web responses');noWebCount=@('Alvos sem porta web aberta detetada','Targets without a detected open web port');phpCount=@('Alvos com indícios PHP','Targets with PHP evidence');errorCount=@('Erros de ligação/recolha','Connection/collection errors');
 NO_WEB_SERVICE=@('SEM SERVIÇO WEB DETETADO','NO WEB SERVICE DETECTED');PHP_NOT_IDENTIFIED=@('PHP NÃO IDENTIFICADO','PHP NOT IDENTIFIED');PHP_NO_VERSION=@('PHP IDENTIFICADO SEM VERSÃO (indício)','PHP IDENTIFIED WITHOUT VERSION (hint)');PHP_VERSION_IDENTIFIED=@('VERSÃO PHP IDENTIFICADA','PHP VERSION IDENTIFIED');CONNECTION_ERROR=@('ERRO DE LIGAÇÃO','CONNECTION ERROR');INVENTORY_PHP=@('PHP NO INVENTÁRIO','PHP IN INVENTORY');INVENTORY_OTHER=@('OUTRO COMPONENTE NO INVENTÁRIO','OTHER INVENTORY COMPONENT');INVENTORY_COMPLETE=@('RECOLHA DE INVENTÁRIO','INVENTORY COLLECTION');
 confidence_LOW=@('BAIXA','LOW');confidence_MEDIUM=@('MÉDIA','MEDIUM');confidence_HIGH=@('ALTA','HIGH');INVENTORY_ERROR=@('ERRO/PERMISSÕES NO INVENTÁRIO','INVENTORY ERROR/PERMISSIONS');
 candidateHosts=@('IPs com portas candidatas','IPs with candidate ports');
 noWebAction=@('Confirmar rede, DNS, firewall e portas autorizadas. Não foi excluída a existência de PHP.','Check network, DNS, firewall and authorized ports. PHP has not been ruled out.');
 noPhpAction=@('O serviço respondeu sem indícios PHP. Confirmar o site virtual/SNI e inventariar o servidor se autorizado.','The service responded without PHP evidence. Check the virtual host/SNI and inventory the server if authorized.');
 noVersionAction=@('Existem indícios PHP sem versão. Recolher inventário local ou por SSH/WinRM autorizado e confirmar o runtime web.','PHP hints have no version. Collect local or authorized SSH/WinRM inventory and confirm the web runtime.');
 tlsAction=@('Corrigir a cadeia de confiança, validade e nome do certificado; usar o hostname/SNI correto. A validação TLS mantém-se ativa.','Check certificate trust chain, validity and hostname; use the correct DNS/SNI name. TLS validation remains enabled.');
 connectAction=@('Consultar o erro técnico; confirmar DNS, rota, firewall, protocolo e tempo limite. Repetir apenas no âmbito autorizado.','Review the technical error; check DNS, routing, firewall, protocol and timeout. Retry only within the authorized scope.');
 redirectAction=@('O redirecionamento não foi seguido. Autorizar e indicar explicitamente o destino correto, incluindo o hostname/SNI.','The redirect was not followed. Authorize and explicitly supply the correct destination, including its DNS/SNI name.');
 inventoryAction=@('Confirmar permissões e associar processos, pacotes e executáveis ao runtime web; versões em disco/CLI não certificam o site.','Check permissions and link processes, packages and executables to the web runtime; disk/CLI versions do not certify the site.');
 remoteAction=@('Confirmar credenciais, permissões e a configuração SSH/WinRM existente; consultar o erro técnico.','Check credentials, permissions and existing SSH/WinRM configuration; review the technical error.');
 summaryNote=@('Portas TCP abertas são candidatas: só uma resposta HTTP confirma um serviço web. Confiança refere-se à evidência PHP, não à segurança do equipamento. INCONCLUSIVO nunca significa seguro.','Open TCP ports are candidates: only an HTTP response confirms a web service. Confidence describes PHP evidence, not host safety. INCONCLUSIVE never means safe.');
 limitText=@('Só os alvos e portas autorizados são analisados. DNS/SNI identifica o site pedido; não enumera todos os sites virtuais nem backends. Redirecionamentos não são seguidos. Inventário depende das permissões e não entra nos contentores. Exposição pública é declarada pelo técnico. Sem exploits ou alterações nos alvos.','Only authorized targets and ports are checked. DNS/SNI selects the requested site; it does not enumerate every virtual host or backend. Redirects are not followed. Inventory depends on permissions and does not enter containers. Public exposure is technician-declared. No exploits or target changes.');
}
foreach($key in $labels.Keys){$Text[$key]=$labels[$key]}
function Get-Optional($Object,[string]$Name,[string]$Default='') {
    if($Object.PSObject.Properties[$Name] -and $null -ne $Object.$Name -and [string]$Object.$Name -ne '-') {return [string]$Object.$Name}
    $Default
}
function Sanitized-Detail([string]$Value){
    $s=Convert-SafeCell $Value
    $s=$s -replace '(?i)(https?://)[^/\s@]+@','$1[redacted]@'
    $s=$s -replace '(?i)(https?://[^?\s]+)\?[^\s]*','$1?[redacted]'
    $s=$s -replace '(?i)((?:authorization|cookie)\s*[:=]\s*).*','$1[redacted]'
    $s=$s -replace '(?i)((?:password|passwd|token|secret|authorization|cookie)\s*[:=]\s*)\S+','$1[redacted]'
    $s
}
$results=@(foreach($o in $observations){
    $verified=$false;$a='UNKNOWN';$b='UNKNOWN';$version=$o.PHPVersion;$package=$o.Package;$detail=$o.Evidence
    $key="$($o.IP)|$($o.Service)|$($o.Runtime)"
    $webRuntime=$o.Service -match '^HTTPS?:|PHP-FPM|mod_php|php.*cgi|lsphp|frankenphp'
    if($evidenceMap.ContainsKey($key)){
        $e=$evidenceMap[$key]
        if($webRuntime -and $e.ReviewedAt -ceq $Today -and $e.RuntimeVerified -ceq 'TRUE' -and $e.ReviewedBy -ne '-' -and $e.Advisory -cmatch '^https://[^\s@]+$' -and $e.PHPVersion -cmatch '^\d+\.\d+\.\d+$' -and ($version -eq '-' -or $version -ceq $e.PHPVersion) -and ($package -eq '-' -or $package -ceq $e.Package)){
            $state=Get-VersionState $e.PHPVersion
            if($e.CVE109618 -ne 'FIXED' -or $e.CVE109619 -ne 'FIXED' -or $state -eq 'FIXED_VERSION' -or $e.Package -ne '-'){
                $verified=$true;$a=$e.CVE109618;$b=$e.CVE109619;$version=$e.PHPVersion;$package=$e.Package
                $detail+="; reviewed: $($e.ReviewedBy), $($e.ReviewedAt); CVE109618=$a; CVE109619=$b; $($e.Advisory)"
            }else{$detail+='; rejected: backport requires exact package/build'}
        }else{$detail+='; ignored: stale, mismatched or incomplete attestation'}
    }
    $classification=Get-Classification $version $o.Service $verified $a $b
    $vcode='INCONCLUSIVE';$status=T inconclusive;$risk=T undetermined;$action=T unknownAction
    switch($classification){
        VULNERAVEL {$vcode='VULNERABLE_CONFIRMED';$status=T vulnerable;$risk=T high;$action=T vulnAction}
        CORRIGIDO {$vcode='FIXED';$status=T fixed;$risk=T low;$action=T fixAction}
        'POTENCIALMENTE VULNERAVEL' {$vcode='POTENTIALLY_VULNERABLE';$status=T potential;$risk=T high;$action=T oldAction}
    }
    $group='INVENTORY';$discovery=Get-Optional $o DiscoveryCode
    if($o.Service -match '^HTTPS?:'){$group='WEB';if(-not $discovery){$discovery=if($version -ne '-'){'PHP_VERSION_IDENTIFIED'}elseif($o.Application -ne '-'){'PHP_NO_VERSION'}else{'PHP_NOT_IDENTIFIED'}}}
    elseif($o.Service -eq 'DISCOVERY'){$group='NO_RESPONSE';if(-not $discovery){$discovery='NO_WEB_SERVICE'}}
    elseif(-not $discovery){$discovery=if($o.Service -in @('WinRM','SSH','LOCAL')){'INVENTORY_COMPLETE'}elseif($version -ne '-' -or $o.Service -match 'PHP|mod_php|CLI' -or $package -match 'php'){'INVENTORY_PHP'}else{'INVENTORY_OTHER'}}
    if($o.Service -match '^(Docker|Podman)$' -and $o.Evidence -match '(?:Imagem|Image)=([^;]+)' -and $Matches[1] -match '(?i)php'){$discovery='INVENTORY_PHP'}
    $errorCode=Get-Optional $o ErrorCode;$errorDetail=Sanitized-Detail (Get-Optional $o ErrorDetail);$http=Get-Optional $o HTTPStatus;$tls=Get-Optional $o TLSValidation;$redirect=Get-Optional $o RedirectTo
    if($o.Service -eq 'COLLECTION'){$discovery='INVENTORY_ERROR';$errorCode='INVENTORY_PARTIAL';$errorDetail=Sanitized-Detail $o.Evidence}
    if($group -eq 'INVENTORY' -and $errorCode){$discovery='INVENTORY_ERROR'}
    if($errorCode -eq 'WORKER_FAILED'){$discovery='CONNECTION_ERROR'}
    $confidence=Get-Optional $o Confidence LOW;if($version -ne '-'){$confidence='MEDIUM'};if($verified){$confidence='HIGH'};if($tls -eq 'DISABLED'){$confidence='LOW'}
    if($vcode -eq 'INCONCLUSIVE'){
        switch($discovery){NO_WEB_SERVICE {$action=T noWebAction};PHP_NOT_IDENTIFIED {$action=T noPhpAction};PHP_NO_VERSION {$action=T noVersionAction};CONNECTION_ERROR {$action=T connectAction};default {if($group -eq 'INVENTORY'){$action=T inventoryAction}}}
        if($errorCode -like 'TLS_CERTIFICATE*'){$action=T tlsAction}elseif($errorCode -and $errorCode -ne 'NO_TCP_RESPONSE'){$action=T connectAction}
        if($errorCode -in @('INVENTORY_PARTIAL','LOCAL_FAILED')){$action=T inventoryAction}
        if($errorCode -in @('WINRM_FAILED','SSH_FAILED')){$action=T remoteAction}
        if($redirect){$action=T redirectAction}
    }
    $address=Get-Optional $o Address '-';if($address -eq '-' -and $o.IP -match '^\d+\.\d+\.\d+\.\d+$'){$address=$o.IP}
    $public=T unknownValue;if($publicMap.ContainsKey($o.IP) -or $publicMap.ContainsKey($address) -or $publicMap.ContainsKey(($o.IP -split '=')[0])){$public=T declared;if($vcode -eq 'VULNERABLE_CONFIRMED'){$risk=T critical}}
    $reachable=T unknownValue;if($o.Reachable -eq 'SIM'){$reachable=T yes}elseif($o.Reachable -eq 'NA'){$reachable=T na}elseif($o.Reachable -eq 'SIMULADO'){$reachable='SIMULATED'}
    [pscustomobject]@{Target=$o.IP;IP=$address;Hostname=$o.Hostname;OS=$o.OS;Group=$group;Service=$o.Service;Runtime=$o.Runtime;Application=$o.Application.Replace('(indicio)',('('+(T hint)+')'));PHPVersion=$version;Package=$package;CVEs=$Cves;DiscoveryCode=$discovery;Discovery=(T $discovery);VulnerabilityCode=$vcode;Vulnerability=$status;Risk=$risk;Confidence=(T ("confidence_"+$confidence));HTTPStatus=$http;TLSValidation=$tls;ErrorCode=$errorCode;ErrorDetail=$errorDetail;RedirectTo=$redirect;Reachable=$reachable;PublicExposure=$public;Evidence=(Sanitized-Detail (Translate-Detail "$detail; CVE109618=$a; CVE109619=$b"));Recommendation=$action}
})
if(-not $results.Count){throw 'No results / Sem resultados.'}
function Encode-Html($Value){[Net.WebUtility]::HtmlEncode((Convert-SafeCell $Value))}
$null=New-Item -ItemType Directory -Path $OutDir -Force
$runPath=Join-Path (Resolve-Path -LiteralPath $OutDir).Path ('php-audit-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $runPath
$csvPath=Join-Path $runPath report.csv;$htmlPath=Join-Path $runPath report.html
$fields=@('Target','IP','Hostname','OS','Group','Service','DiscoveryCode','Discovery','PHPVersion','CVEs','VulnerabilityCode','Vulnerability','Risk','Confidence','HTTPStatus','TLSValidation','ErrorCode','ErrorDetail','RedirectTo','Application','Runtime','Package','Reachable','PublicExposure','Evidence','Recommendation')
$keys=@('target','address','host','os','group','service','DiscoveryCode','discovery','php','cves','VulnerabilityCode','vulnerability','risk','confidence','http','tls','errorCode','error','redirect','app','runtime','package','reachable','public','evidence','recommendation')
$exportRows=@(foreach($row in $results){$item=[ordered]@{};for($i=0;$i -lt $fields.Count;$i++){$label=$keys[$i];if($Text.ContainsKey($label)){$label=T $label};$value=$row.($fields[$i]);if($fields[$i] -eq 'Group'){$value=T (@{WEB='webGroup';INVENTORY='inventoryGroup';NO_RESPONSE='noWebGroup'}[$value])};$item[$label]=Convert-CsvSafe $value};[pscustomobject]$item})
# Explicit UTF-8 BOM on both PowerShell engines; blank unknown cells, formula protection retained.
$csv=($exportRows|ConvertTo-Csv -NoTypeInformation) -join "`r`n"
[IO.File]::WriteAllText($csvPath,$csv+"`r`n",(New-Object Text.UTF8Encoding($true)))
function Report-Table($Rows){
    $head=@('target','service','discovery','php','vulnerability','confidence','action')|ForEach-Object {'<th scope="col">'+(Encode-Html (T $_))+'</th>'}
    $body=@(foreach($row in $Rows){
        $technical="IP=$($row.IP); $(T host)=$($row.Hostname); $(T os)=$($row.OS); $(T app)=$($row.Application); $($row.Runtime); $($row.Package); HTTP=$($row.HTTPStatus); TLS=$($row.TLSValidation); $($row.ErrorCode); $($row.ErrorDetail); $(T redirect)=$($row.RedirectTo); $(T public)=$($row.PublicExposure); $(T risk)=$($row.Risk); $(T reachable)=$($row.Reachable); $($row.Evidence)"
        '<tr><td><strong>'+(Encode-Html $row.Target)+'</strong><details><summary>'+(T details)+'</summary><p>'+(Encode-Html $technical)+'</p></details></td><td>'+(Encode-Html $row.Service)+'</td><td>'+(Encode-Html $row.Discovery)+'</td><td>'+(Encode-Html $row.PHPVersion)+'</td><td>'+(Encode-Html $row.Vulnerability)+'</td><td>'+(Encode-Html $row.Confidence)+'</td><td>'+(Encode-Html $row.Recommendation)+'</td></tr>'
    })
    '<div class="table"><table><thead><tr>'+($head -join '')+'</tr></thead><tbody>'+($body -join "`n")+'</tbody></table></div>'
}
$web=@($results|Where-Object Group -eq WEB);$inventory=@($results|Where-Object Group -eq INVENTORY);$noWeb=@($results|Where-Object Group -eq NO_RESPONSE)
$errors=@($results|Where-Object {$_.ErrorCode -and $_.ErrorCode -ne 'NO_TCP_RESPONSE'})
$httpRows=@($web|Where-Object {$_.HTTPStatus -match '^\d+$' -and [int]$_.HTTPStatus -gt 0})
$stats=[ordered]@{targetCount=@($results.Target|Sort-Object -Unique).Count;results=$results.Count;tcpCount=$web.Count;candidateHosts=@($web.IP|Where-Object {$_ -and $_ -ne '-'}|Sort-Object -Unique).Count;webCount=$httpRows.Count;webHosts=@($httpRows.Target|Sort-Object -Unique).Count;noWebCount=$noWeb.Count;phpCount=@($results|Where-Object {$_.DiscoveryCode -match '^PHP_(NO_VERSION|VERSION_IDENTIFIED)$|^INVENTORY_PHP$'}|Select-Object -ExpandProperty Target -Unique).Count;errorCount=$errors.Count;attention=@($results|Where-Object {$_.VulnerabilityCode -in @('VULNERABLE_CONFIRMED','POTENTIALLY_VULNERABLE')}).Count}
$cards=foreach($k in $stats.Keys){'<div><strong>'+$stats[$k]+'</strong>'+(Encode-Html (T $k))+'</div>'}
$sections='<h2>'+(T webGroup)+' ('+$web.Count+')</h2>'+(Report-Table $web)
if($inventory.Count){$sections+='<h2>'+(T inventoryGroup)+' ('+$inventory.Count+')</h2>'+(Report-Table $inventory)}
if($errors.Count){$sections+='<h2>'+(T errorsGroup)+' ('+$errors.Count+')</h2>'+(Report-Table $errors)}
if($noWeb.Count){$sections+='<details class="no-response"><summary>'+(T noWebGroup)+' ('+$noWeb.Count+')</summary>'+(Report-Table $noWeb)+'</details>'}
$simulationNote='';if($SelfTest -or $Simulate){$simulationNote='<p><strong>'+(T simulated)+'</strong></p>'}
$html=@"
<!doctype html><html lang="$Language"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>$(T title)</title>
<style>body{font:14px system-ui,sans-serif;color:#183047;background:#f3f6fa;margin:0;padding:24px}main{max-width:1500px;margin:auto}h1{margin-bottom:6px}p{line-height:1.6}.stats{display:flex;flex-wrap:wrap;gap:10px;margin:20px 0}.stats div{padding:14px;background:white;border:1px solid #d6e0e9;border-radius:6px}.stats strong{font-size:24px;display:block}.table{overflow:auto;background:white}table{width:100%;min-width:1050px;border-collapse:collapse}td:first-child{min-width:120px}td:nth-child(2),td:nth-child(4){white-space:nowrap}td:nth-child(3){min-width:165px}td:nth-child(5){min-width:145px}td:last-child{min-width:260px}th,td{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #dde5ee}th{background:#143a5e;color:white}td{overflow-wrap:anywhere}td details{font-size:12px;max-width:390px}summary{cursor:pointer;color:#385a75}.no-response{margin-top:25px}footer{font-size:12px;margin-top:25px}@media print{body{padding:0}.table{overflow:visible}table{font-size:10px;min-width:0}td{min-width:0!important}}</style></head><body><main>
<h1>$(T title)</h1><p>$Cves · $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC</p>$simulationNote
<p><strong>$(T scope):</strong> $(Encode-Html ($Targets -join ', '))</p><div class="stats">$($cards -join '')</div>
<p>$(T summaryNote)</p><p>$(T explain)</p>$sections
<footer><p>$(T versions)</p><p>$(T limitText)</p><a href="https://www.php.net/archive/2026.php#2026-10-21-5">$(T source)</a></footer></main></body></html>
"@
[IO.File]::WriteAllText($htmlPath,$html,(New-Object Text.UTF8Encoding($false)))
Write-Host "$(T done):`n$htmlPath`n$csvPath"
