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
    [ValidateRange(1,65535)][int]$WinRMPort = 0,
    [switch]$InsecureTls,
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
if (-not $Targets.Count -and -not $TargetsFile -and -not $Simulate -and -not $SelfTest -and
    ($isIseHost -or ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected))) {
    $Targets = @((Read-Host 'IPs / Rede / Network (ex.: 192.168.1.0/24)'))
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
 'vulnerable' = @('VULNERÁVEL','VULNERABLE')
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
if (-not $WinRMPort) { if ($UseSSL) { $WinRMPort = 5986 } else { $WinRMPort = 5985 } }

function Expand-Scope([string[]]$Scope, [int]$Limit) {
    function IpNumber([string]$Address) {
        if ($Address -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { throw "Invalid IPv4 / IPv4 invalido: $Address" }
        [long]$v=0
        for($j=1;$j -le 4;$j++){ $o=[int]$Matches[$j]; if($o -gt 255){throw "Invalid IPv4: $Address"}; $v=$v*256+$o }
        return $v
    }
    $seen=@{}
    foreach($line in $Scope){foreach($token in (($line -replace '#.*$','') -split '[,\s]+' | Where-Object { $_ })){
        if($token.Contains('-')){
            $range=$token.Split('-');if($range.Count -ne 2){throw "Invalid range / Intervalo invalido: $token"}
            [long]$lo=IpNumber $range[0]
            if($range[1] -match '^\d{1,3}$'){
                $last=[int]$range[1];if($last -gt 255){throw "Invalid range: $token"}
                [long]$hi=[math]::Floor($lo/256)*256+$last
            }else{[long]$hi=IpNumber $range[1]}
        }else{
            $parts=$token.Split('/');if($parts.Count -gt 2){throw "Invalid CIDR: $token"}
            [long]$v=IpNumber $parts[0];$prefix=32
            if($parts.Count -eq 2){if($parts[1] -notmatch '^\d{1,2}$' -or [int]$parts[1] -gt 32){throw "Invalid CIDR: $token"};$prefix=[int]$parts[1]}
            [long]$size=[math]::Pow(2,32-$prefix);if($size -gt $Limit){throw 'CIDR exceeds / excede MaxHosts'}
            [long]$lo=[math]::Floor($v/$size)*$size;[long]$hi=$lo+$size-1
            if($prefix -lt 31){$lo++;$hi--}
        }
        if($hi -lt $lo -or $hi-$lo+1 -gt $Limit){throw "Invalid or excessive range / Intervalo invalido ou excessivo: $token"}
        for([long]$n=$lo;$n -le $hi;$n++){
            $ip='{0}.{1}.{2}.{3}' -f ([math]::Floor($n/16777216)),([math]::Floor($n/65536)%256),([math]::Floor($n/256)%256),($n%256)
            if(-not $seen.ContainsKey($ip)){ $seen[$ip]=$true;if($seen.Count -gt $Limit){throw 'Too many IPs / Demasiados IPs'};$ip }
        }
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
    if ($Service -ne 'CLI' -and $state -in @('BELOW','LEGACY')) { return 'POTENCIALMENTE VULNERAVEL' }
    return 'INCONCLUSIVO'
}
function New-Observation($IP,$Hostname,$OS,$Service,$Runtime,$Application,$PHPVersion,$Package,$Reachable,$Evidence) {
    [pscustomobject][ordered]@{IP=$IP;Hostname=$Hostname;OS=$OS;Service=$Service;Runtime=$Runtime;Application=$Application;PHPVersion=$PHPVersion;Package=$Package;Reachable=$Reachable;Evidence=$Evidence}
}
function Read-Protocol([string]$Path,[string[]]$Fields) {
    $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8)
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
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) { Get-CimInstance -ClassName $Class -ErrorAction Stop }
        else { Get-WmiObject -Class $Class -ErrorAction Stop }
    }
    $os='Windows';try { $os=(Inventory-Cim Win32_OperatingSystem).Caption } catch {}
    [pscustomobject]@{Service='META';Runtime='OS';PHPVersion='-';Package='-';Evidence=$os}
    [pscustomobject]@{Service='META';Runtime='HOST';PHPVersion='-';Package='-';Evidence=$env:COMPUTERNAME}
    $paths=@{}
    foreach ($cmd in @(Get-Command php.exe -All -ErrorAction SilentlyContinue)) { if ($cmd.Source) { $paths[$cmd.Source]=$true } }
    foreach ($path in @('C:\PHP\php.exe','C:\PHP\php-cgi.exe','C:\Program Files\PHP\php.exe','C:\Program Files (x86)\PHP\php.exe')) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { $paths[$path]=$true }
    }
    try {
        foreach ($p in @(Inventory-Cim Win32_Process | Where-Object { $_.Name -match '^(php.*|httpd|nginx|w3wp|frankenphp|lsphp)\.exe$' })) {
            $name=$p.Name; $path=$p.ExecutablePath
            Obs $name "process:$($p.ProcessId)" '-' '-' "Processo ativo; executavel=$path; versao carregada por confirmar"
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
                $v=(& $path -n -r 'echo PHP_VERSION;' 2>$null | Out-String).Trim()
                if ($v -notmatch '^\d+\.\d+\.\d+[\w.+-]*$') { $v='-' }
                Obs CLI "cli:$path" $v '-' 'PHP_VERSION via -n; CLI nao comprova runtime web'
            } else {
                $v=(Get-Item -LiteralPath $path).VersionInfo.ProductVersion
                if ($v -notmatch '^\d+\.\d+\.\d+[\w.+-]*$') { $v='-' }
                Obs PHP-BINARY "binary:$path" $v '-' 'Versao do ficheiro em disco; nao comprova versao dos workers em memoria'
            }
        } catch { Obs COLLECTION "binary:$path" '-' '-' 'Versao PHP indisponivel ou sem permissao' }
    }
    if (Get-Command docker.exe -ErrorAction SilentlyContinue) {
        try {
            foreach ($line in @(& docker.exe ps --format '{{.ID}}|{{.Image}}|{{.Ports}}' 2>$null | Select-Object -First 100)) {
                $parts=$line -split '\|',3
                Obs Docker "docker:$($parts[0])" '-' '-' "Imagem=$($parts[1]); portas=$($parts[2]); versao PHP/digest carregado por confirmar"
            }
        } catch { Obs COLLECTION docker '-' '-' 'Docker sem acesso; conteineres por confirmar' }
    }
    Obs META COMPLETE '-' '-' 'Inventario limitado aos privilegios da conta; nao implica cobertura de todas as instalacoes'
}

$worker = {
    param($IP,$Ports,$TlsPorts,$TimeoutSeconds,$RemoteTimeoutSeconds,$Credential,$RemoteCurrentUser,$UseSSL,$WinRMPort,$InsecureTls,$CollectorText)
    $ErrorActionPreference='Stop'
    function Row($Service,$Runtime,$App,$Version,$Package,$Reachable,$Detail) {
        [pscustomobject]@{IP=$IP;Hostname='-';OS='-';Service=$Service;Runtime=$Runtime;Application=$App;PHPVersion=$Version;Package=$Package;Reachable=$Reachable;Evidence=$Detail}
    }
    function Test-Tcp([int]$Port) {
        $tcp=New-Object Net.Sockets.TcpClient
        try {
            $task=$tcp.ConnectAsync($IP,$Port)
            if (-not $task.Wait($TimeoutSeconds*1000)) { return $false }
            return $tcp.Connected
        } catch { return $false } finally { $tcp.Dispose() }
    }
    $rows=New-Object 'System.Collections.Generic.List[object]'; $any=$false
    # Per-worker TLS opt-in; never changes the parent session or WinRM checks.
    $oldCallback=[Net.ServicePointManager]::ServerCertificateValidationCallback
    $oldProtocol=[Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol=$oldProtocol -bor [Net.SecurityProtocolType]::Tls12
        if ($InsecureTls) {
            Add-Type 'public static class AuditTls { public static bool Accept(object a, System.Security.Cryptography.X509Certificates.X509Certificate b, System.Security.Cryptography.X509Certificates.X509Chain c, System.Net.Security.SslPolicyErrors d) { return true; } }'
            [Net.ServicePointManager]::ServerCertificateValidationCallback=[AuditTls]::Accept
        }
        foreach ($port in $Ports) {
            if (-not (Test-Tcp $port)) { continue }
            $any=$true; $scheme='http'; if ($TlsPorts -contains $port) { $scheme='https' }
            $version='-'; $apps='-'; $detail='TCP aberto; HTTP/TLS por confirmar'; $response=$null; $stream=$null
            try {
                $request=[Net.HttpWebRequest]::Create("${scheme}://${IP}:$port/")
                $request.Proxy=$null; $request.AllowAutoRedirect=$false; $request.KeepAlive=$false
                $request.Timeout=$TimeoutSeconds*3000; $request.ReadWriteTimeout=$TimeoutSeconds*1000
                $request.MaximumResponseHeadersLength=32
                $request.UserAgent='PHP-Audit/1.0 (authorized inventory)'
                try { $response=$request.GetResponse() }
                catch [Net.WebException] { if ($_.Exception.Response) { $response=$_.Exception.Response } else { throw } }
                $server=[string]$response.Headers['Server']; $powered=[string]$response.Headers['X-Powered-By']
                $banner="$server $powered"
                if ($banner -match 'PHP/([0-9]+\.[0-9]+\.[0-9]+[^ ;,\r\n]*)') { $version=$Matches[1] }
                $stream=$response.GetResponseStream(); $buffer=New-Object byte[] 65536; $offset=0
                $watch=[Diagnostics.Stopwatch]::StartNew()
                while ($offset -lt $buffer.Length -and $watch.Elapsed.TotalSeconds -lt $TimeoutSeconds*3) {
                    $read=$stream.Read($buffer,$offset,$buffer.Length-$offset)
                    if ($read -le 0) { break }; $offset+=$read
                }
                $body=[Text.Encoding]::UTF8.GetString($buffer,0,$offset)
                # Cookie names aid detection; values never enter report/log.
                $cookies=[string]$response.Headers['Set-Cookie']
                $cookieNames=@([regex]::Matches($cookies,'(?:^|[,;]\s*)([A-Za-z0-9_]+)=') | ForEach-Object { $_.Groups[1].Value }) -join ' '
                $fingerprint="$body $server $powered $cookieNames"
                $patterns=[ordered]@{
                    WordPress='wp-content/|wp-includes/|generator[^>]*WordPress';Nextcloud='nextcloud|nc_sameSiteCookies';
                    Joomla='joomla|/media/system/';Drupal='drupal|data-drupal|/sites/default/';Laravel='laravel|laravel_session';
                    Magento='magento|/static/version[0-9]+/|mage/cookies';MediaWiki='mediawiki|mw-config|wgCanonicalNamespace';
                    phpBB='phpbb';WHMCS='whmcs|/templates/six/|/templates/twenty-one/'
                }
                $found=@(foreach ($name in $patterns.Keys) { if ($fingerprint -match $patterns[$name]) { "$name (indicio)" } })
                if ($found.Count) { $apps=$found -join '; ' }
                $detail="TCP aberto; HTTP=$([int]$response.StatusCode); Server=$server; X-Powered-By=$powered; GET / limitado a 64 KiB; sem redirects"
            } catch { $version='-'; $apps='-'; $detail='TCP aberto; HTTP/TLS com erro, timeout ou corpo incompleto; sem versao fiavel' }
            finally { if ($stream) { $stream.Dispose() }; if ($response) { $response.Close() }; if ($request) { $request.Abort() } }
            if ($InsecureTls) { $detail+='; certificado TLS nao validado' }
            $rows.Add((Row "$($scheme.ToUpper()):$port" "web:$port" $apps $version '-' SIM $detail))
        }
        if ($Credential -or $RemoteCurrentUser) {
            $remoteJob=$null; $remoteOS='-'; $remoteHost='-'; $complete=$false
            try {
                $parameters=@{
                    ComputerName=$IP;Port=$WinRMPort;UseSSL=[bool]$UseSSL;AsJob=$true;ErrorAction='Stop';
                    SessionOption=(New-PSSessionOption -OpenTimeout ($TimeoutSeconds*1000) -OperationTimeout ($RemoteTimeoutSeconds*1000));
                    ScriptBlock=[scriptblock]::Create($CollectorText)
                }
                if ($Credential) { $parameters.Credential=$Credential }
                $remoteJob=Invoke-Command @parameters
                $null=Wait-Job $remoteJob -Timeout $RemoteTimeoutSeconds
                $remoteRows=@(Receive-Job $remoteJob -ErrorAction SilentlyContinue)
                $complete=$remoteJob.State -eq 'Completed' -and @($remoteRows | Where-Object { $_.Service -eq 'META' -and $_.Runtime -eq 'COMPLETE' }).Count -gt 0
                foreach ($r in $remoteRows) {
                    if ($r.Service -eq 'META') {
                        if ($r.Runtime -eq 'OS') { $remoteOS=$r.Evidence; $any=$true }
                        if ($r.Runtime -eq 'HOST') { $remoteHost=$r.Evidence }
                        continue
                    }
                    $rows.Add((Row $r.Service $r.Runtime '-' $r.PHPVersion $r.Package NA $r.Evidence))
                }
            } catch { $complete=$false }
            finally { if ($remoteJob) { Stop-Job $remoteJob -ErrorAction SilentlyContinue; Remove-Job $remoteJob -Force -ErrorAction SilentlyContinue } }
            $state='DESCONHECIDO'; if ($complete) { $state='SIM' }
            $rows.Add((Row WinRM inventory '-' '-' '-' $state "Recolha concluida=$complete; falha ou permissoes insuficientes implicam cobertura parcial"))
            foreach ($r in $rows) { $r.Hostname=$remoteHost; $r.OS=$remoteOS }
        }
        if (-not $any) { $rows.Add((Row DISCOVERY host '-' '-' '-' DESCONHECIDO 'Sem resposta nas portas testadas; host desligado/filtrado ou servicos noutras portas; PHP nao excluido')) }
        $rows.ToArray()
    } finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback=$oldCallback
        [Net.ServicePointManager]::SecurityProtocol=$oldProtocol
    }
}

if (-not $SelfTest -and -not $Simulate) {
    $scope=@($Targets)
    if ($TargetsFile) { $scope+=@(Get-Content -LiteralPath $TargetsFile -Encoding UTF8) }
    $ips=@(Expand-Scope $scope $MaxHosts)
    if (-not $ips.Count) { throw 'Indique Targets ou TargetsFile (ou SelfTest).' }
    Write-Host "$(T scanning): $($ips.Count) IPs..."
    $pending=New-Object 'System.Collections.Generic.Queue[string]'
    foreach ($ip in $ips) { $pending.Enqueue($ip) }
    $jobs=@{}; $collected=New-Object 'System.Collections.Generic.List[object]'
    try {
        while ($pending.Count -or $jobs.Count) {
            while ($pending.Count -and $jobs.Count -lt $Concurrency) {
                $ip=$pending.Dequeue()
                $job=Start-Job -ScriptBlock $worker -ArgumentList $ip,$Ports,$TlsPorts,$TimeoutSeconds,$RemoteTimeoutSeconds,$Credential,([bool]$RemoteCurrentUser),([bool]$UseSSL),$WinRMPort,([bool]$InsecureTls),$remoteCollector.ToString()
                $jobs[$job.Id]=@{Job=$job;IP=$ip;Started=[DateTime]::UtcNow}
            }
            $null=Wait-Job -Job @($jobs.Values | ForEach-Object { $_.Job }) -Any -Timeout 1
            foreach ($id in @($jobs.Keys)) {
                $entry=$jobs[$id]; $job=$entry.Job
                $expired=([DateTime]::UtcNow-$entry.Started).TotalSeconds -gt ($Ports.Count*$TimeoutSeconds*6+$RemoteTimeoutSeconds+60)
                if ($job.State -in @('Completed','Failed','Stopped') -or $expired) {
                    if ($expired) { Stop-Job $job -ErrorAction SilentlyContinue }
                    $items=@(Receive-Job $job -ErrorAction SilentlyContinue)
                    foreach ($item in $items) { if ($item.IP -and $item.Service) { $collected.Add($item) } }
                    if (-not $items.Count -or $job.State -ne 'Completed') {
                        $collected.Add((New-Observation $entry.IP '-' '-' DISCOVERY host '-' '-' '-' DESCONHECIDO 'Worker falhou ou excedeu tempo; recolha incompleta'))
                    }
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                    $jobs.Remove($id)
                }
            }
        }
    } finally {
        foreach ($entry in $jobs.Values) { Stop-Job $entry.Job -ErrorAction SilentlyContinue; Remove-Job $entry.Job -Force -ErrorAction SilentlyContinue }
    }
    $observations=@($collected.ToArray() | Sort-Object IP,Service,Runtime)
}

$results=@(foreach ($o in $observations) {
    $verified=$false; $a='UNKNOWN'; $b='UNKNOWN'; $version=$o.PHPVersion; $package=$o.Package; $detail=$o.Evidence
    $key="$($o.IP)|$($o.Service)|$($o.Runtime)"
    if ($evidenceMap.ContainsKey($key)) {
        $e=$evidenceMap[$key]
        if ($e.ReviewedAt -ceq $Today -and $e.RuntimeVerified -ceq 'TRUE' -and $e.ReviewedBy -ne '-' -and
            $e.Advisory -cmatch '^https://[^\s@]+$' -and $e.PHPVersion -cmatch '^\d+\.\d+\.\d+$' -and
            ($version -eq '-' -or $version -ceq $e.PHPVersion) -and ($package -eq '-' -or $package -ceq $e.Package) -and
            $o.Service -notin @('CLI','PACKAGE','DISCOVERY','WinRM','SSH')) {
            $state=Get-VersionState $e.PHPVersion
            if ($e.CVE109618 -ne 'FIXED' -or $e.CVE109619 -ne 'FIXED' -or $state -eq 'FIXED_VERSION' -or $e.Package -ne '-') {
                $verified=$true; $a=$e.CVE109618; $b=$e.CVE109619; $version=$e.PHPVersion; $package=$e.Package
                $detail+="; Confirmacao revista: $($e.ReviewedBy), $($e.ReviewedAt); CVE109618=$a; CVE109619=$b; $($e.Advisory)"
            } else { $detail+='; Confirmacao rejeitada: backport exige pacote/build exato' }
        } else { $detail+='; Confirmacao ignorada: desatualizada, divergente ou incompleta' }
    }
    $status=Get-Classification $version $o.Service $verified $a $b
    $exposure='DESCONHECIDA'; if ($publicMap.ContainsKey($o.IP)) { $exposure='SIM (declarada)' }
    $risk='POR DETERMINAR'
    switch ($status) {
        VULNERAVEL { $risk='ALTO'; if ($exposure -ne 'DESCONHECIDA') { $risk='CRITICO' } }
        'POTENCIALMENTE VULNERAVEL' { $risk='ALTO' }
        CORRIGIDO { $risk='BAIXO (estas CVEs, este runtime)' }
    }
    if ($status -eq 'CORRIGIDO') {
        $recommendation='Manter evidencias da correcao e dos workers carregados; validar restantes sites, pools, backends e conteineres. Nao e certificacao do host.'
    } else {
        $recommendation='Confirmar todos os runtimes web e backports do fornecedor para ambas as CVEs. Atualizar para 8.2.35/8.3.36/8.4.27/8.5.12 ou posterior da mesma serie; <=8.1 requer suporte LTS/backport ou migracao. Priorizar exposicao publica; acordar restricao temporaria de acesso. WAF nao comprova correcao.'
    }
    [pscustomobject][ordered]@{
        IP=$o.IP;Hostname=$o.Hostname;OS=$o.OS;Service=$o.Service;Runtime=$o.Runtime;Application=$o.Application;
        PHPVersion=$version;Package=$package;CVEs=$Cves;Status=$status;Risk=$risk;Reachable=$o.Reachable;PublicExposure=$exposure;
        Evidence="$detail; estados CVE individuais: $a/$b; versao CLI/banner/pacote nao comprova runtime web corrigido";Recommendation=$recommendation
    }
})
if (-not $results.Count) { throw 'No results / Sem resultados.' }
function Encode-Html($Value) { [Net.WebUtility]::HtmlEncode([string]$Value) }
$exportRows=New-Object 'System.Collections.Generic.List[object]'
$htmlRows=New-Object 'System.Collections.Generic.List[string]'
foreach ($row in $results) {
    $original=$row.Status; $css='unknown'; $status=T inconclusive; $action=T unknownAction; $risk=T undetermined
    switch ($original) {
        VULNERAVEL { $status=T vulnerable; $action=T vulnAction; $risk=T high; $css='bad'; if ($row.PublicExposure -ne 'DESCONHECIDA') { $risk=T critical } }
        CORRIGIDO { $status=T fixed; $action=T fixAction; $risk=T low; $css='good' }
        'POTENCIALMENTE VULNERAVEL' { $status=T potential; $action=T oldAction; $risk=T high; $css='warn' }
    }
    $reachable=T unknownValue
    switch ($row.Reachable) { SIM {$reachable=T yes}; NA {$reachable=T na}; SIMULADO {$reachable='SIMULATED'} }
    $exposure=T unknownValue; if ($row.PublicExposure -ne 'DESCONHECIDA') { $exposure=T declared }
    $application=$row.Application.Replace('(indicio)',('('+ (T hint)+')'))
    $detail=Translate-Detail (Convert-SafeCell $row.Evidence)
    $export=[ordered]@{}
    $fields=@('IP','host','os','service','runtime','app','php','package','cves','status','risk','reachable','public','evidence','recommendation')
    $values=@($row.IP,$row.Hostname,$row.OS,$row.Service,$row.Runtime,$application,$row.PHPVersion,$row.Package,$row.CVEs,$status,$risk,$reachable,$exposure,$detail,$action)
    for($i=0;$i -lt $fields.Count;$i++) { $label=$fields[$i]; if($i -ne 0) { $label=T $label }; $export[$label]=Convert-CsvSafe $values[$i] }
    $exportRows.Add([pscustomobject]$export)
    $technical="$(T os): $($row.OS) | $(T runtime): $($row.Runtime) | $(T package): $($row.Package) | $(T reachable): $reachable | $(T public): $exposure | $(T risk): $risk"
    $name='';if ($row.Hostname -ne '-') { $name='<br>'+(Encode-Html $row.Hostname) }
    $htmlRows.Add('<tr class="'+$css+'"><td><strong>'+(Encode-Html $row.IP)+'</strong>'+$name+'<details><summary>'+(T details)+'</summary><p>'+(Encode-Html $technical)+'</p><p>'+(Encode-Html $detail)+'</p></details></td><td>'+(Encode-Html $row.Service)+'</td><td>'+(Encode-Html $application)+'</td><td>'+(Encode-Html $row.PHPVersion)+'</td><td>'+(Encode-Html $status)+'</td><td>'+(Encode-Html $action)+'</td></tr>')
}
$null=New-Item -ItemType Directory -Path $OutDir -Force
$runPath=Join-Path (Resolve-Path -LiteralPath $OutDir).Path ('php-audit-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $runPath
$csvPath=Join-Path $runPath 'report.csv'; $htmlPath=Join-Path $runPath 'report.html'
$exportRows.ToArray() | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
$heads=@(foreach ($key in @('host','service','app','php','status','action')) { '<th>'+(T $key)+'</th>' }) -join ''
$uniqueIPs=@($results.IP | Sort-Object -Unique).Count
$attention=@($results | Where-Object { $_.Status -in @('VULNERAVEL','POTENCIALMENTE VULNERAVEL') }).Count
$unknown=@($results | Where-Object Status -eq INCONCLUSIVO).Count
$simulationNote=''; if ($SelfTest -or $Simulate) { $simulationNote='<p><strong>'+(T simulated)+'</strong></p>' }
$scopeLabel=$Targets -join ', '; if ($TargetsFile) { $scopeLabel+='; '+$TargetsFile }
$html=@"
<!doctype html><html lang="$Language"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>$(T title)</title>
<style>body{font:15px system-ui,sans-serif;color:#183047;background:#f3f6fa;margin:0;padding:24px}main{max-width:1200px;margin:auto}h1{margin-bottom:6px}p{line-height:1.5}.muted,summary{color:#52677c}.stats{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}.stats div{padding:16px;background:white;border:1px solid #d6e0e9;border-radius:8px}.stats strong{font-size:24px;display:block}.table{overflow:auto;background:white;border-radius:8px}table{width:100%;border-collapse:collapse}th,td{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid #dde5ee}th{background:#143a5e;color:white}td{overflow-wrap:anywhere}details{font-size:12px;max-width:320px;margin-top:8px}summary{cursor:pointer}.warn td:first-child{border-left:5px solid #d98b13}.bad td:first-child{border-left:5px solid #c42e34}.good td:first-child{border-left:5px solid #228157}.unknown td:first-child{border-left:5px solid #8a99a6}footer{font-size:13px;margin-top:20px}@media print{body{padding:0}.table{overflow:visible}table{font-size:11px}}</style>
<main><h1>$(T title)</h1><p class="muted">$Cves · $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC</p>$simulationNote<p><strong>$(T scope):</strong> $(Encode-Html $scopeLabel)</p>
<div class="stats"><div><strong>$uniqueIPs</strong>$(T hosts)</div><div><strong>$($results.Count)</strong>$(T results)</div><div><strong>$attention</strong>$(T attention)</div><div><strong>$unknown</strong>$(T unknown)</div></div>
<p>$(T next)</p><p>$(T explain)</p><div class="table"><table><thead><tr>$heads</tr></thead><tbody>$($htmlRows -join "`n")</tbody></table></div>
<footer><p>$(T versions)</p><p><strong>$(T limits):</strong> $(T limitText)</p><a href="https://www.php.net/archive/2026.php">$(T source)</a> · 2026-10-22</footer></main></html>
"@
[IO.File]::WriteAllText($htmlPath,$html,(New-Object Text.UTF8Encoding($false)))
Write-Host "$(T done):`n$htmlPath`n$csvPath"
