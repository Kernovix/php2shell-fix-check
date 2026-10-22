#!/usr/bin/env bash
# PHP2Shell Fix Check. Bash >=3.2; read-only inventory and remediation guidance.
# Author / Autor: Kernovix
# Rules reviewed against php.net on 2026-10-22. See README.md.
set -u
set -o pipefail
umask 077
export LC_ALL=C
CVES='CVE-2026-109618; CVE-2026-109619'
PORTS=80,443,8080,8443 TLS_PORTS=443,8443 CONCURRENCY=8 TIMEOUT=3 REMOTE_TIMEOUT=45 MAX_HOSTS=4096
TARGETS='' TARGET_FILE='' PUBLIC_TARGETS='' SSH_USER='' SSH_KEY='' SSH_PORT=22
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LANGUAGE='' OUT="$SCRIPT_DIR/reports" EVIDENCE_FILE='' SIMULATE='' SELF_TEST=0 INSECURE=0
WORK='' RUN='' TODAY=$(date -u +%F)
die() { printf 'ERRO: %s\n' "$*" >&2; exit 2; }
usage() {
cat <<'HELP'
PHP2Shell Fix Check | CVE-2026-109618 / CVE-2026-109619
bash php_audit.sh                         # asks for targets and report language
bash php_audit.sh '192.168.1.0/24' pt      # Portuguese report
bash php_audit.sh '192.168.1.10-30' en     # English report
Optional: --ports 80,443,8080,8443 --tls-ports 443,8443 --concurrency 8
          --ssh-user auditor --ssh-key FILE --out DIR --self-test
Use only authorized targets / Usar apenas alvos autorizados.
HELP
}
need_arg() { [ "$#" -ge 2 ] || die "Falta valor para $1"; }
while [ "$#" -gt 0 ]; do
 case "$1" in
 --help|-h) usage; exit 0;;
 --self-test) SELF_TEST=1; shift; continue;;
 --insecure-tls) INSECURE=1; shift; continue;;
 --language|--lang|--targets|--targets-file|--ports|--tls-ports|--concurrency|--timeout|--remote-timeout|--max-hosts|--ssh-user|--ssh-key|--ssh-port|--public-targets|--evidence|--out|--simulate) need_arg "$@";;
 pt|en) LANGUAGE=$1; shift; continue;;
 -*) die "Unknown option / Opcao desconhecida: $1";;
 *) TARGETS="${TARGETS}${TARGETS:+,}$1"; shift; continue;;
 esac
 case "$1" in
 --language|--lang) LANGUAGE=$2;; --targets) TARGETS=$2;; --targets-file) TARGET_FILE=$2;; --ports) PORTS=$2;; --tls-ports) TLS_PORTS=$2;;
 --concurrency) CONCURRENCY=$2;; --timeout) TIMEOUT=$2;; --remote-timeout) REMOTE_TIMEOUT=$2;; --max-hosts) MAX_HOSTS=$2;;
 --ssh-user) SSH_USER=$2;; --ssh-key) SSH_KEY=$2;; --ssh-port) SSH_PORT=$2;; --public-targets) PUBLIC_TARGETS=$2;;
 --evidence) EVIDENCE_FILE=$2;; --out) OUT=$2;; --simulate) SIMULATE=$2;;
 esac
 shift 2
done
if [ -z "$TARGETS$TARGET_FILE$SIMULATE" ] && [ "$SELF_TEST" -eq 0 ] && [ -t 0 ]; then
 read -r -p 'IPs / Rede / Network (ex.: 192.168.1.0/24): ' TARGETS || die 'Sem escopo indicado'
fi
if [ -z "$LANGUAGE" ] && [ "$SELF_TEST" -eq 0 ] && [ -z "$SIMULATE" ] && [ -t 0 ]; then
 read -r -p 'Idioma do relatório / Report language [pt/en] (pt): ' LANGUAGE || exit 2
fi
LANGUAGE=${LANGUAGE:-pt}
case "$LANGUAGE" in pt|en) :;; *) die 'Idioma / Language: pt ou/or en';; esac
t() {
 case "$LANGUAGE:$1" in
 pt:title) printf '%s' 'PHP2Shell Fix Check — Auditoria PHP';;
 en:title) printf '%s' 'PHP2Shell Fix Check — PHP Audit';;
 pt:date) printf '%s' 'Data UTC';;
 en:date) printf '%s' 'UTC date';;
 pt:scope) printf '%s' 'Alvos';;
 en:scope) printf '%s' 'Targets';;
 pt:hosts) printf '%s' 'IPs analisados';;
 en:hosts) printf '%s' 'IPs checked';;
 pt:results) printf '%s' 'Resultados';;
 en:results) printf '%s' 'Results';;
 pt:attention) printf '%s' 'Precisam de atenção';;
 en:attention) printf '%s' 'Need attention';;
 pt:unknown) printf '%s' 'Inconclusivos';;
 en:unknown) printf '%s' 'Inconclusive';;
 pt:host) printf '%s' 'IP / Nome';;
 en:host) printf '%s' 'IP / Hostname';;
 pt:service) printf '%s' 'Serviço';;
 en:service) printf '%s' 'Service';;
 pt:app) printf '%s' 'Aplicação';;
 en:app) printf '%s' 'Application';;
 pt:php) printf '%s' 'PHP';;
 en:php) printf '%s' 'PHP';;
 pt:status) printf '%s' 'Estado';;
 en:status) printf '%s' 'Status';;
 pt:action) printf '%s' 'O que fazer';;
 en:action) printf '%s' 'What to do';;
 pt:details) printf '%s' 'Ver detalhes';;
 en:details) printf '%s' 'View details';;
 pt:os) printf '%s' 'Sistema operativo';;
 en:os) printf '%s' 'Operating system';;
 pt:runtime) printf '%s' 'Runtime';;
 en:runtime) printf '%s' 'Runtime';;
 pt:package) printf '%s' 'Pacote';;
 en:package) printf '%s' 'Package';;
 pt:cves) printf '%s' 'CVEs';;
 en:cves) printf '%s' 'CVEs';;
 pt:risk) printf '%s' 'Risco';;
 en:risk) printf '%s' 'Risk';;
 pt:reachable) printf '%s' 'Acessível pela rede';;
 en:reachable) printf '%s' 'Network reachable';;
 pt:public) printf '%s' 'Exposição pública';;
 en:public) printf '%s' 'Public exposure';;
 pt:evidence) printf '%s' 'Evidências';;
 en:evidence) printf '%s' 'Evidence';;
 pt:recommendation) printf '%s' 'Recomendação';;
 en:recommendation) printf '%s' 'Recommendation';;
 pt:vulnerable) printf '%s' 'VULNERÁVEL';;
 en:vulnerable) printf '%s' 'VULNERABLE';;
 pt:fixed) printf '%s' 'CORRIGIDO';;
 en:fixed) printf '%s' 'FIXED';;
 pt:potential) printf '%s' 'POTENCIALMENTE VULNERÁVEL';;
 en:potential) printf '%s' 'POTENTIALLY VULNERABLE';;
 pt:inconclusive) printf '%s' 'INCONCLUSIVO';;
 en:inconclusive) printf '%s' 'INCONCLUSIVE';;
 pt:high) printf '%s' 'ALTO';;
 en:high) printf '%s' 'HIGH';;
 pt:critical) printf '%s' 'CRÍTICO';;
 en:critical) printf '%s' 'CRITICAL';;
 pt:low) printf '%s' 'BAIXO (estas CVEs)';;
 en:low) printf '%s' 'LOW (these CVEs)';;
 pt:undetermined) printf '%s' 'POR DETERMINAR';;
 en:undetermined) printf '%s' 'UNDETERMINED';;
 pt:yes) printf '%s' 'SIM';;
 en:yes) printf '%s' 'YES';;
 pt:na) printf '%s' 'Não associado a uma porta web';;
 en:na) printf '%s' 'Not linked to a web port';;
 pt:unknownValue) printf '%s' 'Desconhecido';;
 en:unknownValue) printf '%s' 'Unknown';;
 pt:declared) printf '%s' 'SIM (informado pelo técnico)';;
 en:declared) printf '%s' 'YES (reported by technician)';;
 pt:hint) printf '%s' 'indício';;
 en:hint) printf '%s' 'hint';;
 pt:simulated) printf '%s' 'SIMULAÇÃO — dados fictícios, sem auditoria de uma rede real.';;
 en:simulated) printf '%s' 'SIMULATION — fictional data, no real network audit.';;
 pt:explain) printf '%s' 'Uma versão antiga pode ter correções do fornecedor. Sem prova suficiente, o resultado é INCONCLUSIVO. Uma linha corrigida não certifica todo o servidor.';;
 en:explain) printf '%s' 'An older version may contain vendor fixes. Without sufficient evidence, the result is INCONCLUSIVE. A fixed row does not certify the entire server.';;
 pt:next) printf '%s' 'Priorize os resultados que precisam de atenção. Confirme o runtime web e as correções do fornecedor antes de atualizar.';;
 en:next) printf '%s' 'Prioritize results that need attention. Confirm the web runtime and vendor fixes before updating.';;
 pt:fixAction) printf '%s' 'Guardar a confirmação e verificar os restantes sites e runtimes.';;
 en:fixAction) printf '%s' 'Keep the confirmation and check other sites and runtimes.';;
 pt:unknownAction) printf '%s' 'Confirmar o PHP usado pelo site e verificar as duas CVEs com o fornecedor.';;
 en:unknownAction) printf '%s' 'Confirm the PHP runtime used by the site and check both CVEs with the vendor.';;
 pt:oldAction) printf '%s' 'Verificar possíveis backports e atualizar o runtime web se necessário.';;
 en:oldAction) printf '%s' 'Check for vendor backports and update the web runtime if needed.';;
 pt:vulnAction) printf '%s' 'Atualizar o runtime afetado e acordar restrição temporária de acesso.';;
 en:vulnAction) printf '%s' 'Update the affected runtime and agree on temporary access restrictions.';;
 pt:limits) printf '%s' 'Limites';;
 en:limits) printf '%s' 'Limitations';;
 pt:limitText) printf '%s' 'Só os IPs e portas indicados são verificados. Sites por nome/SNI, proxies e instalações ocultas podem não ser identificados. Exposição pública é informada pelo técnico, não testada da Internet. Não há exploits nem alterações nos servidores.';;
 en:limitText) printf '%s' 'Only the specified IPs and ports are checked. Name-based/SNI sites, proxies and hidden installations may be missed. Public exposure is technician-reported, not tested from the Internet. No exploits or server changes are performed.';;
 pt:versions) printf '%s' 'Referência: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. PHP ≤8.1: confirmar suporte e backports. CLI e banners não provam que o site está corrigido.';;
 en:versions) printf '%s' 'Reference: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. PHP ≤8.1: check support and backports. CLI versions and banners do not prove a website is fixed.';;
 pt:source) printf '%s' 'Aviso oficial do PHP';;
 en:source) printf '%s' 'Official PHP advisory';;
 pt:done) printf '%s' 'Relatórios guardados em';;
 en:done) printf '%s' 'Reports saved to';;
 pt:scanning) printf '%s' 'A verificar';;
 en:scanning) printf '%s' 'Checking';;
 pt:tests) printf '%s' 'Testes internos aprovados';;
 en:tests) printf '%s' 'Internal tests passed';;
 *) printf '%s' "$1";;
 esac
}

integer() { case "$1" in ''|*[!0-9]*|0[0-9]*) return 1;; esac; [ "${#1}" -le 6 ] && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]; }
integer "$CONCURRENCY" 1 64 || die 'Concorrencia: 1..64'
integer "$TIMEOUT" 1 60 || die 'Timeout: 1..60'
integer "$REMOTE_TIMEOUT" 5 600 || die 'Remote timeout: 5..600'
integer "$MAX_HOSTS" 1 65536 || die 'Max hosts: 1..65536'
integer "$SSH_PORT" 1 65535 || die 'Porta SSH invalida'
for plist in "$PORTS" "$TLS_PORTS"; do
 [[ "$plist" =~ ^[0-9]+(,[0-9]+)*$ ]] || die 'Lista de portas invalida'
 for p in ${plist//,/ }; do integer "$p" 1 65535 || die 'Porta invalida'; done
done
[ "$(printf '%s' "$PORTS" | tr , '\n' | wc -l)" -lt 64 ] || die 'Maximo 64 portas'
if [ -n "$SSH_USER" ]; then
 [[ "$SSH_USER" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]] || die 'Utilizador SSH invalido'
 [ -z "$SSH_KEY" ] || [ -f "$SSH_KEY" ] || die 'Chave SSH inexistente'
fi
for c in awk sed sort head tr date mktemp; do command -v "$c" >/dev/null || die "Requisito em falta: $c"; done
WORK=$(mktemp -d) || die 'Nao foi possivel criar temporarios'
cleanup() {
 local p
 for p in $(jobs -pr); do kill "$p" 2>/dev/null || :; done
 [ -z "$WORK" ] || rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
TAB=$(printf '\t')
# Expand explicit IPv4 scope only. No DNS/URLs, no redirects or implicit LAN scan.
expand_scope() {
 awk -v limit="$MAX_HOSTS" '
 function fail(s){print "Invalid scope / Alvos invalidos: " s > "/dev/stderr";bad=1;exit 2}
 function ipnum(s,parts,n,j,v){n=split(s,parts,".");if(n!=4)fail(s);v=0;for(j=1;j<=4;j++){if(parts[j]!~/^[0-9]+$/||length(parts[j])>3||parts[j]+0>255)fail(s);v=v*256+parts[j]}return v}
 function add(v){if(!seen[v]++){if(++count>limit)fail("too many IPs / demasiados IPs");printf "%d.%d.%d.%d\n",int(v/16777216),int(v/65536)%256,int(v/256)%256,v%256}}
 {sub(/^\357\273\277/, "");sub(/\r$/, "");sub(/#.*/, "");gsub(/,/, " ");for(t=1;t<=NF;t++){
  token=$t
  if(index(token,"-")){
   if(split(token,r,"-")!=2)fail(token);lo=ipnum(r[1]);end=r[2]
   if(end~/^[0-9]+$/){if(length(end)>3||end+0>255)fail(token);hi=int(lo/256)*256+end}else hi=ipnum(end)
   if(hi<lo||hi-lo+1>limit)fail(token);for(x=lo;x<=hi;x++)add(x)
  }else{
   n=split(token,a,"/");if(n>2)fail(token);v=ipnum(a[1]);b=32
   if(n==2){if(a[2]!~/^[0-9]+$/||length(a[2])>2||a[2]+0>32)fail(token);b=a[2]+0}
   size=2^(32-b);if(size>limit)fail("CIDR exceeds / excede max-hosts");base=int(v/size)*size
   lo=base;hi=base+size-1;if(b<31){lo++;hi--}for(x=lo;x<=hi;x++)add(x)
  }
 }}END{if(bad)exit 2}'
}
# Strict, plain TSV protocol: ten columns, '-' means unknown. No raw HTTP/config logs.
clean() {
 local v=${1:0:3000}
 while [[ "$v" =~ [[:cntrl:]] ]]; do v=${v//"${BASH_REMATCH[0]}"/ }; done
 printf '%s' "$v"
}
emit() {
 local sep='' v
 for v in "$@"; do printf '%s%s' "$sep" "$(clean "${v:--}")"; sep="$TAB"; done
 printf '\n'
}
version_state() {
 # Strict release triplet. RC/dev/unknown branches must never become fixed.
 local v=$1 major minor patch floor
 [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { printf UNKNOWN; return; }
 major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}
 [ "${#major}" -le 2 ] && [ "${#minor}" -le 2 ] && [ "${#patch}" -le 4 ] || { printf UNKNOWN; return; }
 major=$((10#$major)); minor=$((10#$minor)); patch=$((10#$patch))
 if [ "$major" -lt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -le 1 ]; }; then printf LEGACY; return; fi
 case "$major.$minor" in 8.2) floor=35;;8.3) floor=36;;8.4) floor=27;;8.5) floor=12;;*) printf UNKNOWN;return;;esac
 if [ "$patch" -ge "$floor" ]; then printf FIXED_VERSION; else printf BELOW; fi
}
classify() {
 local version=$1 service=$2 verified=$3 a=$4 b=$5 state
 if [ "$verified" = TRUE ]; then
  if [ "$a" = AFFECTED ] || [ "$b" = AFFECTED ]; then printf VULNERAVEL; return; fi
  if [ "$a" = FIXED ] && [ "$b" = FIXED ]; then printf CORRIGIDO; return; fi
 fi
 state=$(version_state "$version")
 if [ "$service" != CLI ] && { [ "$state" = BELOW ] || [ "$state" = LEGACY ]; }; then printf 'POTENCIALMENTE VULNERAVEL'; else printf INCONCLUSIVO; fi
}
self_tests() {
 local v expected got count=0
 while read -r v expected; do
  got=$(version_state "$v"); [ "$got" = "$expected" ] || die "Teste versao $v: $got != $expected"; count=$((count+1))
 done <<'CASES'
8.2.34 BELOW
8.2.35 FIXED_VERSION
8.2.36 FIXED_VERSION
8.3.35 BELOW
8.3.36 FIXED_VERSION
8.4.26 BELOW
8.4.27 FIXED_VERSION
8.5.11 BELOW
8.5.12 FIXED_VERSION
8.1.34 LEGACY
7.4.33 LEGACY
8.6.0 UNKNOWN
8.5.12RC1 UNKNOWN
- UNKNOWN
CASES
 [ "$(classify 8.5.12 CLI FALSE UNKNOWN UNKNOWN)" = INCONCLUSIVO ] || die 'CLI fix'
 [ "$(classify 8.5.11 CLI FALSE UNKNOWN UNKNOWN)" = INCONCLUSIVO ] || die 'CLI old'
 [ "$(classify 8.5.12 HTTPS FALSE UNKNOWN UNKNOWN)" = INCONCLUSIVO ] || die 'Banner fix'
 [ "$(classify 8.3.6 PHP-FPM TRUE FIXED FIXED)" = CORRIGIDO ] || die 'Backport'
 [ "$(classify 8.3.6 PHP-FPM FALSE FIXED FIXED)" = 'POTENCIALMENTE VULNERAVEL' ] || die 'Unverified backport'
 [ "$(classify 8.3.6 PHP-FPM TRUE AFFECTED FIXED)" = VULNERAVEL ] || die 'One CVE affected'
 [ "$(classify - HTTPS FALSE UNKNOWN UNKNOWN)" = INCONCLUSIVO ] || die 'No version'
 printf 'OK: %s testes de versao + 7 de classificacao.\n' "$count"
 # Real pipeline with simulated observations and current, explicit attestations.
 SIMULATE="$WORK/simulated.tsv"; EVIDENCE_FILE="$WORK/evidence.tsv"
 emit IP Hostname OS Service Runtime Application PHPVersion Package Reachable Evidence > "$SIMULATE"
 emit 192.0.2.10 wp.example Linux HTTP:80 web:80 WordPress 8.3.35 - SIMULADO 'SIMULADO: banner antigo' >> "$SIMULATE"
 emit 192.0.2.11 app.example Ubuntu HTTPS:443 web:443 Nextcloud 8.3.6 'php8.3-fpm=SIMULADO' SIMULADO 'SIMULADO: runtime validado pelo tecnico' >> "$SIMULATE"
 emit 192.0.2.12 cli.example Windows CLI cli:php - 8.5.12 - SIMULADO 'SIMULADO: apenas CLI' >> "$SIMULATE"
 emit 192.0.2.13 old.example Linux PHP-FPM process:123 - 8.4.26 - SIMULADO 'SIMULADO: sem backport; runtime confirmado' >> "$SIMULATE"
 emit 192.0.2.14 hidden.example - HTTPS:443 web:443 Joomla - - SIMULADO 'SIMULADO: sem versao' >> "$SIMULATE"
 emit 192.0.2.15 offline.example - DISCOVERY host - - - SIMULADO 'SIMULADO: portas filtradas' >> "$SIMULATE"
 emit 192.0.2.16 new.example Linux HTTPS:443 web:443 - 8.5.12 - SIMULADO 'SIMULADO: banner corrigido nao comprova runtime' >> "$SIMULATE"
 emit IP Service Runtime PHPVersion Package CVE109618 CVE109619 RuntimeVerified ReviewedAt ReviewedBy Advisory > "$EVIDENCE_FILE"
 emit 192.0.2.11 HTTPS:443 web:443 8.3.6 'php8.3-fpm=SIMULADO' FIXED FIXED TRUE "$TODAY" 'Tecnico SIMULADO' 'https://example.invalid/advisory-SIMULADO' >> "$EVIDENCE_FILE"
 emit 192.0.2.13 PHP-FPM process:123 8.4.26 - AFFECTED AFFECTED TRUE "$TODAY" 'Tecnico SIMULADO' 'https://example.invalid/advisory-SIMULADO' >> "$EVIDENCE_FILE"
}
[ "$SELF_TEST" -eq 0 ] || self_tests
# Freeze and validate operator attestations before any network traffic. Accept CRLF/BOM.
normalize_tsv() { awk '{sub(/^\357\273\277/, "");sub(/\r$/, "");print}' "$1" > "$2"; }
if [ -n "$EVIDENCE_FILE" ]; then
 [ -r "$EVIDENCE_FILE" ] || die 'Evidencias ilegivel'
 normalize_tsv "$EVIDENCE_FILE" "$WORK/attestations.tsv" || die 'Erro a ler evidencias'
 EVIDENCE_FILE="$WORK/attestations.tsv"
 awk -F '\t' 'NR==1{if($0!="IP\tService\tRuntime\tPHPVersion\tPackage\tCVE109618\tCVE109619\tRuntimeVerified\tReviewedAt\tReviewedBy\tAdvisory")exit 2;next}
 NF!=11{exit 2} {for(i=1;i<=11;i++)if($i=="")exit 2;
 if($6!~/^(FIXED|AFFECTED|UNKNOWN)$/||$7!~/^(FIXED|AFFECTED|UNKNOWN)$/||$8!~/^(TRUE|FALSE)$/)exit 2;
 key=$1 SUBSEP $2 SUBSEP $3;if(seen[key]++)exit 2}' "$EVIDENCE_FILE" || die 'Evidencias TSV invalidas ou duplicadas'
fi
if [ -n "$SIMULATE" ]; then
 [ -r "$SIMULATE" ] || die 'Ficheiro de simulacao ilegivel'
 normalize_tsv "$SIMULATE" "$WORK/observations.tsv" || die 'Erro a ler simulacao'
else
 [ -n "$TARGETS$TARGET_FILE" ] || die 'Indique --targets ou --targets-file (ou --self-test)'
 for c in curl timeout bash; do command -v "$c" >/dev/null || die "Requisito em falta: $c"; done
 [ -z "$SSH_USER" ] || command -v ssh >/dev/null || die 'ssh em falta'
 { printf '%s\n' "$TARGETS"; if [ -n "$TARGET_FILE" ]; then cat -- "$TARGET_FILE" || exit 2; fi; } > "$WORK/scope.input" || die 'Escopo ilegivel'
 expand_scope < "$WORK/scope.input" > "$WORK/targets" || die 'Escopo recusado'
 [ -s "$WORK/targets" ] || die 'Escopo vazio'
fi
printf '%s\n' "$PUBLIC_TARGETS" | expand_scope > "$WORK/public" || die 'Exposicao invalida'
# Remote collector never reads application configs, env, command lines or secrets.
cat > "$WORK/collector.sh" <<'REMOTE'
#!/bin/sh
export LC_ALL=C
line() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" | tr '\r' ' '; }
os=$(uname -s 2>/dev/null)
if [ -r /etc/os-release ]; then
 pretty=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"' | head -c 160)
 os="$os $pretty"
fi
line META OS - - "$os"
line META HOST - - "$(hostname 2>/dev/null | head -c 200)"
# CLI is actual PHP_VERSION but NEVER used to certify a web runtime.
for bin in php php5 php7.4 php8.0 php8.1 php8.2 php8.3 php8.4 php8.5; do
 if command -v "$bin" >/dev/null 2>&1; then
  v=$("$bin" -n -r 'echo PHP_VERSION;' 2>/dev/null | head -c 100)
  line CLI "cli:$bin" "${v:--}" - 'PHP_VERSION via -n; sem ligacao ao servico web'
 fi
done
# Package inventories retain epochs/releases/architecture; no online changelog fetch.
if command -v dpkg-query >/dev/null 2>&1; then
 dpkg-query -W -f='${db:Status-Status}\t${binary:Package}\t${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null |
  awk -F '\t' '$1=="installed"{print $2"="$3}' | head -n 150 | while IFS= read -r pkg; do
   line PACKAGE "package:$pkg" - "$pkg" 'dpkg instalado; backport e runtime carregado por confirmar'
  done
elif command -v rpm >/dev/null 2>&1; then
 rpm -qa --qf '%{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null |
  grep -E '^(php|rh-php|ea-php)' | head -n 150 | while IFS= read -r pkg; do
   line PACKAGE "package:$pkg" - "$pkg" 'RPM instalado; fornecedor/stream e runtime carregado por confirmar'
  done
fi
# ps comm only, never args (could contain credentials). No process restarts.
ps -e -o pid= -o comm= 2>/dev/null | head -n 4096 | while read -r pid name rest; do
 case "$name" in
  *php*fpm*|php-cgi*|apache2|httpd|nginx|frankenphp|lsphp*|litespeed*)
   svc="$name"; case "$name" in *php*fpm*) svc=PHP-FPM;; esac
   exe=$(readlink "/proc/$pid/exe" 2>/dev/null | head -c 300)
   v=-; pkg=-
   case "$name" in
    *php*fpm*|php-cgi*|lsphp*)
     # Query the same executable inode through procfs, not an unrelated PATH CLI.
     # -n avoids php.ini/extensions; -v never starts a listening daemon.
     v=$("/proc/$pid/exe" -n -v 2>/dev/null | sed -nE '1s/^PHP ([^ ]+).*/\1/p' | head -c 100)
     [ -n "$v" ] || v=-;;
   esac
   # Installed ownership is evidence only: on-disk packages may differ from memory.
   case "$exe" in
    /*) case "$exe" in *' (deleted)') :;; *)
     if command -v dpkg-query >/dev/null 2>&1; then
      owner=$(dpkg-query -S "$exe" 2>/dev/null | head -n 1 | sed 's/: \/.*//')
      if [ -n "$owner" ]; then pkg=$(dpkg-query -W -f='${binary:Package}=${Version}' "$owner" 2>/dev/null); fi
     elif command -v rpm >/dev/null 2>&1; then
      pkg=$(rpm -qf --qf '%{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' "$exe" 2>/dev/null)
     fi;; esac;;
   esac
   line "$svc" "process:$pid" "$v" "${pkg:--}" "Processo ativo; executavel=${exe:--}; versao via procfs quando permitida; pacote em disco nao comprova workers atualizados"
   if [ -r "/proc/$pid/maps" ]; then
    awk '/\/.*libphp[^/ ]*\.so/{print $NF}' "/proc/$pid/maps" | sort -u | head -n 4 | while IFS= read -r mod; do
     line mod_php "module:$pid:$mod" - - 'Modulo PHP mapeado; disco/pacote nao comprova workers atualizados'
    done
   fi;;
 esac
done
# Docker metadata only: no inspect Env, no exec/pull/start. Tags are not versions.
if command -v docker >/dev/null 2>&1; then
 docker ps --format '{{.ID}}|{{.Image}}|{{.Ports}}' 2>/dev/null | head -n 100 | while IFS='|' read -r id image ports; do
  line Docker "docker:$id" - - "Imagem=$image; portas=$ports; PHP interno e digest carregado por confirmar"
 done
fi
line META COMPLETE - - 'Inventario limitado aos privilegios da conta; processos/pacotes/conteineres podem estar ocultos'
REMOTE
tcp_open() { timeout "$TIMEOUT" bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$1" "$2" >/dev/null 2>&1; }
fingerprint() {
 local f=$1 apps='' name pat
 while IFS='|' read -r name pat; do
  if grep -Eiq "$pat" "$f"; then apps="${apps}${apps:+; }$name (indicio)"; fi
 done <<'PATTERNS'
WordPress|wp-content/|wp-includes/|name=["\x27]generator[^>]*WordPress
Nextcloud|nextcloud|nc_sameSiteCookies
Joomla|joomla|/media/system/
Drupal|drupal|data-drupal|/sites/default/
Laravel|laravel|laravel_session
Magento|magento|/static/version[0-9]+/|mage/cookies
MediaWiki|mediawiki|mw-config|wgCanonicalNamespace
phpBB|phpbb|phpbb[0-9_]*=
WHMCS|whmcs|/templates/six/|/templates/twenty-one/
PATTERNS
 printf '%s' "${apps:--}"
}
scan_host() {
 local ip=$1 file="$WORK/$1.tsv" any=0 p scheme f rc ver app banner hostname='-' os='-' svc rid pkg detail typ remote_rc
 : > "$file"
 for p in ${PORTS//,/ }; do
  if tcp_open "$ip" "$p"; then
   any=1; scheme=http; case ",$TLS_PORTS," in *",$p,"*) scheme=https;; esac
   f="$WORK/$ip.$p.http"
   local tls=(); [ "$INSECURE" -eq 0 ] || tls=(-k)
   # No proxy, redirect, auth, cookies or extra probes. Bounded GET / only.
   curl -q --silent --include --noproxy '*' --proto '=http,https' --connect-timeout "$TIMEOUT" --max-time "$((TIMEOUT*3))" "${tls[@]}" \
    --user-agent 'PHP-Audit/1.0 (authorized inventory)' "$scheme://$ip:$p/" 2>/dev/null | head -c 65536 > "$f"
   rc=${PIPESTATUS[0]}
   app=$(fingerprint "$f")
   # PHP version only from response headers, never an arbitrary body string.
   banner=$(awk 'BEGIN{IGNORECASE=1} /^\r?$/{exit} {s=tolower($0);if(s~/^(server|x-powered-by):/)print}' "$f" | tr '\r\n' ' ' | head -c 500)
   ver=$(printf '%s' "$banner" | sed -nE 's/.*PHP\/([0-9]+\.[0-9]+\.[0-9]+[^ ;,\r]*).*/\1/p')
   detail="TCP aberto; HTTP curl=$rc; ${banner:-sem banner PHP}; GET / limitado a 64 KiB; sem redirects"
   [ "$INSECURE" -eq 0 ] || detail="$detail; certificado TLS nao validado"
   svc=$(printf '%s' "$scheme" | tr '[:lower:]' '[:upper:]')
   emit "$ip" - - "$svc:$p" "web:$p" "$app" "${ver:--}" - SIM "$detail" >> "$file"
   rm -f -- "$f"
  fi
 done
 if [ -n "$SSH_USER" ]; then
  local key=(); [ -z "$SSH_KEY" ] || key=(-i "$SSH_KEY")
  timeout "$REMOTE_TIMEOUT" ssh -F /dev/null -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ClearAllForwardings=yes \
   -o ForwardAgent=no -o ForwardX11=no -o PermitLocalCommand=no \
   -o ConnectTimeout="$TIMEOUT" -o ConnectionAttempts=1 -o ServerAliveInterval=5 -o ServerAliveCountMax=1 \
   -p "$SSH_PORT" "${key[@]}" "$SSH_USER@$ip" 'sh -s' < "$WORK/collector.sh" > "$WORK/$ip.remote" 2>/dev/null
  remote_rc=$?
  hostname=$(awk -F '\t' '$1=="META"&&$2=="HOST"{print $5;exit}' "$WORK/$ip.remote")
  os=$(awk -F '\t' '$1=="META"&&$2=="OS"{print $5;exit}' "$WORK/$ip.remote")
  [ -z "$os" ] || any=1
  while IFS="$TAB" read -r svc rid ver pkg detail; do
   [ "$svc" != META ] || continue
   [ -n "$svc" ] || continue
   emit "$ip" "${hostname:--}" "${os:--}" "$svc" "$rid" - "$ver" "$pkg" NA "$detail" >> "$file"
  done < "$WORK/$ip.remote"
  emit "$ip" "${hostname:--}" "${os:--}" SSH inventory - - - "$([ "$remote_rc" -eq 0 ] && printf SIM || printf DESCONHECIDO)" \
   "SSH exit=$remote_rc; conclusao=$([ "$remote_rc" -eq 0 ] && printf recebido || printf parcial-ou-indisponivel); permissoes limitam cobertura" >> "$file"
  # Add remote hostname/OS to endpoint rows without claiming a backend association.
  awk -F '\t' -v OFS='\t' -v h="${hostname:--}" -v o="${os:--}" '{$2=h;$3=o;print}' "$file" > "$file.tmp" && mv -- "$file.tmp" "$file"
 fi
 if [ "$any" -eq 0 ]; then
  emit "$ip" - - DISCOVERY host - - - DESCONHECIDO 'Sem resposta nas portas testadas; host desligado/filtrado ou servicos noutras portas; PHP nao excluido' >> "$file"
 fi
}
if [ -z "$SIMULATE" ]; then
 printf 'Auditoria: %s IPs; concorrencia %s.\n' "$(wc -l < "$WORK/targets")" "$CONCURRENCY"
 n=0
 while IFS= read -r ip; do
  scan_host "$ip" &
  n=$((n+1)); if [ "$n" -ge "$CONCURRENCY" ]; then wait; n=0; fi
 done < "$WORK/targets"
 wait
 emit IP Hostname OS Service Runtime Application PHPVersion Package Reachable Evidence > "$WORK/observations.tsv"
 while IFS= read -r ip; do
  if [ -s "$WORK/$ip.tsv" ]; then cat -- "$WORK/$ip.tsv" >> "$WORK/observations.tsv"; else
   emit "$ip" - - DISCOVERY host - - - DESCONHECIDO 'Falha interna do worker; recolha incompleta' >> "$WORK/observations.tsv"
  fi
 done < "$WORK/targets"
fi
# Validate input protocols. Empty fields prohibited to avoid Bash IFS collapsing tabs.
awk -F '\t' 'NR==1{if($0!="IP\tHostname\tOS\tService\tRuntime\tApplication\tPHPVersion\tPackage\tReachable\tEvidence")exit 2;next} NF!=10{exit 2} {for(i=1;i<=10;i++)if($i=="")exit 2} END{if(NR<2)exit 2}' "$WORK/observations.tsv" || die 'Observacoes TSV invalidas'
mkdir -p -- "$OUT" || die 'Diretorio de relatorios indisponivel'
RUN=$(mktemp -d "$OUT/php-audit-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX") || die 'Falha a criar diretorio da execucao'
translate_detail() {
 local v=$1
 local from='TCP aberto' to='TCP open'; v=${v//"$from"/"$to"}
 local from='sem banner PHP' to='no PHP banner'; v=${v//"$from"/"$to"}
 local from='limitado a' to='limited to'; v=${v//"$from"/"$to"}
 local from='sem redirects' to='no redirects'; v=${v//"$from"/"$to"}
 local from='certificado TLS nao validado' to='TLS certificate not validated'; v=${v//"$from"/"$to"}
 local from='Processo ativo' to='Running process'; v=${v//"$from"/"$to"}
 local from='executavel=' to='executable='; v=${v//"$from"/"$to"}
 local from='versao via procfs quando permitida' to='version via procfs where permitted'; v=${v//"$from"/"$to"}
 local from='pacote em disco nao comprova workers atualizados' to='on-disk package does not prove workers are updated'; v=${v//"$from"/"$to"}
 local from='Sem resposta nas portas testadas; host desligado/filtrado ou servicos noutras portas; PHP nao excluido' to='No response on tested ports; host offline/filtered or services on other ports; PHP is not ruled out'; v=${v//"$from"/"$to"}
 local from='Inventario limitado aos privilegios da conta; processos/pacotes/conteineres podem estar ocultos' to='Inventory limited by account permissions; processes/packages/containers may be hidden'; v=${v//"$from"/"$to"}
 local from='dpkg instalado; backport e runtime carregado por confirmar' to='Installed dpkg package; backport and loaded runtime unconfirmed'; v=${v//"$from"/"$to"}
 local from='RPM instalado; fornecedor/stream e runtime carregado por confirmar' to='Installed RPM package; vendor/stream and loaded runtime unconfirmed'; v=${v//"$from"/"$to"}
 local from='PHP_VERSION via -n; sem ligacao ao servico web' to='PHP_VERSION via -n; not linked to a web service'; v=${v//"$from"/"$to"}
 local from='PHP_VERSION via -n; CLI nao comprova runtime web' to='PHP_VERSION via -n; CLI does not prove the web runtime'; v=${v//"$from"/"$to"}
 local from='Modulo PHP mapeado; disco/pacote nao comprova workers atualizados' to='Mapped PHP module; disk/package does not prove workers are updated'; v=${v//"$from"/"$to"}
 local from='Imagem=' to='Image='; v=${v//"$from"/"$to"}
 local from='portas=' to='ports='; v=${v//"$from"/"$to"}
 local from='PHP interno e digest carregado por confirmar' to='Container PHP and loaded digest unconfirmed'; v=${v//"$from"/"$to"}
 local from='versao PHP/digest carregado por confirmar' to='PHP version/loaded digest unconfirmed'; v=${v//"$from"/"$to"}
 local from='conclusao=' to='completion='; v=${v//"$from"/"$to"}
 local from='recebido' to='received'; v=${v//"$from"/"$to"}
 local from='parcial-ou-indisponivel' to='partial-or-unavailable'; v=${v//"$from"/"$to"}
 local from='permissoes limitam cobertura' to='permissions limit coverage'; v=${v//"$from"/"$to"}
 local from='Falha interna do worker; recolha incompleta' to='Worker failure; incomplete collection'; v=${v//"$from"/"$to"}
 local from='Worker falhou ou excedeu tempo; recolha incompleta' to='Worker failed or timed out; incomplete collection'; v=${v//"$from"/"$to"}
 local from='TCP aberto; HTTP/TLS com erro, timeout ou corpo incompleto; sem versao fiavel' to='TCP open; HTTP/TLS failed, timed out or body incomplete; no reliable version'; v=${v//"$from"/"$to"}
 local from='HTTP/TLS com erro, timeout ou corpo incompleto; sem versao fiavel' to='HTTP/TLS failed, timed out or body incomplete; no reliable version'; v=${v//"$from"/"$to"}
 local from='Processo ativo; executavel=' to='Running process; executable='; v=${v//"$from"/"$to"}
 local from='versao carregada por confirmar' to='loaded version unconfirmed'; v=${v//"$from"/"$to"}
 local from='Sem acesso ao inventario de processos; cobertura parcial' to='Process inventory unavailable; partial coverage'; v=${v//"$from"/"$to"}
 local from='conforme nome do servico' to='according to service name'; v=${v//"$from"/"$to"}
 local from='Handler FastCGI configurado; pools, workers e sites por validar' to='FastCGI handler configured; pools, workers and sites unconfirmed'; v=${v//"$from"/"$to"}
 local from='IIS detetado; configuracao sem acesso ou nao interpretavel' to='IIS detected; configuration unavailable or unreadable'; v=${v//"$from"/"$to"}
 local from='Versao do ficheiro em disco; nao comprova versao dos workers em memoria' to='On-disk file version; does not prove in-memory worker versions'; v=${v//"$from"/"$to"}
 local from='Versao PHP indisponivel ou sem permissao' to='PHP version unavailable or access denied'; v=${v//"$from"/"$to"}
 local from='Docker sem acesso; conteineres por confirmar' to='Docker unavailable; containers unconfirmed'; v=${v//"$from"/"$to"}
 local from='Inventario limitado aos privilegios da conta; nao implica cobertura de todas as instalacoes' to='Inventory limited by account permissions; does not imply all installations were covered'; v=${v//"$from"/"$to"}
 local from='Recolha concluida=' to='Collection complete='; v=${v//"$from"/"$to"}
 local from='falha ou permissoes insuficientes implicam cobertura parcial' to='failure or insufficient permissions mean partial coverage'; v=${v//"$from"/"$to"}
 local from='Confirmacao revista:' to='Reviewed confirmation:'; v=${v//"$from"/"$to"}
 local from='Confirmacao rejeitada: backport exige pacote/build exato' to='Confirmation rejected: backport requires exact package/build'; v=${v//"$from"/"$to"}
 local from='Confirmacao ignorada: desatualizada, divergente ou incompleta' to='Confirmation ignored: stale, mismatched or incomplete'; v=${v//"$from"/"$to"}
 local from='estados CVE individuais:' to='individual CVE states:'; v=${v//"$from"/"$to"}
 local from='versao CLI/banner/pacote nao comprova runtime web corrigido' to='CLI/banner/package version does not prove the web runtime is fixed'; v=${v//"$from"/"$to"}
 local from='SIMULADO:' to='SIMULATED:'; v=${v//"$from"/"$to"}
 local from='banner antigo' to='old banner'; v=${v//"$from"/"$to"}
 local from='runtime validado pelo tecnico' to='runtime verified by technician'; v=${v//"$from"/"$to"}
 local from='apenas CLI' to='CLI only'; v=${v//"$from"/"$to"}
 local from='sem backport; runtime confirmado' to='no backport; runtime confirmed'; v=${v//"$from"/"$to"}
 local from='runtime sem backport' to='runtime without backport'; v=${v//"$from"/"$to"}
 local from='sem versao' to='no version'; v=${v//"$from"/"$to"}
 local from='portas filtradas' to='filtered ports'; v=${v//"$from"/"$to"}
 local from='banner corrigido nao comprova runtime' to='fixed banner does not prove the runtime'; v=${v//"$from"/"$to"}
 printf '%s' "$v"
}
CSV="$RUN/report.csv" HTML="$RUN/report.html"
csv_cell() {
 local v=$1
 if [[ "$v" =~ ^[[:space:]]*[=+@-] ]]; then v="'$v"; fi
 v=${v//\"/\"\"}; printf '"%s"' "$v"
}
html_cell() {
 local v=$1
 v=${v//&/'&amp;'}; v=${v//</'&lt;'}; v=${v//>/'&gt;'}; v=${v//\"/'&quot;'}; v=${v//\'/'&#39;'}
 printf '%s' "$v"
}
csv_row() { local sep='' x; for x in "$@"; do printf '%s' "$sep"; csv_cell "$x"; sep=,; done; printf '\r\n'; }
csv_row IP "$(t host)" "$(t os)" "$(t service)" "$(t runtime)" "$(t app)" PHP "$(t package)" CVEs "$(t status)" "$(t risk)" "$(t reachable)" "$(t public)" "$(t evidence)" "$(t recommendation)" > "$CSV"
: > "$WORK/rows.html"; : > "$WORK/status"
while IFS="$TAB" read -r ip hostname os svc rid app ver pkg reachable detail; do
 [ "$ip" != IP ] || continue
 verified=FALSE; a=UNKNOWN; b=UNKNOWN
 # Optional existing attestation support; never requested in the normal workflow.
 if [ -n "$EVIDENCE_FILE" ]; then
  match=$(awk -F '\t' -v ip="$ip" -v s="$svc" -v r="$rid" '$1==ip&&$2==s&&$3==r{print}' "$EVIDENCE_FILE")
  if [ -n "$match" ]; then
   IFS="$TAB" read -r eip es er ev ep ea eb ef ed eu el <<< "$match"
   if [ "$ed" = "$TODAY" ] && [ "$ef" = TRUE ] && [ "$eu" != - ] && [[ "$el" =~ ^https://[^[:space:]@]+$ ]] && \
    [[ "$ev" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && { [ "$ver" = - ] || [ "$ver" = "$ev" ]; } && \
    { [ "$pkg" = - ] || [ "$pkg" = "$ep" ]; } && [ "$svc" != CLI ] && [ "$svc" != PACKAGE ] && [ "$svc" != DISCOVERY ] && [ "$svc" != SSH ]; then
    state=$(version_state "$ev")
    if { [ "$ea" != FIXED ] || [ "$eb" != FIXED ]; } || [ "$state" = FIXED_VERSION ] || [ "$ep" != - ]; then
     verified=TRUE; a=$ea; b=$eb; ver=$ev; pkg=$ep
     detail="$detail; $eu; $ed; $el; CVE-109618=$a; CVE-109619=$b"
    fi
   fi
  fi
 fi
 code=$(classify "$ver" "$svc" "$verified" "$a" "$b")
 exposure=$(t unknownValue); grep -Fxq "$ip" "$WORK/public" && exposure=$(t declared)
 risk=$(t undetermined); action=$(t unknownAction); css=unknown
 case "$code" in
 VULNERAVEL) status=$(t vulnerable); risk=$(t high); action=$(t vulnAction); css=bad; [ "$exposure" != "$(t declared)" ] || risk=$(t critical);;
 CORRIGIDO) status=$(t fixed); risk=$(t low); action=$(t fixAction); css=good;;
 'POTENCIALMENTE VULNERAVEL') status=$(t potential); risk=$(t high); action=$(t oldAction); css=warn;;
 *) status=$(t inconclusive);;
 esac
 case "$reachable" in SIM) reachable=$(t yes);;NA) reachable=$(t na);;SIMULADO) reachable=SIMULATED;;*) reachable=$(t unknownValue);;esac
 if [ "$LANGUAGE" = en ]; then app=${app//indicio/hint}; detail=$(translate_detail "$detail"); else app=${app//indicio/indício}; fi
 csv_row "$ip" "$hostname" "$os" "$svc" "$rid" "$app" "$ver" "$pkg" "$CVES" "$status" "$risk" "$reachable" "$exposure" "$detail" "$action" >> "$CSV"
 printf '%s\n' "$code" >> "$WORK/status"
 {
  printf '<tr class="%s"><td><strong>' "$css"; html_cell "$ip"; printf '</strong>'
  [ "$hostname" = - ] || { printf '<br>'; html_cell "$hostname"; }
  printf '<details><summary>%s</summary><p>' "$(t details)"
  html_cell "$(t os): $os | $(t runtime): $rid | $(t package): $pkg | $(t reachable): $reachable | $(t public): $exposure | $(t risk): $risk"
  printf '</p><p>'; html_cell "$detail"; printf '</p></details></td>'
  for value in "$svc" "$app" "$ver" "$status" "$action"; do printf '<td>'; html_cell "$value"; printf '</td>'; done
  printf '</tr>\n'
 } >> "$WORK/rows.html"
done < "$WORK/observations.tsv"
count_all=$(wc -l < "$WORK/status")
count_attention=$(awk '$0=="VULNERAVEL"||$0=="POTENCIALMENTE VULNERAVEL"{n++}END{print n+0}' "$WORK/status")
count_unknown=$(grep -Fxc INCONCLUSIVO "$WORK/status" || :)
{
 printf '<!doctype html><html lang="%s"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>%s</title>' "$LANGUAGE" "$(t title)"
 cat <<'CSS'
<style>body{font:15px system-ui,sans-serif;color:#183047;background:#f3f6fa;margin:0;padding:24px}main{max-width:1200px;margin:auto}h1{margin-bottom:6px}p{line-height:1.5}.muted,summary{color:#52677c}.stats{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}.stats div{padding:16px;background:white;border:1px solid #d6e0e9;border-radius:8px}.stats strong{font-size:24px;display:block}.table{overflow:auto;background:white;border-radius:8px}table{width:100%;border-collapse:collapse}th,td{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid #dde5ee}th{background:#143a5e;color:white}td{overflow-wrap:anywhere}details{font-size:12px;max-width:320px;margin-top:8px}summary{cursor:pointer}.warn td:first-child{border-left:5px solid #d98b13}.bad td:first-child{border-left:5px solid #c42e34}.good td:first-child{border-left:5px solid #228157}.unknown td:first-child{border-left:5px solid #8a99a6}footer{font-size:13px;margin-top:20px}@media print{body{padding:0}.table{overflow:visible}table{font-size:11px}details{display:block}}</style><main>
CSS
 printf '<h1>%s</h1><p class="muted">%s · %s</p>' "$(t title)" "$CVES" "$(date -u +%FT%TZ)"
 [ -z "$SIMULATE" ] || printf '<p><strong>%s</strong></p>' "$(t simulated)"
 printf '<p><strong>%s:</strong> ' "$(t scope)"; html_cell "${TARGETS:-${TARGET_FILE:--}}"; printf '</p>'
 printf '<div class="stats"><div><strong>%s</strong>%s</div><div><strong>%s</strong>%s</div><div><strong>%s</strong>%s</div><div><strong>%s</strong>%s</div></div>' \
  "$(awk -F '\t' 'NR>1{print $1}' "$WORK/observations.tsv" | sort -u | wc -l)" "$(t hosts)" "$count_all" "$(t results)" "$count_attention" "$(t attention)" "$count_unknown" "$(t unknown)"
 printf '<p>%s</p><p>%s</p><div class="table"><table><thead><tr>' "$(t next)" "$(t explain)"
 for key in host service app php status action; do printf '<th>%s</th>' "$(t "$key")"; done
 printf '</tr></thead><tbody>'; cat "$WORK/rows.html"; printf '</tbody></table></div>'
 printf '<footer><p>%s</p><p><strong>%s:</strong> %s</p><a href="https://www.php.net/archive/2026.php">%s</a> · 2026-10-22</footer></main></html>' "$(t versions)" "$(t limits)" "$(t limitText)" "$(t source)"
} > "$HTML" || die 'HTML write failed'
[ -s "$CSV" ] && [ -s "$HTML" ] || die 'Incomplete reports'
printf '%s:\n%s\n%s\n' "$(t done)" "$HTML" "$CSV"
