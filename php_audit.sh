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
LANGUAGE='' OUT="$SCRIPT_DIR/reports" EVIDENCE_FILE='' SIMULATE='' SELF_TEST=0 INSECURE=0 LOCAL_INVENTORY=0
WORK='' RUN='' TODAY=$(date -u +%F)
die() { printf 'ERRO: %s\n' "$*" >&2; exit 2; }
usage() {
cat <<'HELP'
PHP2Shell Fix Check | CVE-2026-109618 / CVE-2026-109619
bash php_audit.sh                         # asks for targets and report language
bash php_audit.sh '192.168.1.0/24' pt      # Portuguese report
bash php_audit.sh '192.168.1.10-30' en     # English report
Optional: --ports 80,443,8080,8443 --tls-ports 443,8443 --concurrency 8
          --ssh-user auditor --ssh-key FILE --local-inventory --out DIR --self-test
DNS/SNI: site.example or site.example=192.0.2.10 (mapping applies to web only)
Use only authorized targets / Usar apenas alvos autorizados.
HELP
}
need_arg() { [ "$#" -ge 2 ] || die "Falta valor para $1"; }
while [ "$#" -gt 0 ]; do
 case "$1" in
 --help|-h) usage; exit 0;;
 --self-test) SELF_TEST=1; shift; continue;;
 --local-inventory) LOCAL_INVENTORY=1; shift; continue;;
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
if [ -z "$TARGETS$TARGET_FILE$SIMULATE" ] && [ "$SELF_TEST" -eq 0 ] && [ "$LOCAL_INVENTORY" -eq 0 ] && [ -t 0 ]; then
 read -r -p 'IPs / DNS / Rede / Network (ex.: 192.168.1.0/24 ou/or app.example.com): ' TARGETS || die 'Sem escopo indicado'
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
 pt:vulnerable) printf '%s' 'VULNERÁVEL CONFIRMADO';;
 en:vulnerable) printf '%s' 'VULNERABLE (CONFIRMED)';;
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
 pt:target) printf '%s' 'Alvo';;
 en:target) printf '%s' 'Target';;
 pt:address) printf '%s' 'IP';;
 en:address) printf '%s' 'IP';;
 pt:discovery) printf '%s' 'Descoberta';;
 en:discovery) printf '%s' 'Discovery';;
 pt:vulnerability) printf '%s' 'Vulnerabilidade';;
 en:vulnerability) printf '%s' 'Vulnerability';;
 pt:confidence) printf '%s' 'Confiança na evidência PHP';;
 en:confidence) printf '%s' 'Confidence in PHP evidence';;
 pt:group) printf '%s' 'Secção';;
 en:group) printf '%s' 'Section';;
 pt:error) printf '%s' 'Erro técnico';;
 en:error) printf '%s' 'Technical error';;
 pt:errorCode) printf '%s' 'Código de erro';;
 en:errorCode) printf '%s' 'Error code';;
 pt:http) printf '%s' 'HTTP';;
 en:http) printf '%s' 'HTTP';;
 pt:tls) printf '%s' 'Validação TLS';;
 en:tls) printf '%s' 'TLS validation';;
 pt:redirect) printf '%s' 'Redirecionamento (não seguido)';;
 en:redirect) printf '%s' 'Redirect (not followed)';;
 pt:webGroup) printf '%s' 'Serviços web e candidatos';;
 en:webGroup) printf '%s' 'Web services and candidates';;
 pt:inventoryGroup) printf '%s' 'Inventário local/remoto';;
 en:inventoryGroup) printf '%s' 'Local/remote inventory';;
 pt:noWebGroup) printf '%s' 'Alvos sem serviço web detetado';;
 en:noWebGroup) printf '%s' 'Targets without a detected web service';;
 pt:errorsGroup) printf '%s' 'Erros de ligação/recolha';;
 en:errorsGroup) printf '%s' 'Connection/collection errors';;
 pt:targetCount) printf '%s' 'Alvos analisados';;
 en:targetCount) printf '%s' 'Targets checked';;
 pt:tcpCount) printf '%s' 'Portas TCP abertas candidatas';;
 en:tcpCount) printf '%s' 'Candidate open TCP ports';;
 pt:webCount) printf '%s' 'Respostas HTTP/HTTPS';;
 en:webCount) printf '%s' 'HTTP/HTTPS responses';;
 pt:webHosts) printf '%s' 'Alvos com resposta web';;
 en:webHosts) printf '%s' 'Targets with web responses';;
 pt:noWebCount) printf '%s' 'Alvos sem porta web aberta detetada';;
 en:noWebCount) printf '%s' 'Targets without a detected open web port';;
 pt:phpCount) printf '%s' 'Alvos com indícios PHP';;
 en:phpCount) printf '%s' 'Targets with PHP evidence';;
 pt:errorCount) printf '%s' 'Erros de ligação/recolha';;
 en:errorCount) printf '%s' 'Connection/collection errors';;
 pt:NO_WEB_SERVICE) printf '%s' 'SEM SERVIÇO WEB DETETADO';;
 en:NO_WEB_SERVICE) printf '%s' 'NO WEB SERVICE DETECTED';;
 pt:PHP_NOT_IDENTIFIED) printf '%s' 'PHP NÃO IDENTIFICADO';;
 en:PHP_NOT_IDENTIFIED) printf '%s' 'PHP NOT IDENTIFIED';;
 pt:PHP_NO_VERSION) printf '%s' 'PHP IDENTIFICADO SEM VERSÃO (indício)';;
 en:PHP_NO_VERSION) printf '%s' 'PHP IDENTIFIED WITHOUT VERSION (hint)';;
 pt:PHP_VERSION_IDENTIFIED) printf '%s' 'VERSÃO PHP IDENTIFICADA';;
 en:PHP_VERSION_IDENTIFIED) printf '%s' 'PHP VERSION IDENTIFIED';;
 pt:CONNECTION_ERROR) printf '%s' 'ERRO DE LIGAÇÃO';;
 en:CONNECTION_ERROR) printf '%s' 'CONNECTION ERROR';;
 pt:INVENTORY_PHP) printf '%s' 'PHP NO INVENTÁRIO';;
 en:INVENTORY_PHP) printf '%s' 'PHP IN INVENTORY';;
 pt:INVENTORY_OTHER) printf '%s' 'OUTRO COMPONENTE NO INVENTÁRIO';;
 en:INVENTORY_OTHER) printf '%s' 'OTHER INVENTORY COMPONENT';;
 pt:INVENTORY_COMPLETE) printf '%s' 'RECOLHA DE INVENTÁRIO';;
 en:INVENTORY_COMPLETE) printf '%s' 'INVENTORY COLLECTION';;
 pt:candidateHosts) printf '%s' 'IPs com portas candidatas';;
 en:candidateHosts) printf '%s' 'IPs with candidate ports';;
 pt:remoteAction) printf '%s' 'Confirmar credenciais, permissões e a configuração SSH/WinRM existente; consultar o erro técnico.';;
 en:remoteAction) printf '%s' 'Check credentials, permissions and existing SSH/WinRM configuration; review the technical error.';;
 pt:INVENTORY_ERROR) printf '%s' 'ERRO/PERMISSÕES NO INVENTÁRIO';;
 en:INVENTORY_ERROR) printf '%s' 'INVENTORY ERROR/PERMISSIONS';;
 pt:confidence_LOW) printf '%s' 'BAIXA';;
 en:confidence_LOW) printf '%s' 'LOW';;
 pt:confidence_MEDIUM) printf '%s' 'MÉDIA';;
 en:confidence_MEDIUM) printf '%s' 'MEDIUM';;
 pt:confidence_HIGH) printf '%s' 'ALTA';;
 en:confidence_HIGH) printf '%s' 'HIGH';;
 pt:noWebAction) printf '%s' 'Confirmar rede, DNS, firewall e portas autorizadas. Não foi excluída a existência de PHP.';;
 en:noWebAction) printf '%s' 'Check network, DNS, firewall and authorized ports. PHP has not been ruled out.';;
 pt:noPhpAction) printf '%s' 'O serviço respondeu sem indícios PHP. Confirmar o site virtual/SNI e inventariar o servidor se autorizado.';;
 en:noPhpAction) printf '%s' 'The service responded without PHP evidence. Check the virtual host/SNI and inventory the server if authorized.';;
 pt:noVersionAction) printf '%s' 'Existem indícios PHP sem versão. Recolher inventário local ou por SSH/WinRM autorizado e confirmar o runtime web.';;
 en:noVersionAction) printf '%s' 'PHP hints have no version. Collect local or authorized SSH/WinRM inventory and confirm the web runtime.';;
 pt:tlsAction) printf '%s' 'Corrigir a cadeia de confiança, validade e nome do certificado; usar o hostname/SNI correto. A validação TLS mantém-se ativa.';;
 en:tlsAction) printf '%s' 'Check certificate trust chain, validity and hostname; use the correct DNS/SNI name. TLS validation remains enabled.';;
 pt:connectAction) printf '%s' 'Consultar o erro técnico; confirmar DNS, rota, firewall, protocolo e tempo limite. Repetir apenas no âmbito autorizado.';;
 en:connectAction) printf '%s' 'Review the technical error; check DNS, routing, firewall, protocol and timeout. Retry only within the authorized scope.';;
 pt:redirectAction) printf '%s' 'O redirecionamento não foi seguido. Autorizar e indicar explicitamente o destino correto, incluindo o hostname/SNI.';;
 en:redirectAction) printf '%s' 'The redirect was not followed. Authorize and explicitly supply the correct destination, including its DNS/SNI name.';;
 pt:inventoryAction) printf '%s' 'Confirmar permissões e associar processos, pacotes e executáveis ao runtime web; versões em disco/CLI não certificam o site.';;
 en:inventoryAction) printf '%s' 'Check permissions and link processes, packages and executables to the web runtime; disk/CLI versions do not certify the site.';;
 pt:summaryNote) printf '%s' 'Portas TCP abertas são candidatas: só uma resposta HTTP confirma um serviço web. Confiança refere-se à evidência PHP, não à segurança do equipamento. INCONCLUSIVO nunca significa seguro.';;
 en:summaryNote) printf '%s' 'Open TCP ports are candidates: only an HTTP response confirms a web service. Confidence describes PHP evidence, not host safety. INCONCLUSIVE never means safe.';;
 pt:limitText) printf '%s' 'Só os alvos e portas autorizados são analisados. DNS/SNI identifica o site pedido; não enumera todos os sites virtuais nem backends. Redirecionamentos não são seguidos. Inventário depende das permissões e não entra nos contentores. Exposição pública é declarada pelo técnico. Sem exploits ou alterações nos alvos.';;
 en:limitText) printf '%s' 'Only authorized targets and ports are checked. DNS/SNI selects the requested site; it does not enumerate every virtual host or backend. Redirects are not followed. Inventory depends on permissions and does not enter containers. Public exposure is technician-declared. No exploits or target changes.';;
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
 function ipnum(s,parts,n,j,v){n=split(s,parts,".");if(n!=4)fail(s);v=0;for(j=1;j<=4;j++){if(parts[j]!~/^[0-9]+$/||length(parts[j])>3||parts[j]~/^0[0-9]/||parts[j]+0>255)fail(s);v=v*256+parts[j]}return v}
 function dns(s,p,n,j){if(length(s)>253||s~/^[0-9.]+$/)return 0;n=split(s,p,".");for(j=1;j<=n;j++)if(length(p[j])<1||length(p[j])>63||p[j]!~/^[A-Za-z0-9][A-Za-z0-9-]*$/||p[j]~/-$/)return 0;return 1}
 function output(s){s=tolower(s);if(!seen[s]++){if(++count>limit)fail("too many targets");print s}}
 function add(v){output(sprintf("%d.%d.%d.%d",int(v/16777216),int(v/65536)%256,int(v/256)%256,v%256))}
 {sub(/^\357\273\277/,"");sub(/\r$/,"");sub(/#.*/,"");gsub(/,/," ");for(t=1;t<=NF;t++){
  token=$t
  if(index(token,"=")){if(split(token,m,"=")!=2||!dns(m[1]))fail(token);ipnum(m[2]);output(token)}
  else if(token~/^[0-9.]+-[0-9.]+$/){
   if(split(token,r,"-")!=2)fail(token);lo=ipnum(r[1]);last=r[2]
   if(last~/^[0-9]+$/){if(length(last)>3||last+0>255)fail(token);hi=int(lo/256)*256+last}else hi=ipnum(last)
   if(hi<lo||hi-lo+1>limit)fail(token);for(x=lo;x<=hi;x++)add(x)
  }else if(index(token,"/")||token~/^[0-9.]+$/){
   n=split(token,a,"/");if(n>2)fail(token);v=ipnum(a[1]);b=32
   if(n==2){if(a[2]!~/^[0-9]+$/||length(a[2])>2||a[2]+0>32)fail(token);b=a[2]+0}
   size=2^(32-b);if(size>limit)fail("CIDR exceeds max-hosts");base=int(v/size)*size;lo=base;hi=base+size-1;if(b<31){lo++;hi--}for(x=lo;x<=hi;x++)add(x)
  }else{if(!dns(token))fail(token);output(token)}
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
 # Inline sanitation avoids a subshell for every inventory field.
 for v in "$@";do
  v=${v:--};v=${v:0:3000}
  while [[ "$v" =~ [[:cntrl:]] ]];do v=${v//"${BASH_REMATCH[0]}"/ };done
  printf '%s%s' "$sep" "$v";sep="$TAB"
 done
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
 if [[ ! "$service" =~ ^(CLI|PHP-BINARY|PACKAGE|Docker|Podman|SERVICE|COLLECTION|LOCAL|WinRM|SSH|DISCOVERY)$ ]] && { [ "$state" = BELOW ] || [ "$state" = LEGACY ]; }; then printf 'POTENCIALMENTE VULNERAVEL'; else printf INCONCLUSIVO; fi
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
 [ -n "$TARGETS$TARGET_FILE" ] || [ "$LOCAL_INVENTORY" -eq 1 ] || die 'Indique --targets ou --targets-file (ou --self-test)'
 for c in curl timeout bash; do command -v "$c" >/dev/null || die "Requisito em falta: $c"; done
 [ -z "$SSH_USER" ] || command -v ssh >/dev/null || die 'ssh em falta'
 { printf '%s\n' "$TARGETS"; if [ -n "$TARGET_FILE" ]; then cat -- "$TARGET_FILE" || exit 2; fi; } > "$WORK/scope.input" || die 'Escopo ilegivel'
 expand_scope < "$WORK/scope.input" > "$WORK/targets" || die 'Escopo recusado'
 [ -s "$WORK/targets" ] || [ "$LOCAL_INVENTORY" -eq 1 ] || die 'Escopo vazio'
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
for bin in php php5 php7.4 php8.0 php8.1 php8.2 php8.3 php8.4 php8.5 /usr/bin/php[0-9]* /usr/local/bin/php /opt/remi/php*/root/usr/bin/php /opt/plesk/php/*/bin/php; do
 if command -v "$bin" >/dev/null 2>&1; then
  case "${bin##*/}" in php|php5|php[0-9].[0-9]|php[0-9][0-9]) :;;*) continue;;esac
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
# Read service names/states only, never ExecStart, environment or command arguments.
if command -v systemctl >/dev/null 2>&1; then
 systemctl list-units --all --type=service --no-pager --no-legend 2>/dev/null | grep -E 'php.*fpm|apache|httpd|nginx|docker' | head -n 80 | while read -r unit load active sub rest; do
  line SERVICE "service:$unit" - - "Service=$unit; state=$active/$sub"
 done
fi
if command -v apk >/dev/null 2>&1; then
 apk info -v 2>/dev/null | grep -E '^php[0-9]*-' | head -n 150 | while IFS= read -r pkg; do line PACKAGE "package:$pkg" - "$pkg" 'Installed apk package; loaded web runtime unconfirmed'; done
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
 socket=/var/run/docker.sock
 [ ! -S "/run/user/$(id -u)/docker.sock" ] || socket="/run/user/$(id -u)/docker.sock"
 if [ -S "$socket" ];then
 docker -H "unix://$socket" ps --format '{{.ID}}|{{.Image}}|{{.Ports}}' 2>/dev/null | head -n 100 | while IFS='|' read -r id image ports; do
  line Docker "docker:$id" - - "Imagem=$image; portas=$ports; PHP interno e digest carregado por confirmar"
 done
 else line COLLECTION docker - - 'Local Docker socket unavailable; remote contexts are not queried';fi
fi
if command -v podman >/dev/null 2>&1; then
 podman --remote=false ps --format '{{.ID}}|{{.Image}}|{{.Ports}}' 2>/dev/null | head -n 100 | while IFS='|' read -r id image ports; do line Podman "podman:$id" - - "Image=$image; ports=$ports; container PHP unconfirmed";done
fi
line META COMPLETE - - 'Inventario limitado aos privilegios da conta; processos/pacotes/conteineres podem estar ocultos'
REMOTE
fingerprint() {
 local f=$1 apps='' name pat
 while IFS='|' read -r name pat;do
  if grep -Eiq "$pat" "$f";then apps="${apps}${apps:+; }$name (indicio)";fi
 done <<'PATTERNS'
WordPress|wp-content/|wp-includes/|generator[^>]*WordPress
Nextcloud|nextcloud|nc_sameSiteCookies
Joomla|joomla|/media/system/
Drupal|drupal|data-drupal|/sites/default/
Laravel|laravel|laravel_session
Magento|magento|/static/version[0-9]+/|mage/cookies
MediaWiki|mediawiki|mw-config|wgCanonicalNamespace
phpBB|phpbb
WHMCS|whmcs|/templates/six/|/templates/twenty-one/
PATTERNS
 printf '%s' "${apps:--}"
}
sanitize_error() {
 clean "$1" | sed -E 's#(https?://)[^ /@]+@#\1[redacted]@#g; s#(https?://[^? ]+)\?[^ ]*#\1?[redacted]#g; s/([Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]|[Cc][Oo][Oo][Kk][Ii][Ee])[[:space:]]*[:=].*/\1=[redacted]/g; s/([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Cc][Rr][Ee][Tt])[[:space:]]*[=:][[:space:]]*[^ ;]*/\1=[redacted]/g'
}
scan_host() {
 local target=$1 index=$2 host=$1 connect=$1 file="$WORK/host-$2.tsv" any=0 p scheme f rc ver app banner detail svc address discovery http tls error_code error_detail redirect confidence failures='' php_hint fp
 case "$target" in *=*) host=${target%%=*};connect=${target#*=};; esac
 : > "$file"
 for p in ${PORTS//,/ }; do
  timeout "$TIMEOUT" bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$connect" "$p" >/dev/null 2> "$WORK/tcp-$index.err"
  rc=$?
  if [ "$rc" -ne 0 ]; then
   error_code=TCP_FAILED; [ "$rc" -ne 124 ] || error_code=TCP_TIMEOUT
   grep -qi 'refused' "$WORK/tcp-$index.err" && error_code=TCP_REFUSED
   grep -Eqi 'Name or service not known|could not resolve|nodename nor servname|Temporary failure in name resolution|Name does not resolve' "$WORK/tcp-$index.err" && error_code=DNS_FAILURE
   failures="$failures${failures:+ | }$p: $error_code; $(sanitize_error "$(head -c 400 "$WORK/tcp-$index.err")")"
   continue
  fi
  any=1;scheme=http;case ",$TLS_PORTS," in *",$p,"*) scheme=https;;esac
  f="$WORK/response-$index";fp="$WORK/fingerprint-$index";local extra=()
  [ "$INSECURE" -eq 0 ] || extra=(-k)
  [ "$host" = "$connect" ] || extra+=(--resolve "$host:$p:$connect")
  # A capped combined stream avoids unbounded temporary headers or bodies.
  curl -q --ipv4 --silent --show-error --include --noproxy '*' --proto '=http,https' --connect-timeout "$TIMEOUT" --max-time "$((TIMEOUT*3))" "${extra[@]}" \
   --user-agent 'PHP-Audit/2.0 (authorized read-only inventory)' --header 'Accept-Encoding: identity' \
   --write-out '\nAUDIT_META:%{http_code}:%{remote_ip}\n' "$scheme://$host:$p/" 2> "$WORK/curl-$index.err" | head -c 98304 > "$f"
  rc=${PIPESTATUS[0]}
  http=$(awk '/^HTTP\/[0-9.]+ [0-9]+/{code=$2}END{if(code+0>=200)print code}' "$f")
  address=-
  if [ "$rc" -ne 23 ] && [ "$(wc -c < "$f")" -lt 98304 ]; then address=$(tail -n 1 "$f" | sed -nE 's/^AUDIT_META:[0-9]+:([0-9.]+)$/\1/p');fi
  if [ -z "$address" ] || [ "$address" = - ]; then case "$connect" in *[!0-9.]* ) address=-;;*) address=$connect;;esac;fi
  # Only the final response header block is eligible for version evidence.
  awk '/^HTTP\/[0-9.]+ /{headers="";active=1;next} active{if($0~/^\r?$/){active=0;next}headers=headers $0 "\n"}END{printf "%s",headers}' "$f" > "$WORK/headers-$index"
  banner=$(awk '{s=tolower($0);if(s~/^(server|x-powered-by):/)print}' "$WORK/headers-$index" | tr '\r\n' ' ' | head -c 1500)
  ver=$(printf '%s' "$banner" | sed -nE 's/.*[Pp][Hh][Pp]\/([0-9]+\.[0-9]+\.[0-9]+[^ ;,\r]*).*/\1/p')
  # Header cookie values never enter the fingerprint/report; names are enough.
  awk 'BEGIN{active=1}/^HTTP\/[0-9.]+ /{active=1;next}active&&/^\r?$/{active=0;next}!active{print}' "$f" | head -c 65536 > "$fp"
  printf '\n%s\n' "$banner" >> "$fp"
  awk 'tolower($0)~/^set-cookie:/{sub(/^[^:]*:[ ]*/,"");split($0,a,"=");print a[1]}' "$WORK/headers-$index" >> "$fp"
  app=$(fingerprint "$fp");php_hint=0
  [ "$app" = - ] || php_hint=1
  grep -Eiq 'PHPSESSID|(^|[^A-Za-z])PHP([^A-Za-z]|$)' "$fp" && php_hint=1
  discovery=PHP_NOT_IDENTIFIED;[ "$php_hint" -eq 0 ] || discovery=PHP_NO_VERSION;[ -z "$ver" ] || discovery=PHP_VERSION_IDENTIFIED
  [ -n "$http" ] || discovery=CONNECTION_ERROR
  error_code='-';error_detail='-'
  case "$rc" in
   0) :;;
   23) [ "$(wc -c < "$f")" -ge 98304 ] || error_code=HTTP_WRITE_FAILED;;
   28) error_code=HTTP_TIMEOUT;; 35) error_code=TLS_HANDSHAKE_FAILED;;51|60) error_code=TLS_CERTIFICATE_INVALID;;77) error_code=TLS_CA_INVALID;;6) error_code=DNS_FAILURE;;7) error_code=TCP_FAILED;;18) error_code=BODY_INCOMPLETE;;52) error_code=HTTP_EMPTY_RESPONSE;;56) error_code=HTTP_READ_FAILED;;*) error_code="CURL_$rc";;
  esac
  [ "$error_code" = - ] || error_detail=$(sanitize_error "$(head -c 2000 "$WORK/curl-$index.err")")
  tls=NOT_APPLICABLE
  if [ "$scheme" = https ]; then tls=UNVERIFIED;[ -z "$http" ] || tls=VALIDATED;case "$error_code" in TLS_CERTIFICATE*|TLS_CA*) tls=FAILED;;esac;[ "$INSECURE" -eq 0 ] || tls=DISABLED;fi
  redirect=-
  case "$http" in 3??) redirect=$(awk 'tolower($0)~/^location:/{sub(/^[^:]*:[ ]*/,"");sub(/\r$/,"");print;exit}' "$WORK/headers-$index" | sed -E 's#[?#].*$##;s#(https?://)[^/@]+@#\1#g');;esac
  confidence=LOW;[ -z "$ver" ] || confidence=MEDIUM;[ "$tls" != DISABLED ] || confidence=LOW
  detail="TCP open; HTTP=${http:--}; curl=$rc; bounded GET /; no redirects"
  [ "$tls" != DISABLED ] || detail="$detail; TLS validation explicitly disabled; no trust assurance"
  svc=$(printf '%s' "$scheme" | tr '[:lower:]' '[:upper:]')
  emit "$target" "$host" - "$svc:$p" "web:$p" "$app" "${ver:--}" - SIM "$detail" "${address:--}" "$discovery" "${http:--}" "$tls" "$error_code" "$error_detail" "${redirect:--}" "$confidence" >> "$file"
 done
 if [ "$any" -eq 0 ]; then
  discovery=NO_WEB_SERVICE;error_code=NO_TCP_RESPONSE
  case "$failures" in *DNS_FAILURE*) discovery=CONNECTION_ERROR;error_code=DNS_FAILURE;;esac
  address=-;case "$connect" in *[!0-9.]*) :;;*) address=$connect;;esac
  emit "$target" "$host" - DISCOVERY host - - - DESCONHECIDO 'No web service detected on tested ports; PHP is not ruled out' "$address" "$discovery" - - "$error_code" "$(sanitize_error "$failures")" - LOW >> "$file"
 fi
 if [ -n "$SSH_USER" ]; then
  local key=();[ -z "$SSH_KEY" ] || key=(-i "$SSH_KEY")
  timeout "$REMOTE_TIMEOUT" ssh -F /dev/null -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ClearAllForwardings=yes -o ForwardAgent=no -o ForwardX11=no -o PermitLocalCommand=no -o ConnectTimeout="$TIMEOUT" -o ConnectionAttempts=1 -o ServerAliveInterval=5 -o ServerAliveCountMax=1 -p "$SSH_PORT" "${key[@]}" "$SSH_USER@$host" 'sh -s' < "$WORK/collector.sh" > "$WORK/remote-$index" 2> "$WORK/ssh-$index.err"
  rc=$?;local remote_host remote_os
  remote_host=$(awk -F '\t' '$1=="META"&&$2=="HOST"{print $5;exit}' "$WORK/remote-$index");remote_os=$(awk -F '\t' '$1=="META"&&$2=="OS"{print $5;exit}' "$WORK/remote-$index")
  while IFS="$TAB" read -r svc rid ver pkg detail; do
   [ "$svc" != META ] || continue;[ -n "$svc" ] || continue
   emit "$target" "${remote_host:-$host}" "${remote_os:--}" "$svc" "$rid" - "$ver" "$pkg" NA "$(sanitize_error "$detail")" >> "$file"
  done < "$WORK/remote-$index"
  error_code=-;error_detail=-
  if [ "$rc" -ne 0 ] || ! grep -q 'META.COMPLETE' "$WORK/remote-$index"; then error_code=SSH_FAILED;error_detail="SSH exit=$rc; $(sanitize_error "$(head -c 1600 "$WORK/ssh-$index.err")")";fi
  emit "$target" "${remote_host:-$host}" "${remote_os:--}" SSH inventory - - - NA "SSH exit=$rc; permissions limit coverage" - INVENTORY_COMPLETE - - "$error_code" "$error_detail" - LOW >> "$file"
 fi
}
if [ -z "$SIMULATE" ]; then
 printf '%s: %s targets; concurrency=%s.\n' "$(t scanning)" "$(wc -l < "$WORK/targets")" "$CONCURRENCY"
 n=0;index=0
 while IFS= read -r target; do index=$((index+1));scan_host "$target" "$index" & n=$((n+1));if [ "$n" -ge "$CONCURRENCY" ];then wait;n=0;fi;done < "$WORK/targets"
 wait
 emit IP Hostname OS Service Runtime Application PHPVersion Package Reachable Evidence Address DiscoveryCode HTTPStatus TLSValidation ErrorCode ErrorDetail RedirectTo Confidence > "$WORK/observations.tsv"
 index=0
 while IFS= read -r target; do
  index=$((index+1));if [ -s "$WORK/host-$index.tsv" ];then cat -- "$WORK/host-$index.tsv" >> "$WORK/observations.tsv";else emit "$target" - - DISCOVERY host - - - DESCONHECIDO 'Worker failed; partial coverage' - CONNECTION_ERROR - - WORKER_FAILED 'Worker produced no observations' - LOW >> "$WORK/observations.tsv";fi
 done < "$WORK/targets"
 if [ "$LOCAL_INVENTORY" -eq 1 ]; then
  timeout "$REMOTE_TIMEOUT" sh "$WORK/collector.sh" > "$WORK/local" 2> "$WORK/local.err";rc=$?
  local_host=$(hostname 2>/dev/null);local_os=$(uname -s)
  while IFS="$TAB" read -r svc rid ver pkg detail;do [ "$svc" != META ] || continue;[ -n "$svc" ] || continue;emit local "${local_host:--}" "$local_os" "$svc" "$rid" - "$ver" "$pkg" NA "$(sanitize_error "$detail")" >> "$WORK/observations.tsv";done < "$WORK/local"
  error_code=-;error_detail=-;if [ "$rc" -ne 0 ] || ! grep -q 'META.COMPLETE' "$WORK/local";then error_code=LOCAL_FAILED;error_detail="Local exit=$rc; $(sanitize_error "$(head -c 1000 "$WORK/local.err")")";fi
  emit local "${local_host:--}" "$local_os" LOCAL inventory - - - NA "Local inventory exit=$rc; permissions limit coverage" - INVENTORY_COMPLETE - - "$error_code" "$error_detail" - LOW >> "$WORK/observations.tsv"
 fi
fi
# Accept the original 10-column simulation protocol and the extended 18-column form.
awk -F '\t' -v OFS='\t' 'NR==1{if($1!="IP"||$4!="Service"||$10!="Evidence")exit 2;print "IP\tHostname\tOS\tService\tRuntime\tApplication\tPHPVersion\tPackage\tReachable\tEvidence\tAddress\tDiscoveryCode\tHTTPStatus\tTLSValidation\tErrorCode\tErrorDetail\tRedirectTo\tConfidence";next}NF!=10&&NF!=18{exit 2}{for(i=1;i<=NF;i++)if($i=="")exit 2;for(i=NF+1;i<=18;i++)$i="-";print}END{if(NR<2)exit 2}' "$WORK/observations.tsv" > "$WORK/normalized" || die 'Observacoes TSV invalidas'
mv -- "$WORK/normalized" "$WORK/observations.tsv"

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
 [ "$v" != - ] || v=''
 if [[ "$v" =~ ^[[:space:]]*[=+@-] ]];then v="'$v";fi
 v=${v//\"/\"\"};printf '"%s"' "$v"
}
html_cell() {
 local v=$1;[ "$v" != - ] || v=''
 v=${v//&/'&amp;'};v=${v//</'&lt;'};v=${v//>/'&gt;'};v=${v//\"/'&quot;'};v=${v//\'/'&#39;'};printf '%s' "$v"
}
csv_row() { local sep='' x;for x in "$@";do printf '%s' "$sep";csv_cell "$x";sep=,;done;printf '\r\n';}
printf '\357\273\277' > "$CSV"
csv_row "$(t target)" IP "$(t host)" "$(t os)" "$(t group)" "$(t service)" DiscoveryCode "$(t discovery)" PHP CVEs VulnerabilityCode "$(t vulnerability)" "$(t risk)" "$(t confidence)" HTTP "$(t tls)" "$(t errorCode)" "$(t error)" "$(t redirect)" "$(t app)" "$(t runtime)" "$(t package)" "$(t reachable)" "$(t public)" "$(t evidence)" "$(t recommendation)" >> "$CSV"
for group in WEB INVENTORY NO_RESPONSE ERRORS;do : > "$WORK/$group.html";done
: > "$WORK/stats"
while IFS="$TAB" read -r target hostname os svc rid app ver pkg reachable detail address discovery http tls error_code error_detail redirect confidence;do
 [ "$target" != IP ] || continue
 verified=FALSE;a=UNKNOWN;b=UNKNOWN
 if [ -n "$EVIDENCE_FILE" ];then
  match=$(awk -F '\t' -v ip="$target" -v s="$svc" -v r="$rid" '$1==ip&&$2==s&&$3==r{print}' "$EVIDENCE_FILE")
  if [ -n "$match" ];then
   IFS="$TAB" read -r eip es er ev ep ea eb ef ed eu el <<< "$match"
   if [ "$ed" = "$TODAY" ] && [ "$ef" = TRUE ] && [ "$eu" != - ] && [[ "$el" =~ ^https://[^[:space:]@]+$ ]] && [[ "$ev" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && { [ "$ver" = - ] || [ "$ver" = "$ev" ]; } && { [ "$pkg" = - ] || [ "$pkg" = "$ep" ]; } && [[ "$svc" =~ ^HTTPS?:|PHP-FPM|mod_php|php.*cgi|lsphp|frankenphp ]];then
    state=$(version_state "$ev")
    if { [ "$ea" != FIXED ] || [ "$eb" != FIXED ]; } || [ "$state" = FIXED_VERSION ] || [ "$ep" != - ];then
     verified=TRUE;a=$ea;b=$eb;ver=$ev;pkg=$ep;detail="$detail; reviewed: $eu; $ed; $el; CVE109618=$a; CVE109619=$b"
    else detail="$detail; rejected: backport requires exact package/build";fi
   else detail="$detail; ignored: stale, mismatched or incomplete attestation";fi
  fi
 fi
 code=$(classify "$ver" "$svc" "$verified" "$a" "$b")
 vcode=INCONCLUSIVE;status=$(t inconclusive);risk=$(t undetermined);action=$(t unknownAction)
 case "$code" in
 VULNERAVEL) vcode=VULNERABLE_CONFIRMED;status=$(t vulnerable);risk=$(t high);action=$(t vulnAction);;
 CORRIGIDO) vcode=FIXED;status=$(t fixed);risk=$(t low);action=$(t fixAction);;
 'POTENCIALMENTE VULNERAVEL') vcode=POTENTIALLY_VULNERABLE;status=$(t potential);risk=$(t high);action=$(t oldAction);;
 esac
 group=INVENTORY;group_label=$(t inventoryGroup)
 case "$svc" in
 HTTP:*|HTTPS:*) group=WEB;group_label=$(t webGroup);if [ "$discovery" = - ];then discovery=PHP_NOT_IDENTIFIED;[ "$app" = - ] || discovery=PHP_NO_VERSION;[ "$ver" = - ] || discovery=PHP_VERSION_IDENTIFIED;fi;;
 DISCOVERY) group=NO_RESPONSE;group_label=$(t noWebGroup);[ "$discovery" != - ] || discovery=NO_WEB_SERVICE;;
 *) if [ "$discovery" = - ];then discovery=INVENTORY_OTHER;case "$svc" in WinRM|SSH|LOCAL) discovery=INVENTORY_COMPLETE;;*PHP*|*php*|CLI) discovery=INVENTORY_PHP;;esac;[ "$ver" = - ] || discovery=INVENTORY_PHP;case "$pkg" in *php*) discovery=INVENTORY_PHP;;esac;fi;;
 esac
 if [ "$svc" = Docker ] || [ "$svc" = Podman ];then image_hint=${detail#*=};image_hint=${image_hint%%;*};case "$image_hint" in *php*) discovery=INVENTORY_PHP;;esac;fi
 if [ "$svc" = COLLECTION ];then discovery=INVENTORY_ERROR;error_code=INVENTORY_PARTIAL;error_detail=$detail;fi
 if [ "$group" = INVENTORY ] && [ "$error_code" != - ];then discovery=INVENTORY_ERROR;fi
 [ "$confidence" != - ] || confidence=LOW
 [ "$ver" = - ] || confidence=MEDIUM;[ "$verified" != TRUE ] || confidence=HIGH;[ "$tls" != DISABLED ] || confidence=LOW
 if [ "$vcode" = INCONCLUSIVE ];then
  case "$discovery" in NO_WEB_SERVICE) action=$(t noWebAction);;PHP_NOT_IDENTIFIED) action=$(t noPhpAction);;PHP_NO_VERSION) action=$(t noVersionAction);;CONNECTION_ERROR) action=$(t connectAction);;*) [ "$group" != INVENTORY ] || action=$(t inventoryAction);;esac
  case "$error_code" in TLS_CERTIFICATE*|TLS_CA*) action=$(t tlsAction);;-|NO_TCP_RESPONSE) :;;*) action=$(t connectAction);;esac
  case "$error_code" in INVENTORY_PARTIAL|LOCAL_FAILED) action=$(t inventoryAction);;SSH_FAILED|WINRM_FAILED) action=$(t remoteAction);;esac
  [ "$redirect" = - ] || action=$(t redirectAction)
 fi
 exposure=$(t unknownValue);if grep -Fxq "$target" "$WORK/public" || grep -Fxq "$address" "$WORK/public" || grep -Fxq "${target%%=*}" "$WORK/public";then exposure=$(t declared);[ "$vcode" != VULNERABLE_CONFIRMED ] || risk=$(t critical);fi
 [ "$address" != - ] || { case "$target" in *[!0-9.]*) :;;*) address=$target;;esac; }
 case "$reachable" in SIM) reachable=$(t yes);;NA) reachable=$(t na);;SIMULADO) reachable=SIMULATED;;*) reachable=$(t unknownValue);;esac
 if [ "$LANGUAGE" = en ];then app=${app//indicio/hint};detail=$(translate_detail "$detail");else app=${app//indicio/indício};fi
 detail=$(sanitize_error "$detail; CVE109618=$a; CVE109619=$b");error_detail=$(sanitize_error "$error_detail")
 csv_row "$target" "$address" "$hostname" "$os" "$group_label" "$svc" "$discovery" "$(t "$discovery")" "$ver" "$CVES" "$vcode" "$status" "$risk" "$(t "confidence_$confidence")" "$http" "$tls" "$error_code" "$error_detail" "$redirect" "$app" "$rid" "$pkg" "$reachable" "$exposure" "$detail" "$action" >> "$CSV"
 emit "$target" "$group" "$http" "$discovery" "$error_code" "$vcode" "$address" >> "$WORK/stats"
 {
  printf '<tr><td><strong>';html_cell "$target";printf '</strong><details><summary>%s</summary><p>' "$(t details)"
  html_cell "IP=$address; $(t host)=$hostname; $(t os)=$os; $rid; $pkg; HTTP=$http; TLS=$tls; $error_code; $error_detail; $(t redirect)=$redirect; $(t public)=$exposure; $detail"
  printf '</p></details></td>'
  for value in "$svc" "$(t "$discovery")" "$ver" "$status" "$(t "confidence_$confidence")" "$action";do printf '<td>';html_cell "$value";printf '</td>';done;printf '</tr>\n'
 } > "$WORK/row.html"
 cat "$WORK/row.html" >> "$WORK/$group.html"
 case "$error_code" in -|NO_TCP_RESPONSE) :;;*) cat "$WORK/row.html" >> "$WORK/ERRORS.html";;esac
done < "$WORK/observations.tsv"
table() {
 printf '<div class="table"><table><thead><tr>'
 for key in target service discovery php vulnerability confidence action;do printf '<th scope="col">%s</th>' "$(t "$key")";done
 printf '</tr></thead><tbody>';cat "$WORK/$1.html";printf '</tbody></table></div>'
}
{
 printf '<!doctype html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>%s</title>' "$LANGUAGE" "$(t title)"
 cat <<'STYLE'
<style>body{font:14px system-ui,sans-serif;color:#183047;background:#f3f6fa;margin:0;padding:24px}main{max-width:1500px;margin:auto}p{line-height:1.6}.stats{display:flex;flex-wrap:wrap;gap:10px;margin:20px 0}.stats div{padding:14px;background:white;border:1px solid #d6e0e9;border-radius:6px}.stats strong{font-size:24px;display:block}.table{overflow:auto;background:white}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #dde5ee}th{background:#143a5e;color:white}td{overflow-wrap:anywhere}td details{font-size:12px;max-width:390px}summary{cursor:pointer;color:#385a75}.no-response{margin-top:25px}footer{font-size:12px;margin-top:25px}@media print{body{padding:0}.table{overflow:visible}table{font-size:10px}}</style></head><body><main>
STYLE
 printf '<h1>%s</h1><p>%s · %s UTC</p>' "$(t title)" "$CVES" "$(date -u +%FT%T)"
 [ -z "$SIMULATE" ] || printf '<p><strong>%s</strong></p>' "$(t simulated)"
 printf '<p><strong>%s:</strong> ' "$(t scope)";html_cell "${TARGETS:-local}";printf '</p><div class="stats">'
 while read -r key count;do printf '<div><strong>%s</strong>%s</div>' "$count" "$(t "$key")";done < <(
  awk -F '\t' '{targets[$1]=1;if($2=="WEB"){tcp++;if($7!="-")candidate[$7]=1;if($3~/^[0-9]+$/&&$3+0>0){http++;web[$1]=1}}if($2=="NO_RESPONSE")no++;if($4~/^PHP_(NO_VERSION|VERSION_IDENTIFIED)$/||$4=="INVENTORY_PHP")php[$1]=1;if($5!="-"&&$5!="NO_TCP_RESPONSE")errors++;if($6=="VULNERABLE_CONFIRMED"||$6=="POTENTIALLY_VULNERABLE")attention++}END{for(k in targets)n++;for(k in candidate)c++;for(k in web)w++;for(k in php)p++;print "targetCount",n+0;print "results",NR;print "tcpCount",tcp+0;print "candidateHosts",c+0;print "webCount",http+0;print "webHosts",w+0;print "noWebCount",no+0;print "phpCount",p+0;print "errorCount",errors+0;print "attention",attention+0}' "$WORK/stats"
 )
 printf '</div><p>%s</p><p>%s</p><h2>%s (%s)</h2>' "$(t summaryNote)" "$(t explain)" "$(t webGroup)" "$(wc -l < "$WORK/WEB.html")";table WEB
 for group in INVENTORY ERRORS;do if [ -s "$WORK/$group.html" ];then key=inventoryGroup;[ "$group" != ERRORS ] || key=errorsGroup;printf '<h2>%s (%s)</h2>' "$(t "$key")" "$(wc -l < "$WORK/$group.html")";table "$group";fi;done
 if [ -s "$WORK/NO_RESPONSE.html" ];then printf '<details class="no-response"><summary>%s (%s)</summary>' "$(t noWebGroup)" "$(wc -l < "$WORK/NO_RESPONSE.html")";table NO_RESPONSE;printf '</details>';fi
 printf '<footer><p>%s</p><p>%s</p><a href="https://www.php.net/archive/2026.php#2026-10-21-5">%s</a></footer></main></body></html>' "$(t versions)" "$(t limitText)" "$(t source)"
} > "$HTML" || die 'HTML write failed'
[ -s "$CSV" ] && [ -s "$HTML" ] || die 'Incomplete reports'
printf '%s:\n%s\n%s\n' "$(t done)" "$HTML" "$CSV"
