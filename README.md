# PHP2Shell Fix Check — CVE-2026-109618 & CVE-2026-109619

**Autor / Author: Kernovix**

**Check PHP2Shell exposure and prepare remediation.** Read-only PHP vulnerability auditing for Linux and Windows: discover PHP services, collect version evidence and identify what needs attention before patching. Two standalone Bash/PowerShell scripts, with English/Portuguese HTML and CSV reports. No Ansible, agents or installation on target servers.

**Verifique a exposição ao PHP2Shell e prepare a correção.** Auditoria PHP de leitura para Linux e Windows: descubra serviços, recolha evidências de versões e identifique o que precisa de atenção antes de atualizar. Dois scripts independentes, com relatórios HTML e CSV em português ou inglês. Sem Ansible, agentes ou instalação nos servidores.

**Fix Check means assessment, not automatic patching.** This tool does not apply fixes or certify remediation from a banner or CLI version. **Fix Check significa verificação, não correção automática:** a ferramenta não aplica patches nem certifica a correção através de banners ou versões CLI.

[Português](#português) · [English](#english)

## Português

**Só precisa de indicar os alvos e escolher o idioma: `pt` ou `en`.** Use apenas redes autorizadas.

No **Windows**, abra `PHP-Audit.ps1` no PowerShell ISE e carregue em **F5**. Responda às duas perguntas: rede/IPs e idioma. Também pode executar no PowerShell:

```powershell
.\PHP-Audit.ps1 '192.168.1.0/24' pt
```

No **Linux**, abra um terminal na pasta do script:

```bash
bash php_audit.sh '192.168.1.0/24' pt
```

Sem argumentos, ambos pedem os alvos e o idioma. Não precisa de editar código, preencher nome de cliente ou change. Em execução não interativa, o idioma predefinido é português.

**Resultado:** abra `reports/<data-hora>/report.html`, ao lado do script. O caminho aparece no final. A tabela mostra IP/nome, serviço, aplicação, PHP, estado e o que fazer. **Ver detalhes** expande as evidências. `report.csv` permite importar para Excel (UTF-8, separador vírgula). Ambos usam o idioma escolhido.

**POTENCIALMENTE VULNERÁVEL** pede confirmação de possíveis backports do fornecedor. **INCONCLUSIVO** significa que faltam provas: nunca significa seguro. CLI, banners e pacotes em disco, isoladamente, não comprovam a correção do site ou de todo o servidor.

## English

**Provide authorized targets and choose the report language: `en` or `pt`.**

```powershell
.\PHP-Audit.ps1 '192.168.1.0/24' en
```

```bash
bash php_audit.sh '192.168.1.0/24' en
```

On Windows, you can open `PHP-Audit.ps1` in **PowerShell ISE**, press **F5**, enter your targets and choose `en`. With no arguments, both scripts ask these two questions. No code editing, customer name or change number is required. Non-interactive runs default to Portuguese unless `en` is supplied.

**Results:** open `reports/<timestamp>/report.html`, next to the script. The exact path is printed when finished. The short table shows IP/hostname, service, application, PHP, status and recommended action. **View details** expands evidence. `report.csv` is provided for Excel (UTF-8, comma delimiter). Both reports use the selected language.

**POTENTIALLY VULNERABLE** needs vendor backport verification. **INCONCLUSIVE** means insufficient evidence: never treat it as safe. CLI versions, banners and installed packages alone do not prove a website or an entire server is fixed.

## Alvos / Targets

| Tipo / Type | Exemplo / Example |
|---|---|
| IP | `192.168.1.10` |
| Lista / List | `'192.168.1.10,192.168.1.20'` |
| Intervalo / Range | `'192.168.1.10-192.168.1.30'` or `'192.168.1.10-30'` |
| Sub-rede / Subnet | `'192.168.1.0/24'` |

<details>
<summary>Requisitos e opções facultativas / Requirements and optional settings</summary>

- **Linux:** Bash 3.2+, curl 7.21+ with HTTPS, coreutils (including timeout/mktemp), awk, grep and sed.
- **Windows:** Windows PowerShell 5.1 with .NET Framework 4.7.2+, or PowerShell 7 on Windows.
- Portas / Ports: **80, 443, 8080, 8443**. Concorrência / Workers: **8**. Limite / Limit: **4096 IPs**. IPv4 only. `/31` and `/32` include all addresses; larger subnets omit network/broadcast.
- Outras portas / Other ports: Bash `--ports 80,443,8000`; PowerShell `-Ports 80,443,8000`. TLS: `--tls-ports` / `-TlsPorts`. Concorrência / Workers: `--concurrency 4` / `-Concurrency 4`.
- Exposição pública conhecida / Known public exposure: `--public-targets 'IP'` / `-PublicTargets 'IP'` (informada pelo técnico, não testada da Internet / technician-reported, not tested from the Internet).

Inventário remoto facultativo, com acessos existentes e autorizados / Optional remote inventory using existing authorized access:

```bash
bash php_audit.sh '192.168.1.0/24' pt --ssh-user auditor
```

```powershell
.\PHP-Audit.ps1 '192.168.1.0/24' en -Credential (Get-Credential) -UseSSL
```

SSH usa chave/ssh-agent e host keys verificadas; WinRM usa a configuração existente. Não altera autenticação, firewall ou TrustedHosts. Bash inventaria Linux por SSH; PowerShell inventaria Windows por WinRM. A descoberta HTTP funciona em qualquer SO. Falhas não interrompem os restantes alvos.

SSH uses keys/ssh-agent and verified host keys; WinRM uses existing configuration. No authentication, firewall or TrustedHosts changes. Bash inventories Linux through SSH; PowerShell inventories Windows through WinRM. HTTP discovery is OS-independent. Failures do not stop other targets.

</details>

## Limites / Limitations

Inventário de leitura: TCP e `GET /` limitado. Sem exploits, DoS, contorno de WAFs, instalação, atualização ou reinício. Passwords, valores de cookies e corpos HTTP não são incluídos nos relatórios. Sites por nome/SNI, proxies, outros caminhos, contentores e instalações ocultas podem não ser identificados. Ausência de resposta ou deteção PHP **não prova ausência de vulnerabilidade**.

Read-only TCP and bounded `GET /` inventory. No exploits, DoS, WAF bypass, installation, updates or restarts. Passwords, cookie values and HTTP bodies are not included in reports. Name-based/SNI sites, proxies, other paths, containers and hidden installations may be missed. No response or no PHP detection **does not prove safety**.

Indícios / Fingerprints: WordPress, Nextcloud, Joomla, Drupal, Laravel, Magento, MediaWiki, phpBB, WHMCS. Inventário remoto / Remote inventory: PHP-FPM, Apache/mod_php, Nginx, IIS, Docker, subject to existing permissions. Application fingerprints are hints.

Referência / Reference (2026-10-22): **PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12**. PHP ≤8.1: confirmar suporte e backports / check vendor support and backports. Debian, Ubuntu and RHEL package revisions cannot be judged solely by the upstream PHP version. The scripts preserve evidence and do not automatically certify vendor backports. Estados confirmados exigem evidência do runtime web e das duas CVEs / Confirmed states require evidence of the web runtime and both CVEs.

## Teste sem rede / Offline check

```bash
bash php_audit.sh --self-test en
```

```powershell
.\PHP-Audit.ps1 -SelfTest -Language pt
```

Testes integrados verificam versões e classificação e geram relatórios fictícios identificados como simulação, sem rede nem ficheiros de teste adicionais. Built-in tests check versions and conservative classification, then generate clearly marked simulated reports without network access or extra test files.

## Fontes / Sources

[PHP security advisory](https://www.php.net/archive/2026.php) · [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) · [Debian](https://security-tracker.debian.org/tracker/CVE-2026-109618) · [Ubuntu](https://ubuntu.com/security/CVE-2026-109618) · [Red Hat](https://access.redhat.com/security/cve/cve-2026-109618)

<details>
<summary>Publicar no GitHub / Publish on GitHub</summary>

Repository name / Nome do repositório: **`php2shell-fix-check`**.

Description: **Read-only PHP2Shell audit for CVE-2026-109618 and CVE-2026-109619. Discover PHP services and prepare remediation. Linux Bash + Windows PowerShell; EN/PT HTML and CSV reports.**

Topics: `php2shell`, `php-security`, `cve-2026-109618`, `cve-2026-109619`, `vulnerability-assessment`, `patch-management`, `remediation`, `bash`, `powershell`, `security-audit`.

Publicar apenas os dois scripts, README e ficheiros de configuração Git. Relatórios, listas de alvos, credenciais e chaves estão excluídos pelo `.gitignore`. Não publicar a pasta interna `.git` como ficheiros de um arquivo. Rever a identidade dos autores dos commits e a conta/organização usada na publicação: o proprietário do repositório ficará público.

Publish only the two scripts, README and Git configuration files. Reports, target lists, credentials and private keys are excluded by `.gitignore`. Do not distribute the internal `.git` directory as archive contents. Review commit authors and the publishing account/organization: repository ownership is public.

Use the description and topics above in GitHub About. Link to the public repository from relevant documentation you control. Descriptive titles and useful documentation help discovery; [Google recommends concise titles without keyword stuffing](https://developers.google.com/search/docs/appearance/title-link). [Crawling may take days or weeks and indexing is not guaranteed](https://developers.google.com/search/docs/crawling-indexing/ask-google-to-recrawl). Use a descrição e os tópicos acima no GitHub About; a indexação rápida não pode ser garantida.

</details>
