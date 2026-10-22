# PHP2Shell Fix Check

**Escolha o idioma / Choose your language**

| Português | English |
| --- | --- |
| [Ler o manual em português →](#português) | [Read the English guide →](README.md#english) |

**CVE-2026-109618 · CVE-2026-109619**

Um projeto de **[Kernovix](https://github.com/Kernovix)** · [Página do projeto](https://kernovix.github.io/php2shell-fix-check/)

## Português

**Descubra serviços PHP, recolha evidências de versões e prepare a correção do PHP2Shell.** Dois scripts independentes: Bash para Linux e PowerShell para Windows. Execute numa máquina dentro da rede autorizada e receba relatórios HTML e CSV guardados localmente.

Sem Ansible, agentes permanentes ou instalação nos servidores analisados. **Fix Check faz a avaliação; não aplica correções.** Utilize apenas em sistemas que está autorizado a auditar.

### 1. Descarregar o script

| O seu computador | Descarregar |
| --- | --- |
| Windows | [PHP-Audit.ps1](https://github.com/Kernovix/php2shell-fix-check/raw/refs/heads/main/PHP-Audit.ps1) |
| Linux | [php_audit.sh](https://github.com/Kernovix/php2shell-fix-check/raw/refs/heads/main/php_audit.sh) |

Guarde o ficheiro numa pasta do computador. Só precisa do script correspondente ao seu sistema operativo.

### 2. Executar

Substitua `192.168.1.0/24` pelos IPs ou pela rede que está autorizado a analisar. O último argumento, `pt`, escolhe relatórios em português; use `en` para relatórios em inglês. O idioma da documentação é independente do idioma do relatório.

**Windows:** abra o PowerShell na pasta do script e execute:

```powershell
.\PHP-Audit.ps1 '192.168.1.0/24' pt
```

Em alternativa, abra `PHP-Audit.ps1` no **PowerShell ISE**, carregue em **F5** e responda às duas perguntas: alvos e idioma do relatório. Siga a política de execução de scripts da sua organização.

**Linux:** abra um terminal na pasta do script e execute:

```bash
bash php_audit.sh '192.168.1.0/24' pt
```

Sem argumentos num terminal interativo, ambos os scripts pedem os alvos e o idioma. Não precisa de editar o código. Nas execuções não interativas, o idioma predefinido é português, a menos que indique `en`.

**O que posso colocar no campo dos alvos?**

| Âmbito | Exemplo |
| --- | --- |
| Um servidor | `'192.168.1.10'` |
| Vários servidores | `'192.168.1.10,192.168.1.20'` |
| Um intervalo de IPs | `'192.168.1.10-30'` ou `'192.168.1.10-192.168.1.30'` |
| Uma sub-rede | `'192.168.1.0/24'` |
| Um hostname DNS (HTTP Host e TLS SNI) | `'app.example.com'` |
| Um site virtual num IPv4 específico | `'app.example.com=192.0.2.10'` |

Os nomes DNS selecionam o site pedido e enviam esse nome no SNI da ligação TLS. `nome=IP` fixa a **ligação web** nesse IP sem alterar o DNS ou o ficheiro hosts. O SSH/WinRM continua a usar o hostname e a resolução de nomes existente. Só é analisado o IPv4 selecionado; não são enumerados outros endereços DNS ou sites virtuais não indicados.

### 3. Abrir o relatório

No final da auditoria, o script apresenta o caminho dos relatórios. Abra **`report.html`** dentro de `reports/<data-hora>/`, ao lado do script. Na mesma pasta fica **`report.csv`**, para abrir no Excel (UTF-8, separador vírgula).

O relatório HTML separa **serviços web e portas candidatas**, **inventário local/remoto**, **erros de ligação/recolha** e uma secção recolhida para **alvos sem serviço web detetado**. Portas TCP abertas são candidatas; só uma resposta HTTP confirma um serviço web. As estatísticas mostram alvos analisados, portas candidatas, respostas HTTP, alvos que responderam, indícios PHP e erros.

**A descoberta e a vulnerabilidade têm colunas separadas.** A descoberta distingue ausência de serviço web detetado, PHP não identificado, indícios PHP sem versão, versão PHP identificada e erros de ligação. Selecione **Ver detalhes** para consultar IP, hostname, indícios de aplicações, runtime, pacotes, estado HTTP, validação TLS, erro técnico sanitizado e redirecionamento não seguido. A confiança refere-se à evidência PHP, não à segurança do equipamento.

O CSV contém os mesmos resultados, com as colunas estáveis `DiscoveryCode` e `VulnerabilityCode` para filtrar. Os valores desconhecidos ficam vazios, em vez de `'-`; mantém-se a proteção contra fórmulas em folhas de cálculo. Ambos os relatórios usam o idioma escolhido e o CSV inclui BOM UTF-8 para o Excel.

Um alvo pode gerar várias observações: uma por serviço candidato ou componente inventariado. O número de linhas de resultados não é o número de máquinas.

| Estado | Significado |
| --- | --- |
| **POTENCIALMENTE VULNERÁVEL** | A versão exige investigação. Confirme os backports do fornecedor e o runtime web antes de concluir que existe vulnerabilidade. |
| **INCONCLUSIVO** | Faltam evidências ou são insuficientes. Nunca significa seguro. |
| **VULNERÁVEL CONFIRMADO** | Evidência revista, ligada ao runtime web, confirma que pelo menos uma das CVEs o afeta. |
| **CORRIGIDO** | Evidência revista, correspondente ao runtime web e às duas CVEs, confirma a correção dessa observação; não certifica todo o servidor. |

**A versão PHP da linha de comandos (CLI) ou um banner HTTP, isoladamente, não prova que o site está corrigido. A ausência de deteção PHP ou de resposta não prova ausência de vulnerabilidade.** Os scripts não certificam automaticamente os backports dos fornecedores. Mantenha os relatórios e as listas de alvos privados.

Os estados confirmados exigem evidência TSV revista facultativa (`--evidence` / `-EvidenceFile`), correspondente ao alvo, serviço, runtime, versão e pacote/build. A evidência deve identificar o revisor e um aviso HTTPS, indicar o estado individual das CVEs e ter sido revista na data UTC atual. Um backport com versão PHP mais antiga exige também um pacote/build exato. O teste integrado verifica confirmações aceites e rejeitadas com evidência fictícia.

### O que os scripts verificam

- Portas TCP **80, 443, 8080 e 8443**, seguidas de um pedido HTTP `GET /` limitado. É possível configurar outras portas, tempos limite e concorrência.
- Indícios de PHP e das aplicações **WordPress, Nextcloud, Joomla, Drupal, Laravel, Magento, MediaWiki, phpBB e WHMCS**. Estes indícios não são prova de instalação.
- **Inventário local** facultativo, ou remoto através de acessos existentes e autorizados: Linux por **SSH**, Windows por **PowerShell Remoting / WinRM**. Recolhe nome, sistema operativo, executáveis/processos PHP, serviços e pacotes, conforme as permissões. Em Windows, verifica também handlers IIS FastCGI acessíveis e localizações habituais PHP/XAMPP/Wamp/Laragon; em Linux, verifica runtimes instalados, pacotes e executáveis dos processos acessíveis.
- **PHP-FPM, Apache/mod_php, Nginx, IIS e metadados Docker**, quando aplicáveis e acessíveis. Os metadados Docker não comprovam a versão PHP dentro do contentor.

Uma falha num alvo não interrompe a análise dos restantes. O técnico pode indicar exposição pública conhecida; os scripts não testam a acessibilidade a partir da Internet.

### Requisitos e opções facultativas

<details>
<summary>Requisitos mínimos e valores predefinidos</summary>

- **Linux:** Bash 3.2+, curl 7.29+ com HTTPS, coreutils (incluindo `timeout` e `mktemp`), awk, grep e sed. Sem novas dependências de execução.
- **Windows:** Windows PowerShell 5.1 com .NET Framework 4.7.2+, ou PowerShell 7 em Windows.
- **Valores predefinidos:** portas `80,443,8080,8443`; TLS em `443,8443`; **8** tarefas em simultâneo; máximo de **4096 endereços IPv4**.
- **IPv4 e hostnames DNS.** `/31` e `/32` incluem todos os endereços; nas sub-redes maiores, os endereços de rede e broadcast são excluídos. IPv6 não é suportado.

</details>

<details>
<summary>Alterar portas, concorrência ou exposição pública declarada</summary>

| Opção | Bash | PowerShell |
| --- | --- | --- |
| Portas | `--ports 80,443,8000` | `-Ports 80,443,8000` |
| Portas TLS | `--tls-ports 443,8443` | `-TlsPorts 443,8443` |
| Tarefas em simultâneo | `--concurrency 4` | `-Concurrency 4` |
| Tempo limite de rede, em segundos | `--timeout 5` | `-TimeoutSeconds 5` |
| Exposição pública conhecida | `--public-targets '192.168.1.10'` | `-PublicTargets '192.168.1.10'` |

Acrescente as opções ao comando habitual. Exemplo:

```bash
bash php_audit.sh '192.168.1.0/24' pt --ports 80,443,8000 --concurrency 4
```

```powershell
.\PHP-Audit.ps1 '192.168.1.0/24' pt -Ports 80,443,8000 -Concurrency 4
```

A exposição pública é indicada pelo técnico, não é verificada a partir da Internet.

</details>

<details>
<summary>Inventariar o computador onde está a executar o script</summary>

O inventário local não exige alvos de rede nem credenciais remotas:

```bash
bash php_audit.sh pt --local-inventory
```

```powershell
.\PHP-Audit.ps1 -LocalInventory -Language pt
```

Pode combinar o inventário local com os alvos habituais. São lidos os metadados acessíveis; não é percorrido todo o sistema de ficheiros, não se entra nos contentores, não se reiniciam workers nem se elevam privilégios. A versão CLI ou de um ficheiro local, isoladamente, não prova a correção do runtime web.

</details>

<details>
<summary>Interpretar erros HTTPS e certificados</summary>

A validação dos certificados TLS está **ativa por defeito**, incluindo nos alvos DNS/SNI. Erros de confiança/nome/validade do certificado, negociação TLS, tempos limite, problemas TCP/DNS e respostas incompletas preservam detalhes técnicos sanitizados. Os redirecionamentos são indicados, mas nunca seguidos; as credenciais, os parâmetros de consulta e os fragmentos são removidos dos respetivos URLs apresentados. Os cookies são usados apenas pelo nome para identificação, sem registar os valores.

Para um diagnóstico expressamente autorizado de um serviço conhecido com certificado inválido, acrescente Bash `--insecure-tls` ou PowerShell `-InsecureTls`. Nunca é automático: o relatório indica validação TLS `DISABLED` e confiança baixa na evidência PHP. Só afeta os pedidos web, não o SSH ou WinRM. Prefira corrigir a cadeia de confiança do certificado ou indicar o hostname correto.

</details>

<details>
<summary>Ativar o inventário facultativo por SSH ou WinRM</summary>

Para **servidores Linux**, use Bash com uma chave SSH ou ssh-agent existente e chaves dos servidores previamente verificadas:

```bash
bash php_audit.sh '192.168.1.0/24' pt --ssh-user auditor
```

Para **servidores Windows**, use PowerShell com acesso WinRM existente e autorizado:

```powershell
.\PHP-Audit.ps1 '192.168.1.0/24' pt -Credential (Get-Credential) -UseSSL
```

Não são pedidas passwords SSH nem acesso sudo. O WinRM utiliza a configuração existente; o script não altera autenticação, regras de firewall ou TrustedHosts. `-WinRMPort 0` (predefinido) omite `Port` no `Invoke-Command`, deixando o WinRM escolher a porta HTTP/HTTPS habitual. Indique `-WinRMPort 5999` apenas para uma porta personalizada. A descoberta HTTP é independente do sistema operativo. Permissões insuficientes podem deixar o inventário parcial ou inconclusivo.

</details>

### Experimentar sem analisar uma rede

O teste integrado verifica a lógica de versões e classificação e gera relatórios HTML e CSV fictícios, identificados como simulação. Não faz pedidos de rede.

```bash
bash php_audit.sh --self-test pt
```

```powershell
.\PHP-Audit.ps1 -SelfTest -Language pt
```

Os testes automatizados de regressão estão em [`tests/`](tests/). Num computador de desenvolvimento com **Node.js 18+ e OpenSSL 1.1.1+**, execute `node tests/run-tests.cjs`. São criados servidores HTTP/TLS locais temporários e relatórios fictícios; não é analisada a rede do cliente nem são instalados certificados. Estas dependências de teste não são necessárias para executar os scripts de auditoria. O GitHub Actions testa Windows PowerShell 5.1, PowerShell 7, Bash em Linux e compatibilidade com Bash 3.2.

### Referência das correções PHP

Estas são as primeiras versões oficiais que os scripts utilizam como referência para as duas CVEs:

| Série PHP | Primeira versão corrigida |
| --- | --- |
| 8.2 | **8.2.35** |
| 8.3 | **8.3.36** |
| 8.4 | **8.4.27** |
| 8.5 | **8.5.12** |

Use a versão corrigida ou uma versão estável posterior da mesma série. Para **PHP 8.1 e anteriores**, confirme o suporte do fornecedor/LTS e os backports ou migre para uma série suportada.

Pacotes Debian, Ubuntu e RHEL podem incluir correções mantendo um número de versão PHP mais antigo. Consulte o aviso do fornecedor para **as duas CVEs** e confirme o runtime que serve os pedidos web. Atualizar apenas a aplicação não comprova que o PHP utilizado por ela foi corrigido.

### Limites e utilização autorizada

Inventário de leitura: verificações TCP e pedidos `GET /` limitados. Sem exploits, testes de DoS, contorno de WAFs, instalação, atualização ou reinício. Passwords, valores de cookies e corpos das respostas HTTP não são incluídos nos relatórios.

Só são selecionados os sites DNS/SNI explicitamente pedidos. Outros sites virtuais, proxies, backends, caminhos, instalações ocultas e contentores com acesso restrito podem não ser identificados. Acorde o âmbito autorizado antes de executar a auditoria. **Sem evidência suficiente, o resultado continua INCONCLUSIVO.**

### Fontes

[Aviso de segurança PHP](https://www.php.net/archive/2026.php#2026-10-21-5) · [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) · [Debian](https://security-tracker.debian.org/tracker/CVE-2026-109618) · [Ubuntu](https://ubuntu.com/security/CVE-2026-109618) · [Red Hat](https://access.redhat.com/security/cve/cve-2026-109618)

---

[English →](README.md#english) · [Voltar ao início ↑](#php2shell-fix-check)
