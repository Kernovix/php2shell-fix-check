# PHP2Shell Fix Check

**Choose your language / Escolha o idioma**

| Português | English |
| --- | --- |
| [Ler o manual em português →](README.pt.md#português) | [Read the English guide →](#english) |

**CVE-2026-109618 · CVE-2026-109619**

A project by **[Kernovix](https://github.com/Kernovix)** · [Project website](https://kernovix.github.io/php2shell-fix-check/)

## English

**Discover PHP services, collect version evidence and prepare remediation for PHP2Shell.** Two independent scripts: Bash for Linux and PowerShell for Windows. Run from one machine inside an authorized network and receive local HTML and CSV reports.

No Ansible, permanent agents or installation on target servers. **Fix Check performs assessment; it does not apply patches.** Use it only on systems you are authorized to audit.

### 1. Download your script

| Your computer | Download |
| --- | --- |
| Windows | [PHP-Audit.ps1](https://github.com/Kernovix/php2shell-fix-check/raw/refs/heads/main/PHP-Audit.ps1) |
| Linux | [php_audit.sh](https://github.com/Kernovix/php2shell-fix-check/raw/refs/heads/main/php_audit.sh) |

Save the file in a folder on your computer. You only need the script for your operating system.

### 2. Run it

Replace `192.168.1.0/24` with your authorized IPs or network. The final argument, `en`, selects English reports; use `pt` for Portuguese reports. The documentation language and report language are independent.

**Windows:** open PowerShell in the script's folder and run:

```powershell
.\PHP-Audit.ps1 '192.168.1.0/24' en
```

Alternatively, open `PHP-Audit.ps1` in **PowerShell ISE**, press **F5**, and answer the two questions: targets and report language. Follow your organization's script execution policy.

**Linux:** open a terminal in the script's folder and run:

```bash
bash php_audit.sh '192.168.1.0/24' en
```

With no arguments in an interactive terminal, both scripts ask for targets and language. No code editing is needed. Non-interactive runs default to Portuguese unless you specify `en`.

**What can I put in the target field?**

| Scope | Example |
| --- | --- |
| One server | `'192.168.1.10'` |
| Several servers | `'192.168.1.10,192.168.1.20'` |
| An IP range | `'192.168.1.10-30'` or `'192.168.1.10-192.168.1.30'` |
| A subnet | `'192.168.1.0/24'` |
| A DNS hostname (HTTP Host and TLS SNI) | `'app.example.com'` |
| A virtual host at a specific IPv4 address | `'app.example.com=192.0.2.10'` |

DNS names select the requested virtual host and send its name in TLS SNI. `name=IP` pins the **web connection** to that IP without changing DNS or the hosts file. SSH/WinRM still uses the hostname and its existing name resolution. Only the selected IPv4 address is checked; other DNS addresses and unlisted virtual hosts are not enumerated.

### 3. Open the report

When the audit finishes, the script prints the report location. Open **`report.html`** inside `reports/<timestamp>/`, next to your script. A **`report.csv`** is saved in the same folder for Excel (UTF-8, comma delimiter).

The HTML report separates **web services and candidate ports**, **local/remote inventory**, **connection/collection errors**, and a collapsed section for **targets without a detected web service**. Open TCP ports are candidates; only an HTTP response confirms a web service. Statistics show targets checked, candidate ports, HTTP responses, responding targets, PHP evidence and errors.

**Discovery and vulnerability are separate columns.** Discovery distinguishes no detected web service, PHP not identified, PHP hints without a version, a PHP version, and connection errors. Select **View details** for the IP, hostname, application evidence, runtime, packages, HTTP status, TLS validation, sanitized technical error and unfollowed redirect. Confidence describes the PHP evidence, not whether the host is safe.

The CSV has the same findings, with stable `DiscoveryCode` and `VulnerabilityCode` columns for filtering. Unknown values are empty, not `'-`; spreadsheet formula protection is retained. Both reports use your selected language and the CSV includes a UTF-8 BOM for Excel.

One target can produce several observations: one per candidate service or inventory component. The result-row count is not the number of machines.

| Status | What it means |
| --- | --- |
| **POTENTIALLY VULNERABLE** | The version needs investigation. Check vendor backports and the web runtime before concluding it is vulnerable. |
| **INCONCLUSIVE** | Evidence is missing or insufficient. This never means safe. |
| **VULNERABLE (CONFIRMED)** | Reviewed evidence linked to the web runtime confirms that at least one CVE affects it. |
| **FIXED** | Reviewed evidence matching the web runtime and both CVEs confirms a fix for that observation; it does not certify the whole server. |

**A CLI version or HTTP banner alone cannot prove that a website is fixed. No PHP detection or no response does not prove the absence of a vulnerability.** The scripts do not automatically certify vendor backports. Keep reports and target lists private.

Confirmed states require optional reviewed TSV evidence (`--evidence` / `-EvidenceFile`), matched to the target, service, runtime, version and package/build. Evidence must identify the reviewer and an HTTPS advisory, cover the individual CVE states and be reviewed on the current UTC date. A backport under an older PHP version also needs an exact package/build. The built-in self-test exercises accepted and rejected confirmations with fictional evidence.

### What the scripts check

- TCP ports **80, 443, 8080 and 8443**, followed by a bounded HTTP `GET /`. Additional ports, timeouts and concurrency are configurable.
- PHP and application hints: **WordPress, Nextcloud, Joomla, Drupal, Laravel, Magento, MediaWiki, phpBB and WHMCS**. Fingerprints are indicators, not proof.
- Optional **local inventory**, or remote inventory through existing authorized access: Linux via **SSH**, Windows via **PowerShell Remoting / WinRM**. Collects hostname, OS, PHP executables/processes, services and package evidence, subject to permissions. Windows also checks accessible IIS FastCGI handlers and common PHP/XAMPP/Wamp/Laragon locations; Linux checks accessible installed runtimes, packages and process executable paths.
- **PHP-FPM, Apache/mod_php, Nginx, IIS and Docker metadata**, where applicable and accessible. Docker metadata does not establish the PHP version inside a container.

Failures on individual targets do not stop the remaining audit. Public exposure can be declared by the technician; the scripts do not test reachability from the Internet.

### Requirements and optional settings

<details>
<summary>Minimum requirements and default settings</summary>

- **Linux:** Bash 3.2+, curl 7.29+ with HTTPS, coreutils (including `timeout` and `mktemp`), awk, grep and sed. No new runtime dependencies are needed.
- **Windows:** Windows PowerShell 5.1 with .NET Framework 4.7.2+, or PowerShell 7 on Windows.
- **Defaults:** ports `80,443,8080,8443`; TLS on `443,8443`; **8** concurrent workers; maximum **4,096 IPv4 addresses**.
- **IPv4 and DNS hostnames.** `/31` and `/32` include every address; larger subnets omit network and broadcast addresses. IPv6 is not supported.

</details>

<details>
<summary>Change ports, concurrency or declared public exposure</summary>

| Setting | Bash | PowerShell |
| --- | --- | --- |
| Ports | `--ports 80,443,8000` | `-Ports 80,443,8000` |
| TLS ports | `--tls-ports 443,8443` | `-TlsPorts 443,8443` |
| Concurrent workers | `--concurrency 4` | `-Concurrency 4` |
| Network timeout, seconds | `--timeout 5` | `-TimeoutSeconds 5` |
| Known public exposure | `--public-targets '192.168.1.10'` | `-PublicTargets '192.168.1.10'` |

Append the options to your normal command. Example:

```bash
bash php_audit.sh '192.168.1.0/24' en --ports 80,443,8000 --concurrency 4
```

```powershell
.\PHP-Audit.ps1 '192.168.1.0/24' en -Ports 80,443,8000 -Concurrency 4
```

Public exposure is technician-reported, not verified from the Internet.

</details>

<details>
<summary>Inventory the computer running the script</summary>

No network targets or remote credentials are required for local inventory:

```bash
bash php_audit.sh en --local-inventory
```

```powershell
.\PHP-Audit.ps1 -LocalInventory -Language en
```

You can combine local inventory with normal targets. It reads accessible metadata; it does not scan the entire filesystem, enter containers, restart workers or elevate privileges. A local CLI/file version alone does not prove that a web runtime is fixed.

</details>

<details>
<summary>Understand HTTPS errors and certificates</summary>

TLS certificate validation is **on by default**, including for DNS/SNI targets. Certificate trust/name/validity errors, handshake failures, timeouts, TCP/DNS problems and incomplete responses retain sanitized diagnostic details. Redirects are reported but never followed; credentials, query strings and fragments are removed from reported redirect URLs. Cookies are used only by name for fingerprinting, not recorded by value.

For an explicitly authorized diagnostic check of a known service with an invalid certificate, append Bash `--insecure-tls` or PowerShell `-InsecureTls`. This is never automatic: reports show `DISABLED` TLS validation and low PHP-evidence confidence. It affects web requests only, not SSH or WinRM. Prefer fixing the certificate trust chain or supplying the correct hostname.

</details>

<details>
<summary>Enable optional SSH or WinRM inventory</summary>

For **Linux targets**, use Bash with an existing SSH key or ssh-agent and verified host keys:

```bash
bash php_audit.sh '192.168.1.0/24' en --ssh-user auditor
```

For **Windows targets**, use PowerShell with existing authorized WinRM access:

```powershell
.\PHP-Audit.ps1 '192.168.1.0/24' en -Credential (Get-Credential) -UseSSL
```

There are no SSH password or sudo prompts. WinRM uses your existing configuration; the script does not change authentication, firewall rules or TrustedHosts. `-WinRMPort 0` (the default) omits `Port` from `Invoke-Command`, so WinRM chooses its normal HTTP/HTTPS port. Specify `-WinRMPort 5999` only for a custom port. HTTP discovery is OS-independent. Missing permissions can leave inventory partial or inconclusive.

</details>

### Try it without scanning a network

The built-in self-test checks version and classification logic, then generates clearly marked simulated HTML and CSV reports. It makes no network requests.

```bash
bash php_audit.sh --self-test en
```

```powershell
.\PHP-Audit.ps1 -SelfTest -Language en
```

Automated regression tests are in [`tests/`](tests/). On a development machine with **Node.js 18+ and OpenSSL 1.1.1+**, run `node tests/run-tests.cjs`. They create temporary local HTTP/TLS fixtures and fictional reports; no client network is scanned and no certificates are installed. Test dependencies are not required to run either audit script. GitHub Actions tests Windows PowerShell 5.1, PowerShell 7, Linux Bash and Bash 3.2 compatibility.

### PHP fix reference

These are the first upstream releases used by the scripts as the reference for both CVEs:

| PHP branch | First fixed release |
| --- | --- |
| 8.2 | **8.2.35** |
| 8.3 | **8.3.36** |
| 8.4 | **8.4.27** |
| 8.5 | **8.5.12** |

Use the fixed release or a newer stable release in the same branch. For **PHP 8.1 and earlier**, check vendor/LTS support and backports or migrate to a supported branch.

Debian, Ubuntu and RHEL packages may carry fixes under older upstream version numbers. Check the vendor's advisory for **both CVEs** and verify the runtime actually serving web requests. An application update alone is not proof that its PHP runtime has been fixed.

### Limits and authorized use

Read-only inventory: TCP checks and bounded `GET /` requests. No exploits, DoS tests, WAF bypass, installation, updates or restarts. Passwords, cookie values and HTTP response bodies are not included in reports.

Only explicitly requested DNS/SNI sites are selected. Other virtual hosts, proxies, backends, paths, hidden installations and restricted containers may be missed. Agree your authorized scope before running the audit. **Insufficient evidence remains INCONCLUSIVE.**

### Sources

[PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5) · [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) · [Debian](https://security-tracker.debian.org/tracker/CVE-2026-109618) · [Ubuntu](https://ubuntu.com/security/CVE-2026-109618) · [Red Hat](https://access.redhat.com/security/cve/cve-2026-109618)

---

[Português →](README.pt.md#português) · [Back to the top ↑](#php2shell-fix-check)
