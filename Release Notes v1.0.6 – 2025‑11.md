Executive Summary (v1.0.6 – 2025‑11‑16)
This release delivers a bullet‑proof VCF‑Operations trust import path and cleans up lingering compatibility issues without changing your UI layout. The tool now handles any Posh‑SSH variant and any remote shell baseline (even when SCP/SFTP/base64 aren’t available), while enforcing FQDN integrity across targets. The end result: predictable “Test → Run” success, idempotent imports, and simplified operations for vCenter, NSX, SDDC Manager/Installer, and Aria Ops for VCF (VCF‑Operations).
Highlights

Triple‑fallback upload: SCP → SFTP → inline heredoc (no base64 dependency).
Root‑aware import: avoids sudo when connected as root; uses sudo only when needed.
Literal remote script: prevents PowerShell interpolation of $(date …) and similar.
UI parity: one new prereq label + install button for Posh‑SSH; everything else unchanged.
Hardened defaults: FQDN enforcement and VCF‑Operations default user root.


 Release Notes — SSLInspect v1.0.6
Date: 2025‑11‑16
Version: 1.0.6
Scope: Trusted Certificate Import for VCF 9 (vCenter, NSX, SDDC Manager, VCF Installer, VCF‑Operations)
Enhancements


VCF‑Operations Support
VCF 9 Is working towards a standardized Token Based API. The Legacy Aria components are not 100% stable yet. I have fallen back to SSH based push for the Certificate store related to VCF Operations. This is temporary until 9.1 (If stable). OpenSSH cannot handle this so one additional prereq of Posh SSH was added.
SSH‑based truststore update for VCF Ops for VCF 9.
Root‑aware logic (root ⇒ no sudo; non‑root ⇒ sudo -S with password).
Idempotent import via fingerprint‑based alias (sslinspect_<sha1>).
Automatic service restart (vmware-vcops).



Upload Robustness

New Copy-RemoteFileCompat:
SCP (preferred) → SFTP (fallback) → Inline heredoc (final fallback).
Inline path writes PEM text directly—no base64, no extra tools on remote.


Remote Script Reliability

Converted to literal here‑string (single‑quoted) to prevent PowerShell interpolation.
Fixes $(date +%Y%m%d%H%M%S) mis‑expansion and -Date binding errors.
Password injected via token replacement (no PS parsing).



UI & Defaults

Added Posh‑SSH prereq label + Install button.
Enforced FQDN for all targets (blocks IPs).
Default username for VCF‑Operations = root.
Type‑driven defaults auto‑applied in the grid.



Bug Fixes

Resolved $Host collision in PowerShell by renaming parameters/locals (e.g., $hostName, -RemoteHost).
Removed hard dependency on -OperationTimeout (Posh‑SSH compatibility wrapper).
Eliminated reliance on printf/base64 in remote flows.
Fixed inline upload failures on systems without SCP/SFTP/base64.

Known Behavior

Re‑runs may return 409 Already Present from SDDC Manager/Installer for existing certs (expected idempotency).
Requires PowerShell 7+, VMware.PowerCLI, VCF.PowerCLI, and Posh‑SSH.

Outputs

Log: SSLInspect-*.log
Results: Results.csv (per‑host status)
Chain diagnostics: ChainDebug.txt, ExpectedCAs.txt


Technical Changelog (Engineer‑Focused)

Files/Functions refer to VCF9TrustedCert.SS.v1.0.6.ps1.

New / Updated Functions

New-SSHSessionCompat
Detects presence of -OperationTimeout on New-SSHSession; includes it only when supported.
Ensures Posh‑SSH version‑agnostic behavior.



Copy-RemoteFileCompat

Order: Set-SCPFile → Set-SFTPFile → inline heredoc.
Inline fallback writes raw PEM with a unique heredoc token, eliminating the need for base64.
Closes SFTP sessions cleanly (Remove-SFTPSession).



Invoke-VCFOpsTrustedImport

Builds combined PEM locally; uploads via Copy-RemoteFileCompat.
Remote import script is literal (single‑quoted here‑string); uses token replacement to inject the Base64 password only if sudo is needed.
RUN() wrapper executes commands as root or via sudo -S.
Splits chain with awk, dedupes by SHA1 fingerprint, and restarts vmware-vcops.



FQDN Enforcement

Test-IsFqdn, Validate-FqdnOrFail block IPs early with a clear message.
Fixes confusion in multi‑target runs and enforces naming hygiene.



Parameter / Variable Safety

Replaced any positional/param use of Host with RemoteHost in custom functions to avoid the read‑only $Host collision.
Avoids PS variable interpolation by using single‑quoted here‑strings for remote Bash and string .Replace() for secrets.

UI & Prereqs

Prereq Panel: adds lblPoshSSH, btnInstallPosh.
Installers: force install/update on demand; no background changes unless clicked.

Error‑Handling & Logging

Wraps each stage with try/catch and logs root cause messages (e.g., SCP/SFTP missing).
Maintains idempotency messages (e.g., 409 Already Present) as Info rather than Fail.

Compatibility Notes

Works with older Posh‑SSH (no -OperationTimeout, missing SCP/SFTP).
Works on appliances lacking base64 utility (inline heredoc path).
Handles shells where sudo prompts differently by sending -S with a newline‑fed password only when not root.