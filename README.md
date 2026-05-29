# VCF Trusted Certificate Import UI

## Overview

**VCF Trusted Certificate Import UI** is a standalone Windows PowerShell/WinForms tool for importing trusted proxy/root CA certificates into VMware Cloud Foundation **SDDC Manager** and **VCF Installer** appliances.

The current build uses **Posh-SSH ShellStream** to match the working manual workflow:

1. SSH to the appliance as `vcf` or another SSH-enabled user.
2. Open an interactive shell stream.
3. Run `su -` and enter the root password interactively.
4. Run the KB-style `keytool` commands as root.
5. Save validation output from the full `keytool -list -v` command into the reports folder.

This version is focused on the VCF appliance trust-store workflow. It does **not** use the earlier vCenter, NSX, VCF SDK, Installer API, or Auto-Detect Proxy Certificate workflows.

---

## Current Version

```text
VCFTrustedChainTool-ShellStreamUI-v3.0.2.ps1
```

### Major updates in v3.x

- Rebuilt around **interactive Posh-SSH ShellStream** for reliable `su -` elevation.
- Removed non-interactive `su` handling because `Invoke-SSHCommand` does not reliably support the appliance's interactive `su -` workflow.
- Removed **Auto-Detect Proxy Cert**.
- Removed **skip** behavior.
- Import now force-deletes the selected alias if present, then re-imports the selected certificate.
- Import no longer restarts services automatically.
- Added separate **Restart Services** button.
- Added separate **Validate Keystore** button.
- Saves full verbose keystore output from:

```bash
keytool -list -v \
  -keystore /etc/vmware/vcf/commonsvcs/trusted_certificates.store \
  -storepass "$KEY"
```

---

## Supported Targets

This build supports SSH-based VCF appliances:

- `SDDC-Manager`
- `VCF-Installer`

Both target types use the same appliance workflow:

```bash
ssh vcf@<target>
su -
```

Then the tool runs the certificate import commands as root.

---

## Prerequisites

### Workstation prerequisites

- Windows workstation with PowerShell.
- Posh-SSH PowerShell module.
- Network connectivity to the appliance on SSH port `22`.
- The certificate file to import, for example `.cer`, `.crt`, `.pem`, or `.der`.

### Appliance credential prerequisites

The tool needs two passwords per target row:

- **Login Password** for SSH user, usually `vcf`.
- **Root Password for su -**.

Direct root SSH is **not required** and may be disabled in many environments. The tool is designed to SSH as `vcf` and then use interactive `su -`.

---

## UI Guide

### Prerequisites

Shows local workstation readiness:

- PowerShell version.
- Posh-SSH module status.
- VMware.PowerCLI module status.

Buttons:

- **Recheck**: refreshes prerequisite status.
- **Install Posh-SSH**: installs Posh-SSH into the current user scope.
- **Install PowerCLI**: optional; retained for visibility, but PowerCLI is not used by the current ShellStream import workflow.

### Certificate / Alias

Fields:

- **Certificate path**: selected local certificate file.
- **Alias**: alias to use in both trust stores.

Example alias:

```text
DominionProxy1
```

Keytool normalizes aliases to lowercase in listing output, so `DominionProxy1` usually appears as:

```text
Alias name: dominionproxy1
```

### Targets

Target grid columns:

- **Host (FQDN/IP)**
- **Type**: `SDDC-Manager` or `VCF-Installer`
- **Login Username**: usually `vcf`
- **Login Password**
- **Root Password for su -**
- **Port**: usually `22`

Passwords are not saved to JSON target files.

### Results

Shows per-target status for:

- Test Login
- Import
- Validate
- Restart

### Log

Shows the live structured log and includes an **Open Log** button.

### Actions

- **Browse**: choose a reports folder.
- **Test Login**: tests SSH login only.
- **Import Cert**: imports the selected certificate and validates the alias. Does **not** restart services.
- **Validate Keystore**: runs the full keystore validation and writes the keytool report.
- **Restart Services**: runs the SDDC Manager restart script on demand.
- **Close**: exits the UI.

---

## Import Workflow

When **Import Cert** is clicked, the tool performs the following steps for each target row.

### 1. SSH and elevate

```bash
ssh vcf@<target>
su -
```

The `su -` interaction is handled through Posh-SSH ShellStream so the root password prompt is handled like a real interactive shell.

### 2. Upload certificate

The selected local certificate is normalized to PEM if needed and uploaded to `/tmp`:

```bash
/tmp/vcftrust-<alias>.pem
```

### 3. Read the commonsvcs keystore password

```bash
KEY=$(cat /etc/vmware/vcf/commonsvcs/trusted_certificates.key)
```

### 4. Force re-import into commonsvcs trust store

If the alias exists, the tool deletes it first. Missing aliases are ignored.

```bash
keytool -delete \
  -alias "$ALIAS" \
  -keystore /etc/vmware/vcf/commonsvcs/trusted_certificates.store \
  -storepass "$KEY" >/dev/null 2>&1 || true

printf 'yes\n' | keytool -importcert \
  -alias "$ALIAS" \
  -file "$CERT" \
  -keystore /etc/vmware/vcf/commonsvcs/trusted_certificates.store \
  -storepass "$KEY"
```

### 5. Force re-import into Java cacerts

If the alias exists, the tool deletes it first. Missing aliases are ignored.

```bash
keytool -delete \
  -alias "$ALIAS" \
  -keystore /etc/alternatives/jre/lib/security/cacerts \
  -storepass changeit >/dev/null 2>&1 || true

printf 'yes\n' | keytool -importcert \
  -alias "$ALIAS" \
  -file "$CERT" \
  -keystore /etc/alternatives/jre/lib/security/cacerts \
  -storepass changeit
```

### 6. Validate alias exists

```bash
keytool -list \
  -keystore /etc/vmware/vcf/commonsvcs/trusted_certificates.store \
  -storepass "$KEY" \
  -alias "$ALIAS"
```

If this alias validation fails, the UI marks the target as failed.

### 7. Save full keystore report

The tool runs:

```bash
keytool -list -v \
  -keystore /etc/vmware/vcf/commonsvcs/trusted_certificates.store \
  -storepass "$KEY"
```

The full output is saved in the run folder as:

```text
KeytoolList-<host>-<alias>.txt
```

---

## Restart Workflow

Restart is intentionally separate from import.

This allows importing several certificates one after another, then restarting services once.

When **Restart Services** is clicked, the tool runs:

```bash
printf 'y\n' | /opt/vmware/vcf/operationsmanager/scripts/cli/sddcmanager_restart_services.sh
```

Restart output is saved as:

```text
RestartServices-<host>.txt
```

---

## Validate Keystore Workflow

When **Validate Keystore** is clicked, the tool runs:

```bash
KEY=$(cat /etc/vmware/vcf/commonsvcs/trusted_certificates.key)

keytool -list \
  -keystore /etc/vmware/vcf/commonsvcs/trusted_certificates.store \
  -storepass "$KEY" \
  -alias "$ALIAS"

keytool -list -v \
  -keystore /etc/vmware/vcf/commonsvcs/trusted_certificates.store \
  -storepass "$KEY"
```

The full verbose keystore output is saved as:

```text
KeytoolList-<host>-<alias>.txt
```

---

## Reports and Output Files

Every launch creates a timestamped run folder:

```text
VCFTrust-Run-YYYYMMDD-HHMMSS
```

Common files include:

```text
VCFTrust-YYYYMMDD-HHMMSS.log
Results.csv
RemediationReport.html
InitialShellOutput-<host>.txt
FullShellOutput-Import-<host>-<alias>.txt
KeytoolList-<host>-<alias>.txt
RestartServices-<host>.txt
NormalizedCertificate-<guid>.pem
```

### Important report files

#### Results.csv

Per-target action results:

```text
Host,Type,Step,Status,Message
```

#### KeytoolList-<host>-<alias>.txt

The most important validation artifact. This file contains the full verbose output from:

```bash
keytool -list -v \
  -keystore /etc/vmware/vcf/commonsvcs/trusted_certificates.store \
  -storepass "$KEY"
```

Use this file to confirm the imported alias and certificate details.

---

## Target JSON Example

You can save and load target lists. Passwords are intentionally not saved.

```json
[
  {
    "TargetName": "pod01sddc01.corp.example.com",
    "Type": "SDDC-Manager",
    "Username": "vcf",
    "Port": 22
  },
  {
    "TargetName": "pod01vcf9installer.corp.example.com",
    "Type": "VCF-Installer",
    "Username": "vcf",
    "Port": 22
  }
]
```

After loading JSON, re-enter:

- Login Password
- Root Password for `su -`

---

## Recommended Usage

### Import one or more certificates

1. Launch the UI.
2. Select a certificate file.
3. Enter an alias.
4. Add or load target rows.
5. Enter SSH and root passwords.
6. Click **Test Login**.
7. Click **Import Cert**.
8. Change certificate and/or alias if needed.
9. Click **Import Cert** again for additional certificates.
10. Click **Restart Services** once after all desired imports.
11. Click **Validate Keystore** to generate a fresh verbose keytool report.

### Suggested alias convention

Use simple, meaningful aliases without spaces:

```text
DominionProxy1
VCFSSLPROXY
CorporateRootCA
```

---

## Security Notes

- Passwords are held only in memory during the UI session.
- Passwords are not written to target JSON files.
- Logs redact the SSH and root passwords.
- The full ShellStream output is saved for troubleshooting, with known secrets redacted.
- The certificate file is copied to `/tmp` on the target as part of the import workflow.

---

## Troubleshooting

### Test Login passes but Import fails at su

Confirm the same credentials work manually:

```bash
ssh vcf@<target>
su -
```

If manual `su -` fails, the UI import will also fail.

### Alias not found after import

Open the generated file:

```text
KeytoolList-<host>-<alias>.txt
```

Search for:

```text
Alias name: <alias-lowercase>
```

Keytool often displays aliases in lowercase.

### Import appears successful but application behavior did not change

Run **Restart Services** after completing imports:

```bash
/opt/vmware/vcf/operationsmanager/scripts/cli/sddcmanager_restart_services.sh
```

The UI does not restart services automatically during import.

### Need to import multiple certs

Import each certificate separately. Use a unique alias for each certificate. Restart services once after all imports are complete.

### Posh-SSH missing

Use the **Install Posh-SSH** button or run:

```powershell
Install-Module Posh-SSH -Scope CurrentUser
```

---

## Removed or Deprecated Functionality

The previous README described earlier functionality that is no longer part of this version:

- vCenter trust import through PowerCLI.
- NSX trust import through REST API.
- VCF SDK / Installer API trust import.
- VCF Operations placeholder.
- Auto-detect proxy certificate.
- Idempotent skip behavior.
- Automatic restart during import.

This version focuses only on the tested ShellStream appliance workflow.

---

## Versioning

```text
Script: VCFTrustedChainTool-ShellStreamUI-v3.0.2.ps1
Version: 3.0.2-shellstream-ui
```

---

## FAQ

### Do I need root SSH enabled?

No. The tool is designed to SSH as `vcf` and then run interactive `su -` through ShellStream.

### Does Import Cert restart services?

No. Restart is intentionally separate. Use **Restart Services** when ready.

### Can I import multiple certificates?

Yes. Import one certificate at a time with an appropriate alias. Restart services once after all imports are complete.

### How do I verify the certificate was imported?

Use **Validate Keystore** and open the generated `KeytoolList-<host>-<alias>.txt` file. Search for the alias and verify the owner, issuer, serial number, and fingerprints.

### Why does the alias appear lowercase?

Keytool commonly displays aliases in lowercase. For example, `DominionProxy1` may appear as `dominionproxy1`.
****
