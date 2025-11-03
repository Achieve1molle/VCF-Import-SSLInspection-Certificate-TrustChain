# VCF Trusted Certificate Import UI

A lightweight WPF tool to import **trusted SSL certificate chains** into **VMware Cloud Foundation** components:

- **vCenter** (PowerCLI)
- **NSX** (REST API)
- **SDDC Manager** (SDK)
- **VCF Installer** (Installer API)
- **VCF Operations** (placeholder / informational)

The tool creates a timestamped run folder per execution, writes a **clean log file** (no transcript, no verbose spam) and updates an on‑screen **UI Log** in real time.

---

##  Features

- **Interactive UI** to select a certificate chain and manage target endpoints.
- **Idempotent trust import** to vCenter, NSX, and SDDC Manager / Installer.
- **Outputs you can ship:**
  - `Results.csv` – per-host step status (Host, Type, Step, Status, Message)
  - `ChainDebug.txt` – subjects, issuers, CA flags, validity, thumbprints
  - `ExpectedCAs.txt` – CA thumbprints and normalized subject DNs
  - `SSLInspect-*.log` – structured run log (also shown in the UI log pane)
- **No‑Verbose mode** – all verbose is disabled; no “Importing/Exporting cmdlet” noise.
- **Prereq checks & one‑click installs** for PowerCLI and VCF.PowerCLI.

---

##  Prerequisites

- **PowerShell 7+** (`pwsh.exe`)
- **.NET / WPF** available on the host (installed with PS7 on Windows)
- **Network connectivity** to targeted components
- **Credentials** with sufficient permissions on:
  - vCenter (administrator privileges)
  - NSX (admin)
  - SDDC Manager / Installer (appropriate API roles)
- **Modules** (installable from the UI if missing):
  - `VMware.PowerCLI`
  - `VCF.PowerCLI` (includes VMware VCF SDK bindings)

> Certificate chain input formats: **.p7b/.p7c, .cer/.crt, .pem** (multi‑PEM supported).

---

##  Getting Started

1. Copy `VCF9TrustedCert.ps1` to a working folder (e.g., `C:\Staging`).
2. Launch with PowerShell 7:
   ```powershell
   pwsh -ExecutionPolicy Bypass -File .\VCF9TrustedCert.ps1
   ```
   The script self‑signs and relaunches in **STA** (required for WPF).

3. In **Prerequisites**:
   - Click **Recheck** to verify.
   - Use **Install VMware.PowerCLI** / **Install VCF.PowerCLI** if required.

4. In **Certificate Chain**, click **Browse…** and select your CA chain file.

5. In **Targets**:
   - **Add Row** and fill **Host**, **Username**, **Password**, **Type**.
   - Port defaults to **443** for all supported types.

6. Click **Test Connection** (optional) to validate reachability/auth.

7. Click **Run** to import the trusted chain to each target.

8. Click **Open Reports** to open the run folder with all outputs.

---

##  UI Guide

- **Prerequisites**  
  Reports PS7/WPF presence, module availability, and OpenSSH (optional).

- **Certificate Chain**  
  Path to your chain file. Supports P7B/PEM/CER/CRT.

- **Targets Grid**  
  Columns: **Host**, **Username**, **Password**, **Port**, **Type**  
  Supported **Type** values:
  - `vCenter`
  - `NSX`
  - `SDDC-Manager`
  - `VCF-Installer`
  - `VCF-Operations` (informational only; no trust import API)

- **Per‑Host Results**  
  Real‑time rows for each action (Test / Install).

- **Log (right pane)**  
  Real‑time structured log; mirrors the `SSLInspect-*.log` file.

- **Actions Bar**  
  - **Open Reports**: opens the current run directory  
  - **Test Connection**: quick auth/API reachability checks  
  - **Run**: execute trust import  
  - **Close**: exit the UI

---

##  Target Behavior

| Type            | Mechanism                                 | Notes |
|-----------------|-------------------------------------------|-------|
| vCenter         | PowerCLI `Add-VITrustedCertificate`       | Connects with provided creds; imports chain to vCenter trust |
| NSX             | REST `POST /api/v1/trust-management/certificates?action=import`  | Imports a CA bundle object; idempotent (409 == already present) |
| SDDC-Manager    | VCF SDK `POST /v1/sddc-manager/trusted-certificates` | Requires VCF SDK modules |
| VCF-Installer   | Installer API `POST /v1/sddc-manager/trusted-certificates` with token | Uses token from `POST /v1/tokens` |
| VCF-Operations  | Not implemented (no published trust API)  | Displays informational row only |

> The tool auto‑detects **Installer mode** on SDDC Manager endpoints and routes to the **Installer API** when applicable.

---

## Outputs

All artifacts are placed under a timestamped folder:

SSLInspect-Run-YYYYMMDD-HHMMSS\
  ├─ SSLInspect-YYYYMMDD-HHMMSS.log  # structured log (no verbose spam)
  ├─ Results.csv                      # Host, Type, Step, Status, Message
  ├─ ChainDebug.txt                   # chain subjects/issuers/validity/CA/thumbprints
  └─ ExpectedCAs.txt                  # CA thumbprints + normalized subject DNs


---

##  Sample `SSLInspect-Targets.json`

You can prepare targets and load them via **Load Targets**:

json
[
  {
    "Host": "vcsa80.corp.example.com",
    "Username": "administrator@vsphere.local",
    "Port": 443,
    "Type": "vCenter"
  },
  {
    "Host": "10.10.50.253",
    "Username": "admin@local",
    "Port": 443,
    "Type": "VCF-Installer"
  }
]
```

---

##  Security Notes

- Passwords are entered in a **WPF PasswordBox** and kept in‑memory only for the current run.
- Logs avoid including secrets. Hostnames, status codes, and error messages are recorded.
- The script uses **HTTPS** endpoints with `-SkipCertificateCheck` only for bootstrapping the trust import operation itself.

---

##  Troubleshooting

- **UI log blank or not updating**
  - Ensure you’re running in **PowerShell 7+** and that the window launched (STA).  
  - The right pane should show:
    
    ==== SSLInspect UI started ====
    Run folder: <path>
   
  - If not, re‑launch:  
    `pwsh -ExecutionPolicy Bypass -File .\VCF9TrustedCert.ps1`

- **“Prerequisites not met”**
  - Click the **Install** buttons under **Prerequisites**.
  - Recheck after installation.

- **vCenter step fails**
  - Verify credentials and network reachability (443).
  - Confirm that **VMware.PowerCLI** imported successfully.

- **SDDC/Installer 409 / “already exists”**
  - That’s expected for idempotent imports; the cert is already trusted.

- **Chain parsing errors**
  - For PEM, ensure it contains one or more blocks:
   
    -----BEGIN CERTIFICATE-----
    
    -----END CERTIFICATE-----
  
  - For P7B/P7C, ensure it’s a valid PKCS#7 chain file.

---

##  Design Choices (Why it’s stable now)

- **No Transcript**: avoids file lock conflicts and transcript spam.
- **No Verbose**: removes “Importing/Exporting cmdlet” noise entirely.
- **Deterministic UI logging**: sync Dispatcher appends for the first burst of lines, then async.

---

##  Versioning & Maintenance

- Script: `VCF9TrustedCert.ps1`
- Suggested version tag: `v1.0 (No-Verbose + UI log stable)`
- Keep modules current:
  ```powershell
  Update-Module VMware.PowerCLI
  Update-Module VCF.PowerCLI


---

##  FAQ

**Q: Do I need to import server certificates or CA certificates?**  
A: Import the **CA(s)** and/or intermediate chain you want the platform to **trust** for outbound/inbound TLS. The tool accepts chain bundles and imports them where supported.

**Q: Will this change the machine certificate on vCenter?**  
A: No. It **adds trusted certificates** (does not replace the machine cert). Use `Set-VIMachineCertificate` if you need to rotate the vCenter machine cert.

**Q: Can I run headless?**  
A: This build is UI‑centric (WPF). If you need a headless/CLI variant, we can produce a minimal `-Chain` / `-Targets` / `-Mode` wrapper.
