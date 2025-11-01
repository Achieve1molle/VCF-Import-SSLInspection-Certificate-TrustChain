# SSLChain (aka “SSLInspect”)

Automate deploying a trusted root certificate **chain** across VMware and Linux targets—via a Windows WPF UI or a non‑interactive CLI. The tool normalizes input chains (PEM/CRT/CER/P7B), imports trust on vCenter over HTTPS, updates trust on SSH targets (NSX, SDDC Manager, VCF Ops, RHEL, or generic Linux), and verifies outbound TLS to a configurable URL (default: `https://depot.broadcom.com`). It also produces timestamped run folders and a CSV of per‑host results.  

> **Note on naming**: The script’s internal logs/folders use “SSLChain”, while your file name may be “SSLInspect”. You can keep the repo name either way; the docs use **SSLChain** for consistency.

---

## Features

- **Two modes**  
  - **WPF UI (STA)**: rich grid to manage targets, per‑row credentials, live logs, and one‑click run/test.  
  - **CLI**: feed a CSV and run headless in automation.  
- **Certificate chain handling**  
  - Accepts `PEM/CRT/CER/P7B`; converts DER/PKCS#7 to PEM automatically (remotely too).  
- **vCenter (8.0U2c+/9.x)**  
  - Imports trusted root **via HTTPS API** (tries `/api/session` then `/rest`), with detailed error capture.  
- **SSH targets** (OpenSSH or Posh‑SSH fallback)  
  - **SDDC Manager**: imports into `commonsvcs` store and Java cacerts.  
  - **VCF Operations**: updates Java `cacerts`.  
  - **NSX**: calls `trust-management` API to import a CA (credentials passed over the secure SSH channel).  
  - **RHEL/Generic Linux**: updates OS trust (anchors + `update-ca-trust`) and Java `cacerts` when available.  
- **Guidance-only targets**  
  - **OpenShift** and **TMC (self-managed)**: emits actionable `oc`/`kubectl` snippets (no SSH needed).  
- **TLS egress probe**  
  - Post‑install `curl -I` to a configurable URL/port; success recorded per host.  
- **Persistence & reporting**  
  - Persists settings in `SSLInspect.config.json`; writes per‑run folders and `Install_Results.csv`; rolling logfile.

---

## Screens & Workflow (UI)

1. **Select certificate chain** (`.cer`, `.crt`, `.pem`, or `.p7b`).
2. **Set egress probe URL/port** (defaults to Broadcom Depot over 443).
3. **Add targets** (Host, Username, Password, Port, Type).  
   - Save/Load targets to JSON (passwords are never saved).  
4. **Test Connection**: checks vCenter API or SSH reachability & rudimentary product detection.  
5. **Run**: performs per‑host actions, logs results, and writes a CSV report.

---

## Quick Start

### Prerequisites

- **Windows** host with **PowerShell 7+** (UI requires WPF/.NET Desktop).  
- **OpenSSH client** (`ssh`/`scp`) or the script will install/load **Posh‑SSH** for password-based SSH.  
- Remote Linux targets need `sudo` and (ideally) `openssl` for on-box chain normalization.

### Run (UI)

powershell
pwsh -File .\SSLChain.ps1
