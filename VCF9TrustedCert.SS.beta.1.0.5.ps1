<#
.SYNOPSIS
Normalize, and Import Trusted Certificate UI Tool for VMware Cloud Foundation 9 environments.

.DESCRIPTION
Provides a WPF-based interface to import trusted SSL certificate chains into
VCF components (vCenter, NSX, SDDC Manager, VCF Installer, VCF Operations).
Generates a run folder with logs, CSV results, and certificate analysis files.
Supports .p7b/.p7c, .cer/.crt, and .pem formats.

.CAPABILITIES
- Interactive UI for certificate chain selection and target management.
- Imports trusted certificates into:
    * vCenter (via PowerCLI)
    * NSX (via REST API)
    * SDDC Manager (via SDK or Installer API)
- Creates detailed outputs:
    * Results.csv (per-host status)
    * ChainDebug.txt (certificate details)
    * ExpectedCAs.txt (CA thumbprints and normalized DNs)
- Real-time UI log and file logging (no transcript, no verbose spam).
- Handles prerequisites check and optional module installation.

.NOTES
Author: 		Michael Molle
Version: 		BETA 1.0.5
Signing:		Self-Signed for Beta versions
Execution Policy: 	Requires PowerShell 7+
UI Framework: 		WPF
Logging: 		UI pane + UTF-8 log file in run folder
Verbose: 		Disabled globally for clean output

.PREREQUISITES
- PowerShell 7 or later
- .NET/WPF available on host
- VMware.PowerCLI and VCF.PowerCLI modules installed (can install via UI)
- Network connectivity to target components
- Administrative credentials for vCenter, NSX, and VCF services
#>

[CmdletBinding()]
param(
    [switch]$NoRelaunch,
    [switch]$SignedOk,
    [switch]$NoAutoSign
)

# --- Global preferences ---
$VerbosePreference      = 'SilentlyContinue'    # disable all Verbose
$InformationPreference  = 'Continue'
$ProgressPreference     = 'SilentlyContinue'

# --- Self-sign & STA relaunch (convenience) ---
function Ensure-SelfSigned {
    param([string]$TargetPath)
    try { $sig = Get-AuthenticodeSignature -FilePath $TargetPath -ErrorAction SilentlyContinue } catch { $sig = $null }
    if ($sig -and $sig.Status -eq 'Valid') { return $false }
    Write-Host "[SelfSign] Creating/trusting a local code-signing certificate and signing the script..."
    $subject = "CN=SSLInspect Local Code Signing ($env:USERNAME@$env:COMPUTERNAME)"
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -like "CN=SSLInspect Local Code Signing*" } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert `
                -Subject $subject `
                -CertStoreLocation 'Cert:\CurrentUser\My' `
                -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
                -KeyExportPolicy Exportable `
                -NotAfter (Get-Date).AddYears(5)
    }
    try { $null = $cert | Copy-Item -Destination 'Cert:\CurrentUser\Root' -Force -ErrorAction SilentlyContinue } catch {}
    try { $null = $cert | Copy-Item -Destination 'Cert:\CurrentUser\TrustedPublisher' -Force -ErrorAction SilentlyContinue } catch {}
    $null = Set-AuthenticodeSignature -FilePath $TargetPath -Certificate $cert -ErrorAction Stop
    Write-Host "[SelfSign] Script signed."
    return $true
}
try { $pwsh = (Get-Process -Id $PID).Path } catch { $pwsh = $null }
if (-not $pwsh) { $pwsh = "pwsh.exe" }
if (-not $NoAutoSign -and -not $SignedOk) {
    $didSign = Ensure-SelfSigned -TargetPath $PSCommandPath
    & $pwsh -NoProfile -ExecutionPolicy Bypass -STA -File "$PSCommandPath" -SignedOk -NoRelaunch
    exit $LASTEXITCODE
}
if (-not $NoRelaunch) {
    if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        & $pwsh -NoProfile -ExecutionPolicy Bypass -STA -File "$PSCommandPath" -NoRelaunch -SignedOk
        exit $LASTEXITCODE
    }
}

# --- Globals & Logging ---
$script:ReportsBase   = (Get-Location).Path
$script:RunDir        = $null
$Global:LogFile       = $null
$script:LogWarmupSync = 50
$script:logQueue      = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

function New-RunDir {
    param([string]$Base)
    if ([string]::IsNullOrWhiteSpace($Base) -or -not (Test-Path $Base)) { $Base = (Get-Location).Path }
    $d = Join-Path $Base ("SSLInspect-Run-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    $Global:LogFile = Join-Path $d ("SSLInspect-" + ((Get-Date).ToString('yyyyMMdd-HHmmss')) + ".log")
    '' | Out-File -FilePath $Global:LogFile -Encoding UTF8 -Force
    $script:RunDir = $d
    $script:RunDir
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level='INFO'
    )
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "[$ts][$Level] $Message"

    # 1) File
    try {
        if ($Global:LogFile) {
            Add-Content -Path $Global:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } catch {}

    # 2) UI
    try {
        if ($script:txtLog -and $script:window) {
            if ($script:LogWarmupSync -gt 0) {
                $script:window.Dispatcher.Invoke([Action]{
                    try { $script:txtLog.AppendText("$line`r`n"); $script:txtLog.ScrollToEnd() } catch {}
                }, [System.Windows.Threading.DispatcherPriority]::Render)
                $script:LogWarmupSync--
            } else {
                $null = $script:window.Dispatcher.BeginInvoke([Action]{
                    try { $script:txtLog.AppendText("$line`r`n"); $script:txtLog.ScrollToEnd() } catch {}
                })
            }
        } else {
            $script:logQueue.Enqueue("$line`r`n")
        }
    } catch {}

    # 3) Console (ok to keep)
    Write-Host $line
}

# --- Cert helpers ---
function Get-CertObjectsFromFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "File not found: $Path" }
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -in '.p7b','.p7c') {
        $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $col.Import($Path)
        return ,@($col)
    }
    if ($ext -in '.cer','.crt') {
        $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path)
        return ,@($x)
    }
    $raw = Get-Content -Path $Path -Raw
    if ($raw -notmatch '-----BEGIN CERTIFICATE-----') { throw "Unsupported certificate text format (no BEGIN CERTIFICATE)." }
    $objs = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
    $buf  = New-Object System.Text.StringBuilder
    foreach ($line in $raw -split "`r?`n") {
        if ($line -match '-----BEGIN CERTIFICATE-----') { $null=$buf.Clear() }
        if ($line.Trim().Length -gt 0) { [void]$buf.AppendLine($line.TrimEnd()) }
        if ($line -match '-----END CERTIFICATE-----') {
            $pem = $buf.ToString()
            $bytes = [Convert]::FromBase64String(($pem -replace '-----.*?-----','' -replace '\s',''))
            $objs.Add( (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($bytes)) ) | Out-Null
        }
    }
    if ($objs.Count -le 0) { throw "PEM parse error: no certificates found." }
    return ,$objs.ToArray()
}
function Convert-CertToPem {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $der = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $b64 = [Convert]::ToBase64String($der, 'InsertLineBreaks')
    return "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
}
function Test-IsCA([System.Security.Cryptography.X509Certificates.X509Certificate2]$x) {
    $isCA = $false
    foreach ($ext in $x.Extensions) {
        if ($ext.Oid.Value -eq '2.5.29.19') {
            $bc = New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension $ext, $false
            if ($bc.CertificateAuthority) { $isCA = $true }; break
        }
    }
    if (-not $isCA -and ($x.Subject -eq $x.Issuer)) { $isCA = $true }
    if (-not $isCA) {
        foreach ($ext in $x.Extensions) {
            if ($ext.Oid.Value -eq '2.5.29.15') {
                try {
                    $ku = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension $ext, $false
                    if ( ($ku.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign) -ne 0) { $isCA = $true }
                } catch {}
                break
            }
        }
    }
    return $isCA
}
function Normalize-DN([string]$dn) {
    if ([string]::IsNullOrWhiteSpace($dn)) { return '' }
    $clean = ($dn -replace '\s+',' ' -replace '\s*,\s*',',').Trim().ToLowerInvariant()
    $parts = $clean.Split(',') | Where-Object { $_ -ne '' } | Sort-Object
    return ($parts -join ',')
}
function Write-ChainDebug {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs,[string]$OutPath)
    $rows = foreach ($x in $Certs) {
        [pscustomobject]@{
            Subject=$x.Subject; Issuer=$x.Issuer; SelfSigned=($x.Subject -eq $x.Issuer)
            IsCA=(Test-IsCA $x); Thumbprint=$x.Thumbprint; NotBefore=$x.NotBefore; NotAfter=$x.NotAfter
        }
    }
    try {
        $rows | Format-Table | Out-String | Set-Content -Path $OutPath -Encoding UTF8
        Write-Log "Chain debug written: $OutPath"
    } catch { Write-Log "Chain debug write failed: $($_.Exception.Message)" 'WARN' }
}
function Get-ExpectedCAsThumbprintsFromObjects([System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs) {
    $tps = New-Object System.Collections.Generic.HashSet[string]
    foreach ($x in $Certs) { if (Test-IsCA $x) { [void]$tps.Add($x.Thumbprint.ToUpperInvariant()) } }
    return $tps
}
function Get-ExpectedCNsFromObjects([System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs) {
    $cns = New-Object System.Collections.Generic.HashSet[string]
    foreach ($x in $Certs) { if ($x.Subject -match 'CN\s*=\s*([^,]+)') { [void]$cns.Add($Matches[1].Trim()) } }
    return $cns
}

# --- PowerCLI / VCF.PowerCLI ---
function Has-PowerCLI { !!(Get-Module -ListAvailable -Name VMware.VimAutomation.Core | Select-Object -First 1) }
function Import-PowerCLIQuiet {
    $mod = Get-Module -ListAvailable -Name VMware.VimAutomation.Core | Select-Object -First 1
    if ($null -eq $mod) { return $false }
    try {
        Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue | Out-Null
        Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        return $true
    } catch { Write-Log "PowerCLI import failed: $($_.Exception.Message)" 'WARN'; return $false }
}
function Has-VCFPowerCLI { !!(Get-Module -ListAvailable -Name VCF.PowerCLI | Select-Object -First 1) }
function Import-VCFPowerCLI {
    try {
        Import-Module VCF.PowerCLI -ErrorAction SilentlyContinue | Out-Null
        Import-Module VMware.Sdk.Vcf.SddcManager -ErrorAction SilentlyContinue | Out-Null
        Import-Module VMware.Sdk.Nsx.Policy -ErrorAction SilentlyContinue | Out-Null
        Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        return $true
    } catch { Write-Log "VCF.PowerCLI import failed: $($_.Exception.Message)" 'WARN'; return $false }
}

# --- SDDC / Installer / NSX (INSTALL ONLY) ---
function Get-VcfInstallerToken {
    param([string]$Fqdn,[string]$User,[string]$Pass)
    $body = @{ username=$User; password=$Pass } | ConvertTo-Json
    Invoke-RestMethod -Uri ("https://{0}/v1/tokens" -f $Fqdn) -Method Post -Body $body -ContentType 'application/json' -SkipCertificateCheck -ErrorAction Stop
}
function Add-VcfInstallerTrustedCert {
    param([string]$Fqdn,[string]$AccessToken,[System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs)
    $hdrs = @{ Authorization = "Bearer $AccessToken"; 'Content-Type'='application/json' }
    $added=0; $skipped=0
    foreach ($x in $Certs) {
        $pem = Convert-CertToPem $x
        $body = @{ certificate=$pem; certificateUsageType='TRUSTED_FOR_OUTBOUND' } | ConvertTo-Json -Compress
        try {
            Invoke-RestMethod -Uri ("https://{0}/v1/sddc-manager/trusted-certificates" -f $Fqdn) -Method Post -Headers $hdrs -Body $body -SkipCertificateCheck -ErrorAction Stop | Out-Null
            $added++
        }
        catch {
            $status=$null; try { $status=[int]$_.Exception.Response.StatusCode } catch {}
            if ($status -eq 409 -or $_.Exception.Message -match '\b409\b') { $skipped++; Write-Log "[$Fqdn] Installer API: certificate already present (409)." }
            else { throw }
        }
    }
    [pscustomobject]@{Added=$added;Skipped=$skipped}
}
function Add-SddcTrustedCertificateSDK {
    param([string]$SddcFqdn,[string]$User,[string]$Pass,[System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs)
    if (-not (Has-VCFPowerCLI) -or -not (Import-VCFPowerCLI)) { throw "VCF.PowerCLI not available." }
    $sd = $null
    try {
        $sec = ConvertTo-SecureString $Pass -AsPlainText -Force
        $sd = Connect-VcfSddcManagerServer -Server $SddcFqdn -User $User -Password $sec -IgnoreInvalidCertificate -NotDefault -ErrorAction Stop
        $op = Get-VcfSddcManagerOperation -Path "/v1/sddc-manager/trusted-certificates" -Method Post | Select-Object -First 1
        if (-not $op) { throw "SDK operation for POST /v1/sddc-manager/trusted-certificates not found." }
        $added=0; $skipped=0
        foreach ($x in $Certs) {
            $pem = Convert-CertToPem $x
            try { $body = [pscustomobject]@{ certificate=$pem; certificateUsageType='TRUSTED_FOR_OUTBOUND' }; & $op.CommandInfo -Body $body | Out-Null; $added++ }
            catch { if ($_.Exception.Message -match '\b409\b' -or $_.Exception.Message -match 'already\s*exists') { $skipped++; Write-Log "[$SddcFqdn] SDDC Manager SDK: certificate already present (skipping)." } else { throw } }
        }
        [pscustomobject]@{Added=$added;Skipped=$skipped}
    } finally { if ($sd) { Disconnect-VcfSddcManagerServer -Server $sd -Force | Out-Null } }
}
function Invoke-NSXCaImport {
    param([string]$Fqdn,[string]$User,[string]$Pass,[System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs)
    $pem = ($Certs | ForEach-Object { Convert-CertToPem $_ }) -join ""
    $json = @{ display_name = ("trusted_ca_{0}" -f (Get-Date -UFormat %s)); pem_encoded = $pem } | ConvertTo-Json -Depth 4
    $pair = "$User`:$Pass"; $b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
    $hdrs = @{ 'Authorization'=("Basic $b64"); 'Content-Type'='application/json' }
    $uri = "https://$Fqdn/api/v1/trust-management/certificates?action=import"
    try { Invoke-RestMethod -Method POST -Uri $uri -Headers $hdrs -SkipCertificateCheck -Body $json -ErrorAction Stop | Out-Null; [pscustomobject]@{Added=1;Skipped=0;Message='Imported CA bundle into NSX trust-management.'} }
    catch {
        $status = $null; try { $status = [int]$_.Exception.Response.StatusCode } catch {}
        if ($status -eq 409 -or $_.Exception.Message -match '\b409\b') { Write-Log "[$Fqdn] NSX API: certificate(s) already present (409)."; [pscustomobject]@{Added=0;Skipped=1;Message='CA bundle already present (idempotent).'} }
        else { throw }
    }
}

# --- Type defaults & normalization ---
function Get-TypeDefaults { param([string]$Type)
    switch ($Type) {
        'vCenter'       { @{ Port = 443; Username = 'administrator@vsphere.local' } }
        'NSX'           { @{ Port = 443; Username = 'admin' } }
        'SDDC-Manager'  { @{ Port = 443; Username = 'administrator@vsphere.local' } }
        'VCF-Installer' { @{ Port = 443; Username = 'admin@local' } }
        'VCF-Operations'{ @{ Port = 443; Username = 'admin' } }
        default         { @{ Port = 443; Username = '' } }
    }
}
function Normalize-TargetType([string]$Type) {
    $t = ($Type ?? '').Trim()
    $t = $t -replace '[\u2010-\u2015]', '-' # unicode dash → ASCII
    switch -Regex ($t.ToLower()) {
        '^vcenter$'                           { 'vCenter'; break }
        '^nsx$'                               { 'NSX'; break }
        '^(sddc[\s\-]?manager)$'              { 'SDDC-Manager'; break }
        '^(vcf[\s\-]?installer)$'             { 'VCF-Installer'; break }
        '^(vcf[\s\-]?(ops|operations))$'      { 'VCF-Operations'; break }
        default                               { $Type }
    }
}
function Apply-TypeDefaults { param([psobject]$Row,[switch]$Force)
    if (-not $Row) { return }
    if ($Row.PSObject.Properties['Type'] -and $Row.Type) { $Row.Type = Normalize-TargetType $Row.Type }
    $defs = Get-TypeDefaults $Row.Type
    if (-not $Row.PSObject.Properties['Port'])     { Add-Member -InputObject $Row -NotePropertyName 'Port' -NotePropertyValue 0 -Force }
    if (-not $Row.PSObject.Properties['Username']) { Add-Member -InputObject $Row -NotePropertyName 'Username' -NotePropertyValue '' -Force }
    if ($Force) { $Row.Port = $defs.Port; $Row.Username = $defs.Username; return }
    $knownDefaults = @('administrator@vsphere.local','admin','admin@local','vcf','')
    if (-not $Row.Port -or $Row.Port -in 22,443) { $Row.Port = $defs.Port }
    if (($Row.Username -in $knownDefaults) -or [string]::IsNullOrWhiteSpace($Row.Username)) { $Row.Username = $defs.Username }
}

# --- WPF UI ---
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase -ErrorAction SilentlyContinue | Out-Null
Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue | Out-Null
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
 xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
 xmlns:sys="clr-namespace:System;assembly=mscorlib"
 Title="Achieve One—Leadership to Adapt—Expertise to Achieve"
 Height="900" Width="1480" MinHeight="760" MinWidth="1240"
 WindowStartupLocation="CenterScreen"
 Background="#0f0f10" Foreground="#f3f3f3">
 <Window.Resources>
  <SolidColorBrush x:Key="Bg" Color="#0f0f10"/>
  <SolidColorBrush x:Key="PanelBg" Color="#1c1c1e"/>
  <SolidColorBrush x:Key="Fg" Color="#f3f3f3"/>
  <SolidColorBrush x:Key="Border" Color="#3a3a3a"/>
  <SolidColorBrush x:Key="HeaderBg" Color="#2a2a2c"/>
  <SolidColorBrush x:Key="SelBg" Color="#3d3d40"/>
  <Style TargetType="GroupBox"><Setter Property="Margin" Value="8"/><Setter Property="Padding" Value="8"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="Background" Value="{StaticResource Bg}"/></Style>
  <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="Margin" Value="8,0,8,6"/></Style>
  <Style TargetType="CheckBox"><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="Margin" Value="4,4,4,4"/></Style>
  <Style TargetType="TextBox"><Setter Property="Margin" Value="8"/><Setter Property="Padding" Value="6"/><Setter Property="Background" Value="{StaticResource PanelBg}"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/></Style>
  <Style TargetType="PasswordBox"><Setter Property="Margin" Value="8"/><Setter Property="Padding" Value="6"/><Setter Property="Background" Value="{StaticResource PanelBg}"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/></Style>
  <Style TargetType="Button"><Setter Property="Margin" Value="8,6,8,6"/><Setter Property="Padding" Value="10,6"/><Setter Property="Background" Value="#2a2a2c"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="BorderBrush" Value="#565656"/></Style>
  <Style TargetType="DataGrid"><Setter Property="Margin" Value="8"/><Setter Property="Background" Value="{StaticResource PanelBg}"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="GridLinesVisibility" Value="All"/><Setter Property="HeadersVisibility" Value="Column"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/><Setter Property="AlternationCount" Value="2"/><Setter Property="RowBackground" Value="#19191b"/><Setter Property="AlternatingRowBackground" Value="#151517"/><Setter Property="HorizontalGridLinesBrush" Value="#303034"/><Setter Property="VerticalGridLinesBrush" Value="#303034"/><Setter Property="SelectionUnit" Value="FullRow"/></Style>
  <Style TargetType="DataGridColumnHeader"><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="Background" Value="{StaticResource HeaderBg}"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
 </Window.Resources>
 <Grid Margin="8">
  <Grid.RowDefinitions>
   <RowDefinition Height="Auto"/>
   <RowDefinition Height="Auto"/>
   <RowDefinition Height="2*"/>
   <RowDefinition Height="1.2*"/>
   <RowDefinition Height="Auto"/>
  </Grid.RowDefinitions>

  <GroupBox Header="Prerequisites" Grid.Row="0">
   <Grid>
    <Grid.ColumnDefinitions>
     <ColumnDefinition Width="2*"/>
     <ColumnDefinition Width="2*"/>
     <ColumnDefinition Width="Auto"/>
     <ColumnDefinition Width="Auto"/>
    </Grid.ColumnDefinitions>
    <Grid Grid.Column="0">
     <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
     <StackPanel Grid.Column="0">
      <TextBlock x:Name="lblPS" Text="PowerShell 7+: (checking…)" />
      <TextBlock x:Name="lblWPF" Text=".NET/WPF: (checking…)" />
      <TextBlock x:Name="lblPCLI" Text="VMware.PowerCLI: (checking…)" />
     </StackPanel>
     <StackPanel Grid.Column="1">
      <TextBlock x:Name="lblVCFP" Text="VCF.PowerCLI: (checking…)" />
      <TextBlock x:Name="lblSDK" Text="SDK Modules (SDDC/NSX): (checking…)" />
      <TextBlock x:Name="lblOpenSSH" Text="OpenSSH client (optional): (checking…)" />
     </StackPanel>
    </Grid>
    <StackPanel Grid.Column="1">
     <TextBlock Text="Installers auto-skip publisher checks and force upgrades (only when you click Install)." />
    </StackPanel>
    <StackPanel Grid.Column="2" Orientation="Vertical" VerticalAlignment="Center">
     <Button x:Name="btnRecheck" Content="Recheck" MinWidth="100"/>
    </StackPanel>
    <StackPanel Grid.Column="3" Orientation="Vertical" VerticalAlignment="Center">
     <Button x:Name="btnInstallPCLI" Content="Install VMware.PowerCLI" MinWidth="170"/>
     <Button x:Name="btnInstallVCF" Content="Install VCF.PowerCLI" MinWidth="170"/>
    </StackPanel>
   </Grid>
  </GroupBox>

  <GroupBox Header="Certificate Chain (CER/CRT/PEM/P7B)" Grid.Row="1">
   <DockPanel LastChildFill="True">
    <TextBox x:Name="txtChain" Margin="8" MinWidth="700"/>
    <Button x:Name="btnBrowseChain" Content="Browse..." DockPanel.Dock="Right"/>
   </DockPanel>
  </GroupBox>

  <GroupBox Header="Targets (vCenter, NSX, SDDC-Manager, VCF-Installer, VCF-Operations)" Grid.Row="2">
   <Grid>
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
    <DockPanel Grid.Row="0" LastChildFill="False" Margin="8,0,8,6">
     <StackPanel Orientation="Horizontal" DockPanel.Dock="Left">
      <Button x:Name="btnAdd" Content="Add Row"/>
      <Button x:Name="btnRemove" Content="Remove Selected"/>
      <Button x:Name="btnLoadTargets" Content="Load Targets"/>
      <Button x:Name="btnSaveTargets" Content="Save Targets"/>
     </StackPanel>
    </DockPanel>
    <DataGrid x:Name="gridTargets" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="False" EnableRowVirtualization="False" EnableColumnVirtualization="False" CanUserAddRows="False">
     <DataGrid.Columns>
      <DataGridTextColumn Header="Host (FQDN/IP)" Width="*"><DataGridTextColumn.Binding><Binding Path="Host" UpdateSourceTrigger="PropertyChanged"/></DataGridTextColumn.Binding></DataGridTextColumn>
      <DataGridTextColumn Header="Username" Width="*"><DataGridTextColumn.Binding><Binding Path="Username" UpdateSourceTrigger="PropertyChanged"/></DataGridTextColumn.Binding></DataGridTextColumn>
      <DataGridTemplateColumn Header="Password" Width="*"><DataGridTemplateColumn.CellTemplate><DataTemplate><PasswordBox Tag="{Binding}" /></DataTemplate></DataGridTemplateColumn.CellTemplate></DataGridTemplateColumn>
      <DataGridTextColumn Header="Port" Width="80"><DataGridTextColumn.Binding><Binding Path="Port" UpdateSourceTrigger="PropertyChanged"/></DataGridTextColumn.Binding></DataGridTextColumn>
      <DataGridComboBoxColumn Header="Type" Width="220">
       <DataGridComboBoxColumn.SelectedItemBinding>
        <Binding Path="Type" UpdateSourceTrigger="PropertyChanged"/>
       </DataGridComboBoxColumn.SelectedItemBinding>
       <DataGridComboBoxColumn.ItemsSource>
        <x:Array Type="{x:Type sys:String}">
         <sys:String>vCenter</sys:String>
         <sys:String>NSX</sys:String>
         <sys:String>SDDC-Manager</sys:String>
         <sys:String>VCF-Installer</sys:String>
         <sys:String>VCF-Operations</sys:String>
        </x:Array>
       </DataGridComboBoxColumn.ItemsSource>
      </DataGridComboBoxColumn>
     </DataGrid.Columns>
    </DataGrid>
   </Grid>
  </GroupBox>

  <Grid Grid.Row="3">
   <Grid.ColumnDefinitions><ColumnDefinition Width="3*"/><ColumnDefinition Width="2*"/></Grid.ColumnDefinitions>
   <GroupBox Header="Per-Host Results" Grid.Column="0">
    <DataGrid x:Name="gridResults" AutoGenerateColumns="False">
     <DataGrid.Columns>
      <DataGridTextColumn Header="Host" Width="*"><DataGridTextColumn.Binding><Binding Path="Host"/></DataGridTextColumn.Binding></DataGridTextColumn>
      <DataGridTextColumn Header="Type" Width="140"><DataGridTextColumn.Binding><Binding Path="Type"/></DataGridTextColumn.Binding></DataGridTextColumn>
      <DataGridTextColumn Header="Step" Width="120"><DataGridTextColumn.Binding><Binding Path="Step"/></DataGridTextColumn.Binding></DataGridTextColumn>
      <DataGridTextColumn Header="Status" Width="110"><DataGridTextColumn.Binding><Binding Path="Status"/></DataGridTextColumn.Binding></DataGridTextColumn>
      <DataGridTextColumn Header="Message" Width="2*"><DataGridTextColumn.Binding><Binding Path="Message"/></DataGridTextColumn.Binding></DataGridTextColumn>
     </DataGrid.Columns>
    </DataGrid>
   </GroupBox>
   <GroupBox Header="Log" Grid.Column="1">
    <DockPanel LastChildFill="True">
     <Button x:Name="btnOpenLog" Content="Open Log" DockPanel.Dock="Top" Margin="8,6,8,0"/>
     <TextBox x:Name="txtLog" AcceptsReturn="True" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Height="340" MaxHeight="360"/>
    </DockPanel>
   </GroupBox>
  </Grid>

  <GroupBox Header="Actions" Grid.Row="4">
   <Grid Margin="8">
    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
    <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Grid.Column="0">
     <TextBlock Text="Reports Path:" Margin="0,0,8,0" VerticalAlignment="Center"/>
     <TextBox x:Name="txtReportsPath" MinWidth="520" IsReadOnly="True"/>
     <Button x:Name="btnBrowseReports" Content="Browse..." Margin="8,0,0,0" MinWidth="110"/>
    </StackPanel>
    <UniformGrid Grid.Column="1" Rows="1" Columns="4" Margin="12,0,0,0" HorizontalAlignment="Right">
     <Button x:Name="btnOpenOut" Content="Open Reports" MinWidth="120"/>
     <Button x:Name="btnTest" Content="Test Connection" MinWidth="140"/>
     <Button x:Name="btnRun" Content="Run" MinWidth="90" IsEnabled="False"/>
     <Button x:Name="btnClose" Content="Close" MinWidth="90"/>
    </UniformGrid>
   </Grid>
  </GroupBox>

 </Grid>
</Window>
"@
try { $script:window = [Windows.Markup.XamlReader]::Parse($xaml) } catch {
    [System.Windows.MessageBox]::Show("XAML parse failed:`r`n$($_.Exception.Message)","XAML Error",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null
    throw
}
$script:window.WindowState='Maximized'

# --- Bind controls (FIX: include txtLog, btnInstallPCLI, btnInstallVCF) ---
$script:txtLog         = $script:window.FindName('txtLog')
$script:txtChain       = $script:window.FindName('txtChain')
$script:btnBrowseChain = $script:window.FindName('btnBrowseChain')
$script:gridTargets    = $script:window.FindName('gridTargets')
$script:btnAdd         = $script:window.FindName('btnAdd')
$script:btnRemove      = $script:window.FindName('btnRemove')
$script:btnLoadTargets = $script:window.FindName('btnLoadTargets')
$script:btnSaveTargets = $script:window.FindName('btnSaveTargets')
$script:gridResults    = $script:window.FindName('gridResults')
$script:btnOpenLog     = $script:window.FindName('btnOpenLog')
$script:btnOpenOut     = $script:window.FindName('btnOpenOut')
$script:btnBrowseReports= $script:window.FindName('btnBrowseReports')
$script:txtReports     = $script:window.FindName('txtReportsPath')
$script:btnTest        = $script:window.FindName('btnTest')
$script:btnRun         = $script:window.FindName('btnRun')
$script:btnClose       = $script:window.FindName('btnClose')
$script:lblPS          = $script:window.FindName('lblPS')
$script:lblWPF         = $script:window.FindName('lblWPF')
$script:lblPCLI        = $script:window.FindName('lblPCLI')
$script:lblVCFP        = $script:window.FindName('lblVCFP')
$script:lblSDK         = $script:window.FindName('lblSDK')
$script:lblOpenSSH     = $script:window.FindName('lblOpenSSH')
$script:btnRecheck     = $script:window.FindName('btnRecheck')
$script:btnInstallPCLI = $script:window.FindName('btnInstallPCLI')   # <-- FIX
$script:btnInstallVCF  = $script:window.FindName('btnInstallVCF')    # <-- FIX

# --- Data sources ---
$script:TargetsOC = New-Object System.Collections.ObjectModel.ObservableCollection[psobject]
$script:Rows      = New-Object System.Collections.ObjectModel.ObservableCollection[psobject]
$script:gridTargets.ItemsSource = $script:TargetsOC
$script:gridResults.ItemsSource = $script:Rows

# --- Timer to flush queued UI log lines ---
$script:uiTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:uiTimer.Interval = [TimeSpan]::FromMilliseconds(150)
$script:uiTimer.add_Tick({
    try {
        $sb = New-Object System.Text.StringBuilder
        while ($true) {
            if (-not $script:logQueue.TryDequeue([ref]$line)) { break }
            [void]$sb.Append($line)
        }
        if ($sb.Length -gt 0 -and $script:txtLog) {
            $script:txtLog.AppendText($sb.ToString())
            $script:txtLog.ScrollToEnd()
        }
    } catch {}
})
try { $script:uiTimer.Start() } catch {}
$script:window.Add_Loaded({
    try {
        $script:uiTimer.Start()
        Start-Sleep -Milliseconds 50
        if ($script:txtLog) { $script:txtLog.ScrollToEnd() }
    } catch {}
})

# --- Prereq checks & label coloring ---
function Set-StatusText { param([System.Windows.Controls.TextBlock]$Label,[string]$Text,[string]$State)
    $Label.Text = $Text
    switch ($State) {
        'OK'   { $Label.Foreground = [Windows.Media.Brushes]::LightGreen }
        'WARN' { $Label.Foreground = [Windows.Media.Brushes]::Gold }
        'FAIL' { $Label.Foreground = [Windows.Media.Brushes]::Tomato }
        default{ $Label.Foreground = [Windows.Media.Brushes]::White }
    }
}
function Prereq-Check {
    $ok = $true
    $isPS7 = $PSVersionTable.PSVersion.Major -ge 7
    Set-StatusText -Label $script:lblPS -Text ("PowerShell {0}" -f $PSVersionTable.PSVersion) -State $(if($isPS7){'OK'}else{'FAIL'})
    $ok = $ok -and $isPS7
    Set-StatusText -Label $script:lblWPF -Text ".NET/WPF: OK" -State 'OK'
    $ssh = Get-Command ssh -EA SilentlyContinue; $scp = Get-Command scp -EA SilentlyContinue
    $sshOK = !!($ssh -and $scp)
    Set-StatusText -Label $script:lblOpenSSH -Text ("OpenSSH client: " + $(if($sshOK){'Found'}else{'Not found (optional)'})) -State $(if($sshOK){'OK'}else{'WARN'})
    $hasPCLI = Has-PowerCLI; if ($hasPCLI) { Import-PowerCLIQuiet | Out-Null }
    Set-StatusText -Label $script:lblPCLI -Text $(if($hasPCLI){"VMware.PowerCLI: Found"}else{"VMware.PowerCLI: Not found"}) -State $(if($hasPCLI){'OK'}else{'WARN'})
    $hasVCF = Has-VCFPowerCLI; if ($hasVCF) { Import-VCFPowerCLI | Out-Null }
    Set-StatusText -Label $script:lblVCFP -Text $(if($hasVCF){"VCF.PowerCLI: Found"}else{"VCF.PowerCLI: Not found"}) -State $(if($hasVCF){'OK'}else{'FAIL'})
    $sdkOK = $false; try { $sdkOK = !!(Get-Module -ListAvailable -Name VMware.Sdk.Vcf.SddcManager | Select-Object -First 1) } catch { }
    Set-StatusText -Label $script:lblSDK -Text $(if($sdkOK){"SDK Modules (SDDC/NSX): Found"}else{"SDK Modules (SDDC/NSX): Not found"}) -State $(if($sdkOK){'OK'}else{'WARN'})
    if ($script:btnRun) { $script:btnRun.IsEnabled = $ok }
    return $ok
}

# --- Window lifecycle ---
$script:window.Add_ContentRendered({
    try {
        if (-not $script:RunDir) { $null = New-RunDir -Base $script:ReportsBase }
        if ($script:txtReports) { $script:txtReports.Text = $script:ReportsBase }
        Write-Log "==== SSLInspect UI started ===="
        Write-Log "Run folder: $script:RunDir"
    } catch {}
    try { $script:uiTimer.Start() } catch {}
    Prereq-Check | Out-Null
})

# --- Button events (guarded if controls exist) ---
if ($script:btnRecheck) { $script:btnRecheck.Add_Click({ Prereq-Check | Out-Null }) }

if ($script:btnInstallPCLI) {
    $script:btnInstallPCLI.Add_Click({
        try {
            $old=$ProgressPreference; $ProgressPreference='SilentlyContinue'
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null
            Install-Module -Name VMware.PowerCLI -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -AcceptLicense -ErrorAction Stop
            Import-PowerCLIQuiet | Out-Null
            Write-Log "VMware.PowerCLI installed/updated and imported."
        } catch { Write-Log "PowerCLI install failed: $($_.Exception.Message)" 'ERROR' }
        finally { $ProgressPreference=$old }
        Prereq-Check | Out-Null
    })
}

if ($script:btnInstallVCF) {
    $script:btnInstallVCF.Add_Click({
        try {
            $old=$ProgressPreference; $ProgressPreference='SilentlyContinue'
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null
            Install-Module -Name VCF.PowerCLI -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -AcceptLicense -ErrorAction Stop
            Import-VCFPowerCLI | Out-Null
            Write-Log "VCF.PowerCLI installed/updated and imported."
        } catch { Write-Log "VCF.PowerCLI install failed: $($_.Exception.Message)" 'ERROR' }
        finally { $ProgressPreference=$old }
        Prereq-Check | Out-Null
    })
}

if ($script:btnBrowseReports) {
    $script:btnBrowseReports.Add_Click({
        try {
            $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
            $dlg.Description = "Choose the base folder where run outputs should be created"
            $dlg.SelectedPath = if ((Test-Path $script:ReportsBase)) { $script:ReportsBase } else { (Get-Location).Path }
            if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $script:ReportsBase = $dlg.SelectedPath
                if ($script:txtReports) { $script:txtReports.Text = $script:ReportsBase }
            }
        } catch {}
    })
}
if ($script:btnOpenOut)  { $script:btnOpenOut.Add_Click({ try { if ($script:RunDir -and (Test-Path $script:RunDir)) { Start-Process explorer.exe $script:RunDir } elseif ($script:ReportsBase -and (Test-Path $script:ReportsBase)) { Start-Process explorer.exe $script:ReportsBase } } catch { } }) }
if ($script:btnOpenLog)  { $script:btnOpenLog.Add_Click({ try { if ($Global:LogFile -and (Test-Path $Global:LogFile)) { Start-Process notepad.exe $Global:LogFile } } catch { } }) }
if ($script:btnClose)    { $script:btnClose.Add_Click({ try { $script:window.Close() } catch { } }) }

# --- Password capture helpers ---
function Get-PasswordBoxForRowIndex([int]$RowIndex) {
    try {
        $rowCont = $script:gridTargets.ItemContainerGenerator.ContainerFromIndex($RowIndex)
        if (-not $rowCont) { return $null }
        $cellContent = $script:gridTargets.Columns[2].GetCellContent($rowCont)
        if ($cellContent -is [System.Windows.Controls.PasswordBox]) { return $cellContent }
        $stack = New-Object System.Collections.Stack; $stack.Push($cellContent)
        while ($stack.Count -gt 0) {
            $node = $stack.Pop()
            if ($node -is [System.Windows.Controls.PasswordBox]) { return $node }
            $count = [Windows.Media.VisualTreeHelper]::GetChildrenCount($node)
            for ($i2=0;$i2 -lt $count;$i2++){ $stack.Push([Windows.Media.VisualTreeHelper]::GetChild($node,$i2)) }
        }
    } catch { }
    $null
}
function Capture-Passwords {
    try {
        for ($i=0; $i -lt $script:gridTargets.Items.Count; $i++) {
            $row = $script:gridTargets.Items[$i]; if (-not $row) { continue }
            if (-not $row.PSObject.Properties['Password']) { Add-Member -InputObject $row -NotePropertyName 'Password' -NotePropertyValue '' -Force }
            $pb = Get-PasswordBoxForRowIndex $i
            if ($pb) { $row.Password = $pb.Password } else { Write-Log "Row $($i): PasswordBox not realized (virtualization) — continuing." 'WARN' }
        }
    } catch { Write-Log "Capture-Passwords error: $($_.Exception.Message)" 'WARN' }
}

# --- Grid helpers ---
if ($script:gridTargets) {
    $script:gridTargets.Add_CellEditEnding({ param($s,$e) try { if ($e.Column.Header -eq 'Type') { $row = $e.Row.Item; if ($row) { Apply-TypeDefaults -Row $row -Force } } } catch {} })
    $script:gridTargets.Add_CurrentCellChanged({ try { $row=$script:gridTargets.CurrentItem; if ($row) { Apply-TypeDefaults -Row $row } } catch {} })
    $script:gridTargets.Add_SelectionChanged({ try { $row=$script:gridTargets.SelectedItem; if ($row) { Apply-TypeDefaults -Row $row } } catch {} })
}

# --- Chain/Targets file dialogs ---
if ($script:btnBrowseChain) {
    $script:btnBrowseChain.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = "Cert files (*.cer;*.crt;*.pem;*.p7b)|*.cer;*.crt;*.pem;*.p7b|All files (*.*)|*.*"
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $script:txtChain.Text = $dlg.FileName }
    })
}
if ($script:btnAdd)       { $script:btnAdd.Add_Click({ $row = [pscustomobject]@{Host='vcsa.example.local';Username='administrator@vsphere.local';Password='';Port=443;Type='vCenter'}; $script:TargetsOC.Add($row) | Out-Null; Apply-TypeDefaults -Row $row }) }
if ($script:btnRemove)    { $script:btnRemove.Add_Click({ $sel = $script:gridTargets.SelectedItem; if ($sel) { [void]$script:TargetsOC.Remove($sel) } }) }
if ($script:btnSaveTargets){
    $script:btnSaveTargets.Add_Click({
        try {
            $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.Filter = "JSON (*.json)|*.json|All files (*.*)|*.*"; $dlg.FileName = "SSLInspect-Targets.json"
            if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $export = foreach ($t in $script:TargetsOC) { $normType = Normalize-TargetType $t.Type; [pscustomobject]@{Host=$t.Host; Username=$t.Username; Port=[int]$t.Port; Type=$normType } }
                ($export | ConvertTo-Json -Depth 3) | Set-Content -Path $dlg.FileName -Encoding UTF8
                Write-Log "Targets saved: $($dlg.FileName)"
            }
        } catch { Write-Log "Save targets error: $($_.Exception.Message)" 'ERROR' }
    })
}
if ($script:btnLoadTargets){
    $script:btnLoadTargets.Add_Click({
        try {
            $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = "JSON (*.json)|*.json|All files (*.*)|*.*"
            if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $data = Get-Content -Path $dlg.FileName -Raw | ConvertFrom-Json
                $script:TargetsOC.Clear()
                foreach ($e in $data) {
                    $type = if ($e.PSObject.Properties['Type'] -and $e.Type) { Normalize-TargetType ([string]$e.Type) } else { 'vCenter' }
                    $defs = Get-TypeDefaults $type
                    $port = if ($e.PSObject.Properties['Port'] -and $e.Port) { [int]$e.Port } else { $defs.Port }
                    $user = if ($e.PSObject.Properties['Username'] -and $e.Username) { [string]$e.Username } else { $defs.Username }
                    $row = [pscustomobject]@{Host=[string]$e.Host; Username=$user; Password=''; Port=$port; Type=$type}
                    $script:TargetsOC.Add($row) | Out-Null
                    Apply-TypeDefaults -Row $row
                }
                Write-Log "Targets loaded: $($dlg.FileName) — Count=$($script:TargetsOC.Count)"
            }
        } catch { Write-Log "Load targets error: $($_.Exception.Message)" 'ERROR' }
    })
}

# --- Test (reachability only) ---
function Test-Target {
    param([string]$Type,[string]$TargetHost,[string]$User,[string]$Pass,[int]$Port)
    $Type = Normalize-TargetType $Type
    switch ($Type) {
        'vCenter' {
            try {
                if (-not (Has-PowerCLI) -or -not (Import-PowerCLIQuiet)) { throw "VMware.PowerCLI not available." }
                $vi = $null
                try {
                    $vi = Connect-VIServer -Server $TargetHost -User $User -Password $Pass -Force -ErrorAction Stop
                    $null = Get-Datacenter -Server $vi -ErrorAction SilentlyContinue
                    [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Pass';Message='HTTPS /sdk reachable'}
                } finally { if ($vi) { Disconnect-VIServer -Server $vi -Force -Confirm:$false | Out-Null } }
            } catch { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Fail';Message=$_.Exception.Message} }
        }
        'NSX' {
            try {
                $resp = Invoke-RestMethod -Method GET -Uri ("https://{0}/api/v1/node" -f $TargetHost) -Headers @{Authorization=("Basic " + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$User`:$Pass")))} -SkipCertificateCheck -ErrorAction Stop
                [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Pass';Message='HTTPS API reachable'}
            } catch { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Fail';Message=$_.Exception.Message} }
        }
        'SDDC-Manager' {
            try {
                $tok = Get-VcfInstallerToken -Fqdn $TargetHost -User $User -Pass $Pass
                if ($tok.accessToken) { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Info';Message='Appears to be in VCF Installer mode (token OK). Use ‘‘VCF-Installer’’.'} }
                else { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Fail';Message='Token not returned'} }
            } catch { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Fail';Message=$_.Exception.Message} }
        }
        'VCF-Installer' {
            try {
                $tok = Get-VcfInstallerToken -Fqdn $TargetHost -User $User -Pass $Pass
                if ($tok.accessToken) { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Pass';Message='Token OK'} }
                else { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Fail';Message='No accessToken returned'} }
            } catch { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Fail';Message=$_.Exception.Message} }
        }
        'VCF-Operations' {
            try {
                $resp = Invoke-WebRequest -Method GET -Uri ("https://{0}/" -f $TargetHost) -SkipCertificateCheck -ErrorAction Stop
                [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Pass';Message='HTTPS reachable'}
            } catch { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Fail';Message=$_.Exception.Message} }
        }
        default { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Info';Message="Type '$Type' not implemented"} }
    }
}
if ($script:btnTest) {
    $script:btnTest.Add_Click({
        try {
            Capture-Passwords
            Write-Log "==== Test connection started ===="
            foreach ($t in $script:TargetsOC) {
                Apply-TypeDefaults -Row $t
                if ([string]::IsNullOrWhiteSpace($t.Host) -or [string]::IsNullOrWhiteSpace($t.Username)) {
                    $script:Rows.Add(([pscustomobject]@{Host=$t.Host;Type=$t.Type;Step='Test';Status='Info';Message='Skipped: Host & Username required'})) | Out-Null
                    continue
                }
                $res = Test-Target -Type $t.Type -TargetHost $t.Host -User $t.Username -Pass ($t.Password ?? '') -Port ([int]$t.Port)
                $script:Rows.Add($res) | Out-Null
                Write-Log ("[{0}] Test: {1} — {2}" -f $t.Host,$res.Status,$res.Message)
            }
            Write-Log "==== Test connection finished ===="
        } catch {
            Write-Log "Test error: $($_.Exception.Message)" 'ERROR'
            [System.Windows.MessageBox]::Show("Test error: $($_.Exception.Message)","SSLInspect",'OK','Error') | Out-Null
        }
    })
}

# --- Run (install only) ---
if ($script:btnRun) {
    $script:btnRun.Add_Click({
        try {
            if (-not (Prereq-Check)) {
                [System.Windows.MessageBox]::Show("Prerequisites not met. Install VCF.PowerCLI (and VMware.PowerCLI for vCenter) first.","SSLInspect",'OK','Warning') | Out-Null
                return
            }
            Capture-Passwords
            if (-not (Test-Path $script:txtChain.Text)) { throw "Chain file not found." }
            $chainPath = $script:txtChain.Text

            $certObjs = Get-CertObjectsFromFile -Path $chainPath
            Write-Log ("Loaded {0} certificate object(s) from chain file." -f $certObjs.Count)

            Write-ChainDebug -Certs $certObjs -OutPath (Join-Path $script:RunDir 'ChainDebug.txt')
            $expectedCNs   = Get-ExpectedCNsFromObjects $certObjs
            $expectedCATPs = Get-ExpectedCAsThumbprintsFromObjects $certObjs
            Write-Log ("Detected {0} CA cert(s) in uploaded chain." -f $expectedCATPs.Count)

            try {
                $lines = New-Object System.Collections.Generic.List[string]
                $lines.Add("== Expected CA Thumbprints (from uploaded chain) ==") | Out-Null
                if ($expectedCATPs.Count -eq 0) { $lines.Add("NO CA certificates detected in uploaded chain") | Out-Null }
                else { foreach ($tp in $expectedCATPs) { $lines.Add($tp) | Out-Null } }
                $lines.Add("") | Out-Null
                $lines.Add("== Expected Subject DNs (normalized) ==") | Out-Null
                foreach ($x in $certObjs) { try { $lines.Add( (Normalize-DN $x.Subject) ) | Out-Null } catch {} }
                $lines | Set-Content -Path (Join-Path $script:RunDir "ExpectedCAs.txt") -Encoding UTF8
            } catch {}

            $script:Rows.Clear()
            Write-Log "==== Run started ===="

            foreach ($t in $script:TargetsOC) {
                Apply-TypeDefaults -Row $t
                $targetHost = $t.Host; $targetType = (Normalize-TargetType $t.Type); $user = $t.Username; $pass = $t.Password
                if ([string]::IsNullOrWhiteSpace($targetHost) -or [string]::IsNullOrWhiteSpace($user)) {
                    $script:Rows.Add(([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Run';Status='Fail';Message='Missing Host/Username'})) | Out-Null
                    continue
                }
                try {
                    switch ($targetType) {
                        'vCenter' {
                            if (-not (Has-PowerCLI) -or -not (Import-PowerCLIQuiet)) { throw "VMware.PowerCLI not available." }
                            Write-Log "[$targetHost] Importing trusted chain into vCenter (PowerCLI)…"
                            $vi = $null
                            try {
                                $vi = Connect-VIServer -Server $targetHost -User $user -Password $pass -Force -ErrorAction Stop
                                $pemText = ($certObjs | ForEach-Object { Convert-CertToPem $_ }) -join ""
                                $old=$ConfirmPreference; $ConfirmPreference='None'
                                try { Add-VITrustedCertificate -Server $vi -VCenterOnly -PemCertificateOrChain $pemText -Confirm:$false -ErrorAction Stop | Out-Null }
                                finally { $ConfirmPreference=$old }
                                $script:Rows.Add(([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Pass';Message='Imported trusted chain via Add-VITrustedCertificate'})) | Out-Null
                                Write-Log "[$targetHost] vCenter trust updated."
                            } finally { if ($vi) { Disconnect-VIServer -Server $vi -Force -Confirm:$false | Out-Null } }
                        }
                        'NSX' {
                            Write-Log "[$targetHost] Importing CA into NSX (REST)…"
                            $res = Invoke-NSXCaImport -Fqdn $targetHost -User $user -Pass $pass -Certs $certObjs
                            $installStatus = if ($res.Added -gt 0) {'Pass'} else {'Info'}
                            $script:Rows.Add(([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status=$installStatus;Message=$res.Message})) | Out-Null
                        }
                        'SDDC-Manager' {
                            $installerMode = $false; $tokenObj = $null
                            try { $tokenObj = Get-VcfInstallerToken -Fqdn $targetHost -User $user -Pass $pass; if ($tokenObj.accessToken) { $installerMode = $true } } catch {}
                            if ($installerMode) {
                                Write-Log "[$targetHost] Detected Installer-mode. Routing to Installer API for trusted cert import…"
                                $res = Add-VcfInstallerTrustedCert -Fqdn $targetHost -AccessToken $tokenObj.accessToken -Certs $certObjs
                                $installStatus = if ($res.Added -gt 0) {'Pass'} else {'Info'}
                                $msg = if ($res.Added -gt 0) {'Trusted certificate(s) added via Installer API'} else {'Already present (Installer API)'}
                                $script:Rows.Add(([pscustomobject]@{Host=$targetHost;Type='VCF-Installer';Step='Install';Status=$installStatus;Message=$msg})) | Out-Null
                            } else {
                                Write-Log "[$targetHost] Adding trusted certificate(s) via SDDC Manager SDK…"
                                $res = Add-SddcTrustedCertificateSDK -SddcFqdn $targetHost -User $user -Pass $pass -Certs $certObjs
                                $installStatus = if ($res.Added -gt 0) {'Pass'} else {'Info'}
                                $msg = if ($res.Added -gt 0) {'Trusted certificate(s) added via SDK'} else {'Already present (SDK)'}
                                $script:Rows.Add(([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status=$installStatus;Message=$msg})) | Out-Null
                            }
                        }
                        'VCF-Installer' {
                            Write-Log "[$targetHost] Adding trusted certificate(s) via VCF Installer API…"
                            $token = Get-VcfInstallerToken -Fqdn $targetHost -User $user -Pass $pass
                            if (-not $token.accessToken) { throw "Token API returned no accessToken." }
                            $res = Add-VcfInstallerTrustedCert -Fqdn $targetHost -AccessToken $token.accessToken -Certs $certObjs
                            $installStatus = if ($res.Added -gt 0) {'Pass'} else {'Info'}
                            $msg = if ($res.Added -gt 0) {'Trusted certificate(s) added via Installer API'} else {'Already present (Installer API)'}
                            $script:Rows.Add(([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status=$installStatus;Message=$msg})) | Out-Null
                        }
                        'VCF-Operations' {
                            $script:Rows.Add(([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Info';Message='Trusted-cert install not implemented (no published API)'})) | Out-Null
                        }
                        default {
                            $script:Rows.Add(([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Run';Status='Fail';Message=("Unsupported Type '{0}'" -f $targetType)})) | Out-Null
                        }
                    }
                } catch {
                    $script:Rows.Add(([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Run';Status='Fail';Message=$_.Exception.Message})) | Out-Null
                    Write-Log "[$targetHost] Error: $($_.Exception.Message)" 'ERROR'
                }
            }

            # CSV (5 columns)
            $outCsv = Join-Path $script:RunDir "Results.csv"
            $normalized = foreach ($r in $script:Rows) {
                [pscustomobject]@{ Host=$r.Host; Type=$r.Type; Step=$r.Step; Status=$r.Status; Message=$r.Message }
            }
            $normalized | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
            Write-Log "CSV saved: $outCsv"
            Write-Log "==== Run finished (Rows=$($script:Rows.Count)) ===="
        } catch {
            Write-Log "Run error: $($_.Exception.Message)" 'ERROR'
            [System.Windows.MessageBox]::Show("Run error: $($_.Exception.Message)","SSLInspect",'OK','Error') | Out-Null
        }
    })
}

# --- Seed example row & show UI ---
$script:TargetsOC.Add([pscustomobject]@{Host='vcsa.example.local';Username='administrator@vsphere.local';Password='';Port=443;Type='vCenter'}) | Out-Null
$null = $script:window.ShowDialog()