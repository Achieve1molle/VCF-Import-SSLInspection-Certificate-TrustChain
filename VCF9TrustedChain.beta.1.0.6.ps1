
<#
.SYNOPSIS
VCF 9 Trusted Certificate Import UI — v1.0.9u

.CHANGES (vs. 1.0.9t)
- Fixed remaining stray bracket in control lookup section (btnInstallNSX).
- Fixed XAML typos: 'Grid.Columnifications' -> 'Grid.ColumnDefinitions' (both occurrences).
- Retains 1.0.9s fix: Resolve-CertFileToPem returns Certs as [X509Certificate2[]] using .ToArray().
- Retains 1.0.9r improvements: UI browse sizing, ESXi push default unchecked, root-only auto-skip, REST diagnostics,
  and PS5-parse-safe interpolation (${http}).

.NOTES
Version: 1.0.9u
#>
[CmdletBinding()]
param([switch]$NoRelaunch,[switch]$SignedOk,[switch]$NoAutoSign)
$Global:SSLInspectVersion='1.0.9u'
$VerbosePreference='SilentlyContinue';$InformationPreference='Continue';$ProgressPreference='SilentlyContinue'
function Coalesce([object]$a,[object]$b){ if ($null -ne $a -and ($a -isnot [string] -or $a -ne '')) { return $a } else { return $b } }
try { Get-ChildItem Function:\Invoke-VCFOpsTrustedImport* -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue; Get-ChildItem Function:\Write-ChainDebug* -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue } catch {}
function Ensure-SelfSigned { param([string]$TargetPath) try { $sig=Get-AuthenticodeSignature -FilePath $TargetPath -ErrorAction SilentlyContinue } catch { $sig=$null } if ($sig -and $sig.Status -eq 'Valid') { return $false } Write-Host '[SelfSign] Creating/trusting a local code-signing certificate and signing the script...'; $subject = "CN=SSLInspect Local Code Signing ($env:USERNAME@$env:COMPUTERNAME)"; $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like 'CN=SSLInspect Local Code Signing*' } | Sort-Object NotAfter -Descending | Select-Object -First 1; if (-not $cert) { $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5) }; foreach ($store in 'Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher') { try { $null = $cert | Copy-Item -Destination $store -Force -ErrorAction SilentlyContinue } catch {} }; $null = Set-AuthenticodeSignature -FilePath $TargetPath -Certificate $cert -ErrorAction Stop; Write-Host '[SelfSign] Script signed.'; return $true }
try { $pwsh=$null; $proc = Get-Process -Id $PID -ErrorAction SilentlyContinue; if ($proc) { $pwsh=$proc.Path } } catch { $pwsh=$null }; if (-not $pwsh) { $pwsh='pwsh.exe' }
if (-not $NoAutoSign -and -not $SignedOk) { $didSign = Ensure-SelfSigned -TargetPath $PSCommandPath; & $pwsh -NoProfile -ExecutionPolicy Bypass -STA -File "$PSCommandPath" -SignedOk -NoRelaunch; exit $LASTEXITCODE }
if (-not $NoRelaunch) { $ap=[Threading.Thread]::CurrentThread.ApartmentState; if ($ap -ne 'STA') { & $pwsh -NoProfile -ExecutionPolicy Bypass -STA -File "$PSCommandPath" -NoRelaunch -SignedOk; exit $LASTEXITCODE } }
$script:ReportsBase=(Get-Location).Path; $script:RunDir=$null; $Global:LogFile=$null; $script:LogWarmupSync=50; $script:logQueue=[System.Collections.Concurrent.ConcurrentQueue[string]]::new()
function New-RunDir{ param([string]$Base) if ([string]::IsNullOrWhiteSpace($Base) -or -not (Test-Path $Base)) { $Base=(Get-Location).Path }; $d=Join-Path $Base ("SSLInspect-Run-"+(Get-Date -Format 'yyyyMMdd-HHmmss')); New-Item -ItemType Directory -Force -Path $d | Out-Null; $Global:LogFile=Join-Path $d ("SSLInspect-"+((Get-Date).ToString('yyyyMMdd-HHmmss'))+".log"); '' | Out-File -FilePath $Global:LogFile -Encoding UTF8 -Force; $script:RunDir=$d; $d }
function Write-Log{ param([Parameter(Mandatory)][string]$Message,[ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO') $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'); $line="[$ts][$Level] $Message"; try { if ($Global:LogFile) { Add-Content -Path $Global:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } } catch {}; try { if ($script:txtLog -and $script:window) { if ($script:LogWarmupSync -gt 0) { $script:window.Dispatcher.Invoke([Action]{ try { $script:txtLog.AppendText("$line`r`n"); $script:txtLog.ScrollToEnd() } catch {} },[System.Windows.Threading.DispatcherPriority]::Render); $script:LogWarmupSync-- } else { $null=$script:window.Dispatcher.BeginInvoke([Action]{ try { $script:txtLog.AppendText("$line`r`n"); $script:txtLog.ScrollToEnd() } catch {} }) } } else { $script:logQueue.Enqueue("$line`r`n") } } catch {}; Write-Host $line }
Add-Type -AssemblyName System.Security
function Convert-CertToPem{ param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) $der=$Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert); $b64=[Convert]::ToBase64String($der,'InsertLineBreaks'); "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n" }
function Get-CertObjectsFromPemText{ param([string]$PemText) $list=New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]; if ([string]::IsNullOrWhiteSpace($PemText)) { return ,@() }; $matches=[regex]::Matches($PemText,'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----'); foreach($m in $matches){ $pem=$m.Value; $b64=($pem -replace '-----.*?-----','' -replace '\s',''); if ([string]::IsNullOrWhiteSpace($b64)) { continue }; try { $bytes=[Convert]::FromBase64String($b64); $x=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes); $list.Add($x)|Out-Null } catch {} }; ,$list.ToArray() }
function Read-PfxPasswordPrompt{ param([string]$Path) Add-Type -AssemblyName System.Windows.Forms | Out-Null; $form=New-Object System.Windows.Forms.Form; $form.Text='PFX/P12 Password'; $form.Width=420; $form.Height=170; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false; $form.MinimizeBox=$false; $label=New-Object System.Windows.Forms.Label; $label.Text="Enter password for:`n$Path"; $label.AutoSize=$true; $label.Left=12; $label.Top=10; $tb=New-Object System.Windows.Forms.MaskedTextBox; $tb.PasswordChar='*'; $tb.Width=360; $tb.Left=12; $tb.Top=60; $ok=New-Object System.Windows.Forms.Button; $ok.Text='OK'; $ok.Width=90; $ok.Left=196; $ok.Top=100; $cancel=New-Object System.Windows.Forms.Button; $cancel.Text='Cancel'; $cancel.Width=90; $cancel.Left=292; $cancel.Top=100; $ok.Add_Click({ $form.Tag=$tb.Text; $form.DialogResult=[System.Windows.Forms.DialogResult]::OK; $form.Close() }); $cancel.Add_Click({ $form.DialogResult=[System.Windows.Forms.DialogResult]::Cancel; $form.Close() }); $form.Controls.AddRange(@($label,$tb,$ok,$cancel)); $form.StartPosition='CenterParent'; $null=$form.ShowDialog(); if ($form.DialogResult -ne [System.Windows.Forms.DialogResult]::OK) { return $null }; $plain=[string]$form.Tag; if ([string]::IsNullOrWhiteSpace($plain)) { return $null }; ConvertTo-SecureString -String $plain -AsPlainText -Force }
function SecureStringToPlain{ param([Security.SecureString]$s) if (-not $s) { return '' }; $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); try { [Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) } }
function Is-CACert{ param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) try { foreach($ext in $Cert.Extensions){ if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]){ if ($ext.CertificateAuthority){ return $true } } }; return ($Cert.Subject -eq $Cert.Issuer) } catch { return ($Cert.Subject -eq $Cert.Issuer) } }
function Resolve-CertFileToPem{ param([Parameter(Mandatory)][string]$InputPath,[string]$OutputDir,[Security.SecureString]$PfxPassword) if (-not (Test-Path $InputPath)) { throw "File not found: $InputPath" }; if (-not $OutputDir) { $OutputDir=(Get-Location).Path }; $ext=(([IO.Path]::GetExtension($InputPath))+'').ToLowerInvariant(); $pemBlocks=New-Object System.Collections.Generic.List[string]; $certObjs=New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]; switch ($ext) { '.pem' { $raw=Get-Content -Path $InputPath -Raw; $objs=Get-CertObjectsFromPemText -PemText $raw; if ($objs.Count -le 0) { throw 'No PEM CERT blocks found.' }; foreach($o in $objs){ $certObjs.Add($o)|Out-Null; $pemBlocks.Add((Convert-CertToPem $o))|Out-Null } } '.crt' { try { $raw=Get-Content -Path $InputPath -Raw; if ($raw -match 'BEGIN CERTIFICATE') { $objs=Get-CertObjectsFromPemText -PemText $raw; foreach($o in $objs){ $certObjs.Add($o); $pemBlocks.Add((Convert-CertToPem $o)) }; break } } catch {}; $x=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($InputPath); $certObjs.Add($x); $pemBlocks.Add((Convert-CertToPem $x)) } '.cer' { $x=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($InputPath); $certObjs.Add($x); $pemBlocks.Add((Convert-CertToPem $x)) } '.der' { $x=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($InputPath); $certObjs.Add($x); $pemBlocks.Add((Convert-CertToPem $x)) } '.p7b' { $col=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection; $col.Import($InputPath); foreach($c in $col){ $certObjs.Add($c)|Out-Null; $pemBlocks.Add((Convert-CertToPem $c))|Out-Null } } '.p7c' { $col=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection; $col.Import($InputPath); foreach($c in $col){ $certObjs.Add($c)|Out-Null; $pemBlocks.Add((Convert-CertToPem $c))|Out-Null } } '.pfx' { if (-not $PfxPassword) { $PfxPassword=Read-PfxPasswordPrompt -Path $InputPath }; if (-not $PfxPassword) { throw 'PFX/P12 requires a password.' }; $plain=SecureStringToPlain $PfxPassword; $col=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection; $col.Import($InputPath,$plain,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable); foreach($c in $col){ $certObjs.Add($c)|Out-Null; $pemBlocks.Add((Convert-CertToPem $c))|Out-Null } } default { throw "Unsupported certificate format: $ext" } }; if ($pemBlocks.Count -le 0 -or $certObjs.Count -le 0) { throw 'No certificates found in the provided file.' }; $seen=New-Object System.Collections.Generic.HashSet[string]; $dedup=New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]; foreach($o in $certObjs){ $tp=$o.Thumbprint.ToUpperInvariant(); if ($seen.Add($tp)) { $dedup.Add($o)|Out-Null } }; $pemOut=(($dedup|ForEach-Object{ Convert-CertToPem $_ }) -join '')
$outPath=Join-Path $OutputDir 'NormalizedChain.pem'; Set-Content -Path $outPath -Value $pemOut -Encoding ASCII -Force; $certArray=@($dedup.ToArray()); [pscustomobject]@{ PemText=$pemOut; Path=$outPath; Certs=$certArray } }
function Split-PemChain([string]$PemText){ [regex]::Matches($PemText,'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----') | ForEach-Object { $_.Value } }
function Get-PemThumbprintFromJsonBlock([string]$jsonBlock){ $pem=$jsonBlock -replace '\\n','`n'; $b64=($pem -replace '-----.*?-----','' -replace '\s',''); $bytes=[Convert]::FromBase64String($b64); $x=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes); $x.Thumbprint.ToUpperInvariant() }
function Has-PowerCLI{ !!(Get-Module -ListAvailable -Name VMware.VimAutomation.Core | Select-Object -First 1) }
function Import-PowerCLIQuiet{ try { Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue | Out-Null; Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; return $true } catch { Write-Log "PowerCLI import failed: $($_.Exception.Message)" 'WARN'; return $false } }
function Has-PoshSSH{ !!(Get-Module -ListAvailable -Name Posh-SSH | Select-Object -First 1) }
function Import-PoshSSH{ try { Import-Module Posh-SSH -ErrorAction SilentlyContinue | Out-Null; return $true } catch { Write-Log "Posh-SSH import failed: $($_.Exception.Message)" 'WARN'; return $false } }
function Has-PowerVCF{ !!(Get-Module -ListAvailable -Name VMware.PowerVCF | Select-Object -First 1) -or !!(Get-Module -ListAvailable -Name PowerVCF | Select-Object -First 1) }
function Ensure-NSXSDK{ try { $old=$ProgressPreference; $ProgressPreference='SilentlyContinue'; Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null; Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null; Install-Module -Name VMware.VMC.NSXT -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -AcceptLicense -ErrorAction Stop; Write-Log 'VMware.VMC.NSXT installed/updated and imported.'; Import-Module VMware.VMC.NSXT -ErrorAction SilentlyContinue | Out-Null; return $true } catch { Write-Log "VMware.VMC.NSXT install failed: $($_.Exception.Message)" 'ERROR'; return $false } finally { $ProgressPreference=$old } }
function Ensure-Module{ param([Parameter(Mandatory)][string]$Name) $ok=$false; switch ($Name) { 'VMware.PowerCLI' { $ok=Has-PowerCLI; if ($ok) { $ok=Import-PowerCLIQuiet } } 'Posh-SSH' { $ok=Has-PoshSSH; if ($ok) { $ok=Import-PoshSSH } } 'VMware.PowerVCF' { $ok=Has-PowerVCF; if ($ok) { try { Import-Module VMware.PowerVCF -ErrorAction SilentlyContinue | Out-Null; $ok=$true } catch { try { Import-Module PowerVCF -ErrorAction SilentlyContinue | Out-Null; $ok=$true } catch { $ok=$false } } } } default { return $false } } if ($ok) { return $true } try { $old=$ProgressPreference; $ProgressPreference='SilentlyContinue'; Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null; Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null; if ($Name -eq 'VMware.PowerVCF') { try { Write-Log 'Attempting Install-Module VMware.PowerVCF…'; Install-Module -Name VMware.PowerVCF -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -AcceptLicense -ErrorAction Stop } catch { Write-Log 'VMware.PowerVCF not in current repositories, attempting Install-Module PowerVCF…' 'WARN'; Install-Module -Name PowerVCF -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -AcceptLicense -ErrorAction Stop }; try { Import-Module VMware.PowerVCF -ErrorAction SilentlyContinue | Out-Null } catch { try { Import-Module PowerVCF -ErrorAction SilentlyContinue | Out-Null } catch {} } } else { Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -AcceptLicense -ErrorAction Stop; switch ($Name) { 'VMware.PowerCLI' { $null=Import-PowerCLIQuiet } 'Posh-SSH' { $null=Import-PoshSSH } } }; Write-Log "$Name installed/updated and imported."; return $true } catch { Write-Log "$Name install failed: $($_.Exception.Message)" 'ERROR'; return $false } finally { $ProgressPreference=$old } }
function New-VcRestSession{ param([string]$VcFqdn,[string]$User,[string]$Pass) $vc="https://$VcFqdn"; $session=Invoke-RestMethod -Method Post -Uri "$vc/rest/com/vmware/cis/session" -Headers @{ 'Content-Type'='application/json' } -Credential (New-Object pscredential($User,(ConvertTo-SecureString $Pass -AsPlainText -Force))) -SkipCertificateCheck; @{ vc=$vc; headers=@{ 'vmware-api-session-id'=$session.value } } }
function Get-HttpErrorDetail{ param([object]$Ex) $code=''; $snippet=''; try { $resp=$Ex.Response; if ($resp -and $resp -is [System.Net.Http.HttpResponseMessage]){ $code=[int]$resp.StatusCode; try { $snippet = $resp.Content.ReadAsStringAsync().Result } catch { $snippet=$Ex.Message } } } catch {} if ($snippet -and $snippet.Length -gt 200) { $snippet=$snippet.Substring(0,200) } [pscustomobject]@{ Code=$code; Snippet=$snippet } }
function Add-VcTrustedRootChainRestEx{ param([string]$VcFqdn,[string]$User,[string]$Pass,[string]$PemChain,[string[]]$ExpectedThumbprints) $sess=New-VcRestSession -VcFqdn $VcFqdn -User $User -Pass $Pass; $blocks=Split-PemChain $PemChain; if (-not $blocks -or $blocks.Count -lt 1) { throw 'No CERT blocks parsed for REST import' }; $body=@{ cert_chain = @{ cert_chain = $blocks } } | ConvertTo-Json -Depth 6; $newId=$null; $http=200; $err=$null; try { $newId = Invoke-RestMethod -Method Post -Uri "$( $sess.vc)/api/vcenter/certificate-management/vcenter/trusted-root-chains" -Headers $sess.headers -SkipCertificateCheck -ContentType 'application/json' -Body $body } catch { $d=Get-HttpErrorDetail -Ex $_.Exception; $http = Coalesce $d.Code 0; $err = "HTTP ${http}: $($d.Snippet)"; $newId = "(create failed)" } try { $chains=Invoke-RestMethod -Method Get -Uri "$( $sess.vc)/api/vcenter/certificate-management/vcenter/trusted-root-chains" -Headers $sess.headers -SkipCertificateCheck; $found=@{}; foreach ($cid in @($chains.chain)) { $d=Invoke-RestMethod -Method Get -Uri "$( $sess.vc)/api/vcenter/certificate-management/vcenter/trusted-root-chains/$cid" -Headers $sess.headers -SkipCertificateCheck; foreach ($blk in $d.cert_chain.cert_chain) { if ($blk -like '*BEGIN CERTIFICATE*') { try { $tp=Get-PemThumbprintFromJsonBlock $blk } catch { continue }; if ($ExpectedThumbprints -contains $tp) { $found[$tp]=$cid } } } }; [pscustomobject]@{ NewChainId=$newId; Http=$http; Error=$err; FoundMap=$found } } catch { [pscustomobject]@{ NewChainId=$newId; Http=$http; Error=(Coalesce $err $_.Exception.Message); FoundMap=@{} } } }
function New-SSHSessionCompat{ param([string]$ComputerName,[pscredential]$Credential,[int]$Port=22,[int]$ConnectionTimeout=30,[int]$OperationTimeout=120,[switch]$AcceptKey) $s=@{ ComputerName=$ComputerName; Credential=$Credential; Port=$Port; ConnectionTimeout=$ConnectionTimeout }; if ($AcceptKey){$s.AcceptKey=$true}; $cmd=Get-Command New-SSHSession -ErrorAction SilentlyContinue; if ($cmd -and $cmd.Parameters.ContainsKey('OperationTimeout')) { $s.OperationTimeout=$OperationTimeout }; New-SSHSession @s }
function Copy-RemoteFileCompat{ param([string]$RemoteHost,[int]$Port,[pscredential]$Credential,[object]$SSHSession,[string]$Local,[string]$Remote) $scp=Get-Command Set-SCPFile -ErrorAction SilentlyContinue; if ($scp) { Set-SCPFile -SSHSession $SSHSession -LocalFile $Local -RemotePath $Remote -ErrorAction Stop; return }; $newS=Get-Command New-SFTPSession -ErrorAction SilentlyContinue; $put=Get-Command Set-SFTPFile -ErrorAction SilentlyContinue; if ($newS -and $put) { $sftp=$null; try { $sftp=New-SFTPSession -ComputerName $RemoteHost -Port $Port -Credential $Credential -AcceptKey -ErrorAction Stop; Set-SFTPFile -SFTPSession $sftp -LocalFile $Local -RemotePath $Remote -Confirm:$false -ErrorAction Stop; return } finally { if ($sftp) { Remove-SFTPSession -SFTPSession $sftp | Out-Null } } }; $payload=Get-Content -Path $Local -Raw -Encoding ASCII; $token="SSLINSPECT_{0}" -f ([Guid]::NewGuid().ToString('N')); $upload="cat > \`"$Remote\`" <<'$token'"+"`n"+$payload+"`n$token`n"; Invoke-SSHCommand -SSHSession $SSHSession -Command $upload -TimeOut 300 -ErrorAction Stop | Out-Null }
function Invoke-VCFOpsTrustedImport3{ param([Parameter(Mandatory)][string]$HostFqdn,[Parameter(Mandatory)][string]$Username,[Parameter(Mandatory)][string]$Password,[int]$Port=22,[Parameter(Mandatory)][string]$PemText) if (-not (Ensure-Module -Name 'Posh-SSH')) { throw 'Posh-SSH module not available.' }; if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($Password)) { throw 'Username and Password are required for VCF-Operations SSH. Populate the SSH Password cell before Run.' }; $PSDefaultParameterValues['New-SSHSession:ErrorAction']='Stop'; $PSDefaultParameterValues['Invoke-SSHCommand:ErrorAction']='Stop'; $localPem=Join-Path $script:RunDir 'vcfops-chain.pem'; Set-Content -Path $localPem -Value $PemText -Encoding ASCII -Force; $sec=ConvertTo-SecureString $Password -AsPlainText -Force; $cred=New-Object System.Management.Automation.PSCredential($Username,$sec); $sshSplat=@{ ComputerName=$HostFqdn; Port=($(if($Port -gt 0){$Port}else{22})); Credential=$cred; AcceptKey=$true; ConnectionTimeout=30; OperationTimeout=120 }; $sess=$null; try { $sess=New-SSHSessionCompat @sshSplat } catch { throw "SSH connect failed: $($_.Exception.Message)" }; try { Copy-RemoteFileCompat -RemoteHost $HostFqdn -Port $Port -Credential $cred -SSHSession $sess -Local $localPem -Remote '/tmp/sslinspect-chain.pem' } catch { if ($sess) { Remove-SSHSession -SSHSession $sess | Out-Null }; throw "SCP/SFTP/Inline upload failed: $($_.Exception.Message)" }; $pwB64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Password)); $remoteScript=@'
set -euo pipefail
PW_B64="__PW64_TOKEN__"
PEM='/tmp/sslinspect-chain.pem'
if [ "$(id -u)" -eq 0 ]; then RUN() { "$@"; } else if command -v base64 >/dev/null 2>&1; then SUDOPW=$(echo -n "$PW_B64" | base64 -d 2>/dev/null || true); elif command -v openssl >/dev/null 2>&1; then SUDOPW=$(echo -n "$PW_B64" | openssl base64 -d -A 2>/dev/null || true); else SUDOPW=""; fi; RUN() { echo "$SUDOPW" | sudo -S "$@"; } fi
command -v openssl >/dev/null 2>&1 || { echo 'openssl not found'; exit 2; }
command -v keytool >/dev/null 2>&1 || { echo 'keytool not found'; exit 3; }
sed -i 's/\r$//' "$PEM" 2>/dev/null || true
CONF_BASE="/usr/lib/vmware-vcops/user/conf"
CANDIDATES=("/data/vcops/user/conf/ssl/tcserver.truststore" "/usr/lib/vmware-vcops/user/conf/ssl/cacerts")
TS_FROM_JMX=$(grep -RIn "javax.net.ssl.trustStore=" "$CONF_BASE" 2>/dev/null | awk -F= '{print $2}' | head -n1 || true)
TS_FROM_KV=$(grep -RIn "vmware-ssl.truststore.file" "$CONF_BASE" 2>/dev/null | awk -F= '{print $2}' | head -n1 || true)
[ -n "$TS_FROM_JMX" ] && CANDIDATES+=("$TS_FROM_JMX"); [ -n "$TS_FROM_KV" ] && CANDIDATES+=("$TS_FROM_KV")
SYS_JRE=$(readlink -f /etc/alternatives/jre*/lib/security/cacerts 2>/dev/null | head -n1 || true)
[ -n "$SYS_JRE" ] && CANDIDATES+=("$SYS_JRE")
CACERTS=""; for f in "${CANDIDATES[@]}"; do [ -f "$f" ] && { CACERTS="$f"; break; }; done
[ -z "$CACERTS" ] && { echo 'Could not locate a truststore (tcserver.truststore/cacerts).'; exit 4; }
PW_CAND=("changeit" "vmware" "vmware1!" "VMware1!" "changeme")
FOUND_PW=""; for pw in "${PW_CAND[@]}"; do if RUN keytool -list -keystore "$CACERTS" -storepass "$pw" >/dev/null 2>&1; then FOUND_PW="$pw"; break; fi; done
[ -z "$FOUND_PW" ] && { echo "Could not determine truststore password for $CACERTS"; exit 5; }
BACKUP="${CACERTS}.$(date +%Y%m%d%H%M%S).bak"; RUN cp -p "$CACERTS" "$BACKUP" 2>/dev/null || true
awk 'BEGIN{c=0}/-----BEGIN CERTIFICATE-----/{c++;f=sprintf("/tmp/sslcert-%02d.pem",c)}{print > f}/-----END CERTIFICATE-----/{close(f)}' "$PEM"
for f in /tmp/sslcert-*.pem; do [ -f "$f" ] || continue; alias=$(openssl x509 -in "$f" -noout -fingerprint -sha1 | sed 's/.*=//' | tr -d ':' | tr 'A-Z' 'a-z'); [ -z "$alias" ] && continue; if RUN keytool -list -keystore "$CACERTS" -storepass "$FOUND_PW" | grep -qi "sslinspect_${alias}"; then echo "alias sslinspect_${alias} already present"; continue; fi; RUN keytool -importcert -trustcacerts -noprompt -alias "sslinspect_${alias}" -file "$f" -keystore "$CACERTS" -storepass "$FOUND_PW"; done
if command -v systemctl >/dev/null 2>&1; then RUN systemctl restart vmware-vcops; else RUN service vmware-vcops restart; fi
echo 'VCF-Operations truststore updated.'
'@; $remoteScript=$remoteScript.Replace('__PW64_TOKEN__',$pwB64); try { $res=Invoke-SSHCommand -SSHSession $sess -Command $remoteScript -TimeOut 900 -ErrorAction Stop; $msg=($res.Output | Where-Object { $_ -and $_.Trim().Length -gt 0 }) -join '; '; if (-not $msg) { $msg='VCF-Operations truststore updated (no output)' }; return [pscustomobject]@{ Added=1; Skipped=0; Message=$msg } } catch { throw "Remote import failed: $($_.Exception.Message)" } finally { if ($sess) { Remove-SSHSession -SSHSession $sess | Out-Null } } }
function Get-TypeDefaults { param([string]$Type) switch ($Type) { 'vCenter' { @{ Port=443; Username='administrator@vsphere.local' } } 'NSX' { @{ Port=443; Username='admin' } } 'SDDC-Manager' { @{ Port=443; Username='administrator@vsphere.local' } } 'VCF-Installer' { @{ Port=443; Username='admin@local' } } 'VCF-Operations' { @{ Port=22; Username='admin' } } default { @{ Port=443; Username='' } } } }
function Normalize-TargetType([string]$Type){ $t = $Type; if ($null -eq $t) { $t = '' } $t = $t.Trim(); $t = $t -replace '[\u2010-\u2015]','-'; $lt = $t.ToLower(); if ($lt -eq 'vcenter') { return 'vCenter' } elseif ($lt -eq 'nsx') { return 'NSX' } elseif ($lt -match '^(sddc[\s\-]?manager)$') { return 'SDDC-Manager' } elseif ($lt -match '^(vcf[\s\-]?installer)$') { return 'VCF-Installer' } elseif ($lt -match '^(vcf[\s\-]?(ops|operations))$') { return 'VCF-Operations' } else { return $Type } }
function Apply-TypeDefaults{ param([psobject]$Row,[switch]$Force) if (-not $Row) { return }; if ($Row.PSObject.Properties['Type'] -and $Row.Type) { $Row.Type=Normalize-TargetType $Row.Type } $defs=Get-TypeDefaults $Row.Type; foreach($n in 'Port','Username','Password','SshUsername','SshPassword'){ if (-not $Row.PSObject.Properties[$n]) { Add-Member -InputObject $Row -NotePropertyName $n -NotePropertyValue '' -Force } }; if ($Force){ $Row.Port=$defs.Port; $Row.Username=$defs.Username; if ($Row.Type -eq 'VCF-Operations') { $Row.Username='admin'; if ([string]::IsNullOrWhiteSpace($Row.SshUsername)) { $Row.SshUsername='root' } }; return }; if (-not $Row.Port -or $Row.Port -in 22,443) { $Row.Port=$defs.Port }; if ($Row.Type -eq 'VCF-Operations') { if ([string]::IsNullOrWhiteSpace($Row.Username) -or ($Row.Username -in @('root','vcf','vcf@local','administrator@vsphere.local'))) { $Row.Username='admin' }; if ([string]::IsNullOrWhiteSpace($Row.SshUsername)) { $Row.SshUsername='root' } } else { if ([string]::IsNullOrWhiteSpace($Row.Username)) { $Row.Username=$defs.Username } } }
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase -ErrorAction SilentlyContinue | Out-Null; Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue | Out-Null
$xaml=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:sys="clr-namespace:System;assembly=mscorlib" Title="Achieve One—Leadership to Adapt—Expertise to Achieve (v{#VER#})" Height="900" Width="1600" MinHeight="760" MinWidth="1240" WindowStartupLocation="CenterScreen" Background="#0f0f10" Foreground="#f3f3f3">
  <Window.Resources>
    <SolidColorBrush x:Key="Bg" Color="#0f0f10"/>
    <SolidColorBrush x:Key="PanelBg" Color="#1c1c1e"/>
    <SolidColorBrush x:Key="Fg" Color="#f3f3f3"/>
    <SolidColorBrush x:Key="Border" Color="#3a3a3a"/>
    <SolidColorBrush x:Key="HeaderBg" Color="#2a2a2c"/>
    <SolidColorBrush x:Key="SelBg" Color="#3d3d40"/>
    <Style TargetType="GroupBox"><Setter Property="Margin" Value="8"/><Setter Property="Padding" Value="8"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="Background" Value="{StaticResource Bg}"/></Style>
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="Margin" Value="8,0,8,6"/></Style>
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="Margin" Value="8,4,8,4"/></Style>
    <Style TargetType="TextBox"><Setter Property="Margin" Value="8"/><Setter Property="Padding" Value="4"/><Setter Property="Height" Value="28"/><Setter Property="Background" Value="{StaticResource PanelBg}"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/></Style>
    <Style TargetType="PasswordBox"><Setter Property="Margin" Value="8"/><Setter Property="Padding" Value="4"/><Setter Property="Height" Value="28"/><Setter Property="Background" Value="{StaticResource PanelBg}"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="BorderBrush" Value="#565656"/></Style>
    <Style TargetType="Button"><Setter Property="Margin" Value="8,6,8,6"/><Setter Property="Padding" Value="8,4"/><Setter Property="Height" Value="28"/><Setter Property="Background" Value="#2a2a2c"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="BorderBrush" Value="#565656"/></Style>
    <Style TargetType="DataGrid"><Setter Property="Margin" Value="8"/><Setter Property="Background" Value="{StaticResource PanelBg}"/><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="GridLinesVisibility" Value="All"/><Setter Property="HeadersVisibility" Value="Column"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/><Setter Property="AlternationCount" Value="2"/><Setter Property="RowBackground" Value="#19191b"/><Setter Property="AlternatingRowBackground" Value="#151517"/><Setter Property="HorizontalGridLinesBrush" Value="#303034"/><Setter Property="VerticalGridLinesBrush" Value="#303034"/><Setter Property="SelectionUnit" Value="FullRow"/></Style>
    <Style TargetType="DataGridColumnHeader"><Setter Property="Foreground" Value="{StaticResource Fg}"/><Setter Property="Background" Value="{StaticResource HeaderBg}"/><Setter Property="BorderBrush" Value="{StaticResource Border}"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
  </Window.Resources>
  <Grid Margin="8">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="2*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <!-- Row 0: Prereqs + Chain -->
    <Grid Grid.Row="0" Margin="0,0,0,8">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="1.6*"/>
        <ColumnDefinition Width="2*"/>
      </Grid.ColumnDefinitions>
      <GroupBox Header="Prerequisites" Grid.Column="0">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="2*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <StackPanel Grid.Column="0">
            <TextBlock x:Name="lblPS" Text="PowerShell 7+: (checking…)" />
            <TextBlock x:Name="lblWPF" Text=".NET/WPF: (checking…)" />
            <TextBlock x:Name="lblPCLI" Text="VMware.PowerCLI: (checking…)" />
            <TextBlock x:Name="lblVCFP" Text="PowerVCF: (checking…)" />
            <TextBlock x:Name="lblSDK" Text="NSX SDK (VMware.VMC.NSXT): (checking…)" />
            <TextBlock x:Name="lblPoshSSH" Text="Posh-SSH: (checking…)" />
          </StackPanel>
          <StackPanel Grid.Column="1" VerticalAlignment="Center">
            <Button x:Name="btnRecheck" Content="Recheck" MinWidth="110"/>
          </StackPanel>
          <StackPanel Grid.Column="2" Orientation="Vertical" VerticalAlignment="Center">
            <Button x:Name="btnInstallPCLI" Content="Install VMware.PowerCLI" MinWidth="210"/>
            <Button x:Name="btnInstallVCF" Content="Install PowerVCF (try VMware.PowerVCF then PowerVCF)" MinWidth="210"/>
            <Button x:Name="btnInstallNSX" Content="Install NSX SDK (VMware.VMC.NSXT)" MinWidth="210"/>
            <Button x:Name="btnInstallPosh" Content="Install Posh-SSH" MinWidth="210"/>
          </StackPanel>
        </Grid>
      </GroupBox>
      <GroupBox Header="Certificate Chain (any format: PEM/DER/P7B/PFX)" Grid.Column="1">
        <StackPanel>
          <TextBlock Text="Tip: Use CA bundle (Root + Intermediate). Root-only is allowed; ESXi push is skipped by default." Foreground="Gold" Margin="8,0,8,4"/>
          <Grid Margin="8,0,8,0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="140"/>
            </Grid.ColumnDefinitions>
            <TextBox x:Name="txtChain" Grid.Column="0" Height="28" Margin="0,0,8,0"/>
            <Button x:Name="btnBrowseChain" Grid.Column="1" Content="Browse..." Height="28" MinWidth="120"/>
          </Grid>
        </StackPanel>
      </GroupBox>
    </Grid>
    <!-- Row 1: Targets -->
    <GroupBox Header="Targets (vCenter, NSX, SDDC-Manager, VCF-Installer, VCF-Operations)" Grid.Row="1">
      <StackPanel>
        <CheckBox x:Name="chkPushEsxi" Content="Push to ESXi hosts (optional)" IsChecked="False"/>
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
              <DataGridTextColumn Header="API Username" Width="*"><DataGridTextColumn.Binding><Binding Path="Username" UpdateSourceTrigger="PropertyChanged"/></DataGridTextColumn.Binding></DataGridTextColumn>
              <DataGridTemplateColumn Header="API Password" Width="*"><DataGridTemplateColumn.CellTemplate><DataTemplate><PasswordBox x:Name="pbApi" Tag="{Binding}" /></DataTemplate></DataGridTemplateColumn.CellTemplate></DataGridTemplateColumn>
              <DataGridTextColumn Header="SSH Username (optional)" Width="*"><DataGridTextColumn.Binding><Binding Path="SshUsername" UpdateSourceTrigger="PropertyChanged"/></DataGridTextColumn.Binding></DataGridTextColumn>
              <DataGridTemplateColumn Header="SSH Password (optional)" Width="*"><DataGridTemplateColumn.CellTemplate><DataTemplate><PasswordBox x:Name="pbSsh" Tag="{Binding}" /></DataTemplate></DataGridTemplateColumn.CellTemplate></DataGridTemplateColumn>
              <DataGridTextColumn Header="Port" Width="80"><DataGridTextColumn.Binding><Binding Path="Port" UpdateSourceTrigger="PropertyChanged"/></DataGridTextColumn.Binding></DataGridTextColumn>
              <DataGridComboBoxColumn Header="Type" Width="220">
                <DataGridComboBoxColumn.SelectedItemBinding><Binding Path="Type" UpdateSourceTrigger="PropertyChanged"/></DataGridComboBoxColumn.SelectedItemBinding>
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
      </StackPanel>
    </GroupBox>
    <!-- Row 2: Results + Log -->
    <Grid Grid.Row="2">
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
          <Button x:Name="btnOpenLog" Content="Open Log" DockPanel.Dock="Top"/>
          <TextBox x:Name="txtLog" AcceptsReturn="True" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Height="420" MaxHeight="520"/>
        </DockPanel>
      </GroupBox>
    </Grid>
    <!-- Row 3: Actions (compact) -->
    <GroupBox Header="Actions" Grid.Row="3">
      <Grid Margin="8">
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Grid.Column="0">
          <TextBlock Text="Reports Path:" Margin="0,0,8,0" VerticalAlignment="Center"/>
          <TextBox x:Name="txtReportsPath" MinWidth="520" IsReadOnly="True" Height="28"/>
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
"@; $xaml=$xaml.Replace('{#VER#}',$Global:SSLInspectVersion)
try { $script:window=[Windows.Markup.XamlReader]::Parse($xaml) } catch { [System.Windows.MessageBox]::Show("XAML parse failed:`r`n$($_.Exception.Message)","XAML Error",'OK','Error') | Out-Null; throw }
$script:window.WindowState='Maximized'
$script:txtLog=$script:window.FindName('txtLog'); $script:txtChain=$script:window.FindName('txtChain'); $script:btnBrowseChain=$script:window.FindName('btnBrowseChain'); $script:gridTargets=$script:window.FindName('gridTargets'); $script:btnAdd=$script:window.FindName('btnAdd'); $script:btnRemove=$script:window.FindName('btnRemove'); $script:btnLoadTargets=$script:window.FindName('btnLoadTargets'); $script:btnSaveTargets=$script:window.FindName('btnSaveTargets'); $script:gridResults=$script:window.FindName('gridResults'); $script:btnOpenLog=$script:window.FindName('btnOpenLog'); $script:btnOpenOut=$script:window.FindName('btnOpenOut'); $script:btnBrowseReports=$script:window.FindName('btnBrowseReports'); $script:txtReports=$script:window.FindName('txtReportsPath'); $script:btnTest=$script:window.FindName('btnTest'); $script:btnRun=$script:window.FindName('btnRun'); $script:btnClose=$script:window.FindName('btnClose'); $script:btnRecheck=$script:window.FindName('btnRecheck'); $script:btnInstallPCLI=$script:window.FindName('btnInstallPCLI'); $script:btnInstallVCF=$script:window.FindName('btnInstallVCF'); $script:btnInstallNSX=$script:window.FindName('btnInstallNSX'); $script:btnInstallPosh=$script:window.FindName('btnInstallPosh'); $script:lblPS=$script:window.FindName('lblPS'); $script:lblWPF=$script:window.FindName('lblWPF'); $script:lblPCLI=$script:window.FindName('lblPCLI'); $script:lblVCFP=$script:window.FindName('lblVCFP'); $script:lblSDK=$script:window.FindName('lblSDK'); $script:lblPoshSSH=$script:window.FindName('lblPoshSSH'); $script:chkPushEsxi=$script:window.FindName('chkPushEsxi');
$script:TargetsOC=New-Object System.Collections.ObjectModel.ObservableCollection[psobject]; $script:Rows=New-Object System.Collections.ObjectModel.ObservableCollection[psobject]
$script:gridTargets.ItemsSource=$script:TargetsOC; $script:gridResults.ItemsSource=$script:Rows
$script:uiTimer=New-Object System.Windows.Threading.DispatcherTimer; $script:uiTimer.Interval=[TimeSpan]::FromMilliseconds(150)
$script:uiTimer.add_Tick({ try { $sb=New-Object System.Text.StringBuilder; while ($true) { if (-not $script:logQueue.TryDequeue([ref]$line)) { break }; [void]$sb.Append($line) }; if ($sb.Length -gt 0 -and $script:txtLog) { $script:txtLog.AppendText($sb.ToString()); $script:txtLog.ScrollToEnd() } } catch {} })
try { $script:uiTimer.Start() } catch {}
$script:window.Add_ContentRendered({ try { if (-not $script:RunDir) { $null=New-RunDir -Base $script:ReportsBase }; if ($script:txtReports) { $script:txtReports.Text=$script:ReportsBase }; Write-Log "==== SSLInspect UI started (v$Global:SSLInspectVersion) ===="; Write-Log "Run folder: $script:RunDir" } catch {}; try { $script:uiTimer.Start() } catch {}; Prereq-Check | Out-Null })
function Set-StatusText{ param([System.Windows.Controls.TextBlock]$Label,[string]$Text,[string]$State) if (-not $Label) { return }; $Label.Text=$Text; switch ($State){ 'OK' { $Label.Foreground=[Windows.Media.Brushes]::LightGreen } 'WARN' { $Label.Foreground=[Windows.Media.Brushes]::Gold } 'FAIL' { $Label.Foreground=[Windows.Media.Brushes]::Tomato } default { $Label.Foreground=[Windows.Media.Brushes]::White } } }
function Prereq-Check{ $ok=$true; $isPS7=$PSVersionTable.PSVersion.Major -ge 7; Set-StatusText -Label $script:lblPS -Text ("PowerShell {0}" -f $PSVersionTable.PSVersion) -State $(if($isPS7){'OK'}else{'FAIL'}); $ok=$ok -and $isPS7; Set-StatusText -Label $script:lblWPF -Text '.NET/WPF: OK' -State 'OK'; $hasPCLI=Has-PowerCLI; if ($hasPCLI) { Import-PowerCLIQuiet | Out-Null }; Set-StatusText -Label $script:lblPCLI -Text ($hasPCLI ? 'VMware.PowerCLI: Found' : 'VMware.PowerCLI: Not found') -State ($hasPCLI ? 'OK':'WARN'); $hasVCF=Has-PowerVCF; Set-StatusText -Label $script:lblVCFP -Text ($hasVCF ? 'PowerVCF: Found' : 'PowerVCF: Not found') -State ($hasVCF ? 'OK':'WARN'); $hasNSX=!!(Get-Module -ListAvailable -Name VMware.VMC.NSXT | Select-Object -First 1); Set-StatusText -Label $script:lblSDK -Text ($hasNSX ? 'NSX SDK (VMware.VMC.NSXT): Found' : 'NSX SDK (VMware.VMC.NSXT): Not found') -State ($hasNSX ? 'OK':'WARN'); $hasPosh=Has-PoshSSH; Set-StatusText -Label $script:lblPoshSSH -Text ($hasPosh ? 'Posh-SSH: Found' : 'Posh-SSH: Not found') -State ($hasPosh ? 'OK':'WARN'); if ($script:btnRun){ $script:btnRun.IsEnabled=$ok }; return $ok }
if ($script:btnRecheck){ $script:btnRecheck.Add_Click({ Prereq-Check | Out-Null }) }
if ($script:btnInstallPCLI){ $script:btnInstallPCLI.Add_Click({ Write-Log 'Install button clicked: VMware.PowerCLI'; Ensure-Module -Name 'VMware.PowerCLI' | Out-Null; Prereq-Check | Out-Null }) }
if ($script:btnInstallVCF){ $script:btnInstallVCF.Add_Click({ Write-Log 'Install button clicked: PowerVCF'; Ensure-Module -Name 'VMware.PowerVCF' | Out-Null; Prereq-Check | Out-Null }) }
if ($script:btnInstallNSX){ $script:btnInstallNSX.Add_Click({ Write-Log 'Install button clicked: VMware.VMC.NSXT'; Ensure-NSXSDK | Out-Null; Prereq-Check | Out-Null }) }
if ($script:btnInstallPosh){ $script:btnInstallPosh.Add_Click({ Write-Log 'Install button clicked: Posh-SSH'; Ensure-Module -Name 'Posh-SSH' | Out-Null; Prereq-Check | Out-Null }) }
function Get-PasswordBoxesForRowIndex([int]$RowIndex){ $result=@{}; try { $rowCont=$script:gridTargets.ItemContainerGenerator.ContainerFromIndex($RowIndex); if (-not $rowCont) { return $result }; $stack=New-Object System.Collections.Stack; $stack.Push($rowCont); while ($stack.Count -gt 0) { $node=$stack.Pop(); if ($node -is [System.Windows.Controls.PasswordBox]) { $result[$node.Name]=$node }; $count=[Windows.Media.VisualTreeHelper]::GetChildrenCount($node); for ($i2=0; $i2 -lt $count; $i2++) { $stack.Push([Windows.Media.VisualTreeHelper]::GetChild($node,$i2)) } } } catch { Write-Log "Get-PasswordBoxes error: $($_.Exception.Message)" 'WARN' }; return $result }
function Capture-Passwords{ try { for ($i=0; $i -lt $script:gridTargets.Items.Count; $i++){ $row=$script:gridTargets.Items[$i]; if (-not $row) { continue }; foreach($p in 'Password','SshPassword'){ if (-not $row.PSObject.Properties[$p]){ Add-Member -InputObject $row -NotePropertyName $p -NotePropertyValue '' -Force } }; $pbs=Get-PasswordBoxesForRowIndex $i; if ($pbs.ContainsKey('pbApi')) { $row.Password=$pbs['pbApi'].Password } else { Write-Log "Row $($i): API PasswordBox not realized — continuing." 'WARN' }; if ($pbs.ContainsKey('pbSsh')) { $row.SshPassword=$pbs['pbSsh'].Password } else { Write-Log "Row $($i): SSH PasswordBox not realized — continuing." 'WARN' } } } catch { Write-Log "Capture-Passwords error: $($_.Exception.Message)" 'WARN' } }
$script:gridTargets.Add_CellEditEnding({ param($sender,$e) try { if ($e.Column -and $e.Column.Header -and $e.Column.Header.ToString() -eq 'Type'){ $row=$e.Row.Item; if ($row -and ($row.Type -match 'VCF-Operations')){ if (-not $row.PSObject.Properties['Username']){ Add-Member -InputObject $row -NotePropertyName 'Username' -NotePropertyValue '' -Force }; if ([string]::IsNullOrWhiteSpace($row.Username) -or ($row.Username -in @('root','vcf','vcf@local','administrator@vsphere.local'))){ $row.Username='admin' }; if (-not $row.PSObject.Properties['SshUsername']){ Add-Member -InputObject $row -NotePropertyName 'SshUsername' -NotePropertyValue '' -Force }; if ([string]::IsNullOrWhiteSpace($row.SshUsername)){ $row.SshUsername='root' } } } } catch { Write-Log "Type-change defaulting error: $($_.Exception.Message)" 'WARN' } })
if ($script:btnBrowseChain){ $script:btnBrowseChain.Add_Click({ $dlg=New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter='All cert files (*.pem;*.crt;*.cer;*.der;*.p7b;*.p7c;*.pfx;*.p12)|*.pem;*.crt;*.cer;*.der;*.p7b;*.p7c;*.pfx;*.p12|All files (*.*)|*.*'; if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){ $script:txtChain.Text=$dlg.FileName } }) }
if ($script:btnAdd){ $script:btnAdd.Add_Click({ $row=[pscustomobject]@{Host='vcsa.example.local';Username='administrator@vsphere.local';Password='';SshUsername='';SshPassword='';Port=443;Type='vCenter'}; $script:TargetsOC.Add($row) | Out-Null; Apply-TypeDefaults -Row $row }) }
if ($script:btnRemove){ $script:btnRemove.Add_Click({ $sel=$script:gridTargets.SelectedItem; if ($sel){ [void]$script:TargetsOC.Remove($sel) } }) }
if ($script:btnSaveTargets){ $script:btnSaveTargets.Add_Click({ try { $dlg=New-Object System.Windows.Forms.SaveFileDialog; $dlg.Filter='JSON (*.json)|*.json|All files (*.*)|*.*'; $dlg.FileName='SSLInspect-Targets.json'; if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){ $export=@(); foreach($t in $script:TargetsOC){ $normType=Normalize-TargetType $t.Type; $export += [pscustomobject]@{ Host=$t.Host; Username=$t.Username; SshUsername=$t.SshUsername; Port=[int]$t.Port; Type=$normType } }; ($export | ConvertTo-Json -Depth 3) | Set-Content -Path $dlg.FileName -Encoding UTF8; Write-Log "Targets saved: $($dlg.FileName)" } } catch { Write-Log "Save targets error: $($_.Exception.Message)" 'ERROR' } }) }
if ($script:btnLoadTargets){ $script:btnLoadTargets.Add_Click({ try { $dlg=New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter='JSON (*.json)|*.json|All files (*.*)|*.*'; if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){ $data=Get-Content -Path $dlg.FileName -Raw | ConvertFrom-Json; $script:TargetsOC.Clear(); foreach ($e in $data) { $etype = $null; if ($e.PSObject.Properties['Type'] -and $e.Type) { $etype = [string]$e.Type } else { $etype = 'vCenter' }; $type = Normalize-TargetType $etype; $defs=Get-TypeDefaults $type; $port = if ($e.PSObject.Properties['Port'] -and $e.Port) { [int]$e.Port } else { $defs.Port }; $user = if ($e.PSObject.Properties['Username'] -and $e.Username) { [string]$e.Username } else { $defs.Username }; $sshuser = if ($e.PSObject.Properties['SshUsername'] -and $e.SshUsername) { [string]$e.SshUsername } else { if ($type -eq 'VCF-Operations') { 'root' } else { '' } }; $row=[pscustomobject]@{ Host=[string]$e.Host; Username=$user; Password=''; SshUsername=$sshuser; SshPassword=''; Port=$port; Type=$type }; $script:TargetsOC.Add($row) | Out-Null; Apply-TypeDefaults -Row $row } ; Write-Log "Targets loaded: $($dlg.FileName) — Count=$($script:TargetsOC.Count)" } } catch { Write-Log "Load targets error: $($_.Exception.Message)" 'ERROR' } }) }
function Test-Target{ param([string]$Type,[string]$TargetHost,[string]$User,[string]$Pass,[int]$Port) $Type=Normalize-TargetType $Type; switch ($Type) { 'vCenter' { try { if (-not (Ensure-Module -Name 'VMware.PowerCLI')) { throw 'VMware.PowerCLI not available.' }; $vi=$null; try { $vi=Connect-VIServer -Server $TargetHost -User $User -Password $Pass -Force -ErrorAction Stop; $null=Get-Datacenter -Server $vi -ErrorAction SilentlyContinue; [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Pass';Message='HTTPS /sdk reachable'} } finally { if ($vi){ Disconnect-VIServer -Server $vi -Force -Confirm:$false | Out-Null } } } catch { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Fail';Message=$_.Exception.Message} } } 'VCF-Operations' { try { if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Pass)) { throw 'API Username and Password are required for VCF-Operations.' }; $base="https://$TargetHost/suite-api"; try { $t=Invoke-RestMethod -Method Post -Uri "$base/api/auth/token/acquire" -ContentType 'application/json' -Body (@{ username=$User; password=$Pass } | ConvertTo-Json) -SkipCertificateCheck; if ($t.token) { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Pass';Message='VCF Ops token OK (API supported)'} } else { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Warn';Message='API did not return token; SSH fallback available'} } } catch { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Warn';Message='API token failed; SSH fallback available (use a VCF Ops UI admin)'} } } catch { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Fail';Message=$_.Exception.Message} } } 'SDDC-Manager' { try { $tok=Invoke-RestMethod -Method Post -Uri ("https://{0}/v1/tokens" -f $TargetHost) -ContentType 'application/json' -Body (@{ username=$User; password=$Pass } | ConvertTo-Json) -SkipCertificateCheck; if ($tok.accessToken) { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Info';Message='Appears to be in VCF Installer mode (token OK). Use “VCF-Installer”.'} } else { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Fail';Message='Token not returned'} } } catch { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='API';Status='Fail';Message=$_.Exception.Message} } } default { [pscustomobject]@{Host=$TargetHost;Type=$Type;Step='Test';Status='Info';Message=("Type '{0}' not implemented" -f $Type)} } } }
if ($script:btnTest){ $script:btnTest.Add_Click({ try { Capture-Passwords; Start-Sleep -Milliseconds 100; Capture-Passwords; Write-Log '==== Test connection started ===='; try { foreach($t in $script:TargetsOC){ Apply-TypeDefaults -Row $t } } catch {}; foreach($t in $script:TargetsOC){ if ([string]::IsNullOrWhiteSpace($t.Host)) { $script:Rows.Add([pscustomobject]@{Host=$t.Host;Type=$t.Type;Step='Test';Status='Info';Message='Skipped: Host required'}) | Out-Null; continue }; $res=Test-Target -Type $t.Type -TargetHost $t.Host -User (Coalesce $t.Username '') -Pass (Coalesce $t.Password '') -Port ([int]$t.Port); $script:Rows.Add($res)|Out-Null; Write-Log ("[{0}] Test: {1} — {2}" -f $t.Host,$res.Status,$res.Message) }; Write-Log '==== Test connection finished ====' } catch { Write-Log "Test error: $($_.Exception.Message)" 'ERROR'; [System.Windows.MessageBox]::Show("Test error: $($_.Exception.Message)","SSLInspect",'OK','Error') | Out-Null } }) }
function Write-ChainDumpL{ param([string]$PemText,[string]$OutPath) try { $objs=Get-CertObjectsFromPemText -PemText $PemText; $rows=foreach($x in $objs){ $isCA=(Is-CACert $x); [pscustomobject]@{ Subject=$x.Subject; Issuer=$x.Issuer; SelfSigned=($x.Subject -eq $x.Issuer); IsCA=$isCA; Thumbprint=$x.Thumbprint; NotBefore=$x.NotBefore; NotAfter=$x.NotAfter } }; ($rows | Format-Table | Out-String) | Set-Content -Path $OutPath -Encoding UTF8; Write-Log "Chain debug written: $OutPath" } catch { Write-Log "Chain dump skipped: $($_.Exception.Message)" 'WARN' } }
function Connect-VIServer-Retry{ param([string]$Server,[string]$User,[string]$Pass,[int]$Attempts=2) for($i=1;$i -le $Attempts;$i++){ try { return Connect-VIServer -Server $Server -User $User -Password $Pass -Force -ErrorAction Stop } catch { if ($i -eq $Attempts){ throw } else { Start-Sleep -Seconds 2; Write-Log "[$Server] Connect-VIServer retry $($i+1) after error: $($_.Exception.Message)" 'WARN' } } } }
if ($script:btnRun){ $script:btnRun.Add_Click({ try { if (-not (Prereq-Check)) { [System.Windows.MessageBox]::Show('Prerequisites not met. Install required modules first.','SSLInspect','OK','Warning') | Out-Null; return }; Capture-Passwords; Start-Sleep -Milliseconds 100; Capture-Passwords; if (-not (Test-Path $script:txtChain.Text)) { throw 'Chain file not found.' }; $inputPath=$script:txtChain.Text; Write-Log 'Normalizing input to PEM (der/pem/p7b/pfx supported)…'; $pfxPass=$null; if ($inputPath.ToLower().EndsWith('.pfx') -or $inputPath.ToLower().EndsWith('.p12')) { $pfxPass=Read-PfxPasswordPrompt -Path $inputPath }; $norm=Resolve-CertFileToPem -InputPath $inputPath -OutputDir $script:RunDir -PfxPassword $pfxPass; $normalizedPemPath=$norm.Path; $normalizedPemText=$norm.PemText; $certObjs=$norm.Certs; Write-Log ("Normalized to {0} cert(s) → {1}" -f $certObjs.Count,$normalizedPemPath); Write-ChainDumpL -PemText $normalizedPemText -OutPath (Join-Path $script:RunDir 'ChainDebug.txt'); $expectedCATPs=New-Object System.Collections.Generic.HashSet[string]; foreach($x in $certObjs){ if (Is-CACert $x){ $null=$expectedCATPs.Add($x.Thumbprint.ToUpperInvariant()) } } $script:Rows.Clear(); Write-Log '==== Run started ====';
  $rootOnly=($certObjs.Count -eq 1 -and (Is-CACert $certObjs[0]))
  if ($rootOnly){ Write-Log 'Single CA root detected — ESXi push will be skipped for this run.' 'WARN' }
  foreach($t in $script:TargetsOC){ Apply-TypeDefaults -Row $t; $targetHost=$t.Host; $targetType=(Normalize-TargetType $t.Type); $apiUser=$t.Username; $apiPass=$t.Password; $port=[int]$t.Port; $sshUser=if (-not [string]::IsNullOrWhiteSpace($t.SshUsername)) { $t.SshUsername } else { $apiUser }; $sshPass=if (-not [string]::IsNullOrWhiteSpace($t.SshPassword)) { $t.SshPassword } else { $apiPass }; if ([string]::IsNullOrWhiteSpace($targetHost)) { $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Run';Status='Fail';Message='Missing Host'}) | Out-Null; continue };
    try {
      switch ($targetType) {
        'vCenter' {
          if (-not (Ensure-Module -Name 'VMware.PowerCLI')) { throw 'VMware.PowerCLI not available.' }
          $pushEsxiReq=$script:chkPushEsxi.IsChecked
          $pushEsxi=($pushEsxiReq -and (-not $rootOnly))
          if ($pushEsxiReq -and $rootOnly){ Write-Log "[$targetHost] ESXi push requested but root-only chain detected — skipping host push." 'WARN' }
          Write-Log ("[{0}] Importing normalized PEM into vCenter (PowerCLI); Push ESXi={1}" -f $targetHost,$pushEsxi)
          $vi=$null; $pcErr=$null; $verified=$false; $hits=@()
          try { $vi=Connect-VIServer-Retry -Server $targetHost -User $apiUser -Pass $apiPass -Attempts 2; if ($pushEsxi) { Add-VITrustedCertificate -Server $vi -PemCertificateOrChain $normalizedPemText -Confirm:$false -ErrorAction Stop | Out-Null } else { Add-VITrustedCertificate -Server $vi -VCenterOnly -PemCertificateOrChain $normalizedPemText -Confirm:$false -ErrorAction Stop | Out-Null } } catch { $pcErr=$_.Exception.Message; Write-Log "[$targetHost] PowerCLI import error: $pcErr" 'WARN' } finally { if ($vi) { Disconnect-VIServer -Server $vi -Force -Confirm:$false | Out-Null } }
          if (-not $pcErr){
            try { $vi=Connect-VIServer-Retry -Server $targetHost -User $apiUser -Pass $apiPass -Attempts 2; $vcTrusted=Get-VITrustedCertificate -Server $vi -VCenterOnly; $hits=@($vcTrusted | Where-Object { $expectedCATPs.Contains($_.Thumbprint.ToUpperInvariant()) }); if ($hits.Count -gt 0) { $verified=$true } } catch { Write-Log "[$targetHost] PowerCLI verify error: $($_.Exception.Message)" 'WARN' } finally { if ($vi){ Disconnect-VIServer -Server $vi -Force -Confirm:$false | Out-Null } }
          }
          if ($verified){
            $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Pass';Message=("Imported via PowerCLI; verified {0} certificate(s)" -f $hits.Count)}) | Out-Null
          } else {
            Write-Log "[$targetHost] Falling back to vCenter REST trusted_root_chains (create+verify)…" 'WARN'
            try {
              $rest=Add-VcTrustedRootChainRestEx -VcFqdn $targetHost -User $apiUser -Pass $apiPass -PemChain $normalizedPemText -ExpectedThumbprints @($expectedCATPs)
              $mapKeys=($rest.FoundMap.Keys -join ',')
              if ($rest.FoundMap.Count -gt 0) {
                $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Pass';Message=("vCenter REST import OK; chainId={0}; Verified in IDs: [{1}]" -f $rest.NewChainId,$mapKeys)}) | Out-Null
              } else {
                $msg=("vCenter REST executed (chainId={0}); verification did not locate expected thumbprint(s). HTTP={1} {2}" -f $rest.NewChainId,(Coalesce $rest.Http ""),(Coalesce $rest.Error ""))
                $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Warn';Message=$msg}) | Out-Null
              }
            } catch {
              $d=Get-HttpErrorDetail -Ex $_.Exception
              $msg=("REST fallback failed: HTTP={0} {1}" -f (Coalesce $d.Code ""),(Coalesce $d.Snippet $_.Exception.Message))
              $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Fail';Message=$msg}) | Out-Null
            }
          }
        }
        'VCF-Operations' {
          $didApi=$false
          try {
            Write-Log "[$targetHost] Importing normalized PEM into VCF-Operations via API (UI-visible)…"
            $base="https://$targetHost/suite-api"; $tok=Invoke-RestMethod -Method Post -Uri "$base/api/auth/token/acquire" -ContentType 'application/json' -Body (@{ username=$apiUser; password=$apiPass } | ConvertTo-Json) -SkipCertificateCheck
            if (-not $tok.token) { throw 'token/acquire did not return a token' }
            $hdrs=@{ Authorization = "vRealizeOpsToken $($tok.token)" }
            Invoke-RestMethod -Method Post -Uri "$base/api/certificate" -Headers $hdrs -SkipCertificateCheck -Form @{ certificateFile = Get-Item $normalizedPemPath } | Out-Null
            $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Pass';Message='VCF Ops API import completed; visible in UI'}) | Out-Null
            $didApi=$true
          } catch { Write-Log "[$targetHost] VCF Ops API import failed: $($_.Exception.Message) — will try SSH if creds available." 'WARN' }
          if (-not $didApi){
            try { $res2=Invoke-VCFOpsTrustedImport3 -HostFqdn $targetHost -Username $sshUser -Password $sshPass -Port ($(if ($port -gt 0) { $port } else { 22 })) -PemText $normalizedPemText; $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Pass';Message=("SSH fallback: {0}" -f $res2.Message)}) | Out-Null }
            catch { $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Fail';Message=$_.Exception.Message}) | Out-Null }
          }
        }
        'SDDC-Manager' { $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Install';Status='Info';Message='Use Installer API or SDK as per previous versions'}) | Out-Null }
        default { $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Run';Status='Fail';Message=("Unsupported Type '{0}'" -f $targetType)}) | Out-Null }
      }
    } catch { $script:Rows.Add([pscustomobject]@{Host=$targetHost;Type=$targetType;Step='Run';Status='Fail';Message=$_.Exception.Message}) | Out-Null; Write-Log "[$targetHost] Error: $($_.Exception.Message)" 'ERROR' }
  }
  $outCsv=Join-Path $script:RunDir 'Results.csv'; ($script:Rows | Select-Object Host,Type,Step,Status,Message) | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8; Write-Log "CSV saved: $outCsv"; Write-Log ("==== Run finished (Rows={0}) ====" -f $script:Rows.Count)
} catch { Write-Log "Run error: $($_.Exception.Message)" 'ERROR'; [System.Windows.MessageBox]::Show("Run error: $($_.Exception.Message)","SSLInspect",'OK','Error') | Out-Null } }) }
$script:TargetsOC.Add([pscustomobject]@{Host='vcsa.example.local';Username='administrator@vsphere.local';Password='';SshUsername='';SshPassword='';Port=443;Type='vCenter'}) | Out-Null
$null=$script:window.ShowDialog()