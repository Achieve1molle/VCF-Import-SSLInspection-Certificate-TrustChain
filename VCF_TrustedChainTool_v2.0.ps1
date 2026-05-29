<#
.SYNOPSIS
  Achieve One - VCF Trusted Certificate Import UI v2.0
.DESCRIPTION
  Standalone WinForms UI using Posh-SSH ShellStream for interactive `su -`.
  Cosmetic/layout update: original-style dark theme, resizable layout, no clipped prerequisite buttons, simplified action bar.
  Functional behavior:
    - Import cert does NOT restart services.
    - Restart Services is an explicit on-demand action.
    - Validate Keystore saves full keytool -list -v output.
    - No Auto-Detect Proxy Cert.
    - No skip logic; existing alias is deleted then re-imported.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$script:Version = '3.0.2-shellstream-ui'
$script:ReportsBase = (Get-Location).Path
$script:RunDir = $null
$script:LogFile = $null
$script:Results = New-Object System.Collections.Generic.List[object]

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security

$script:Colors = [ordered]@{
  Form      = [System.Drawing.Color]::FromArgb(15,15,16)
  Panel     = [System.Drawing.Color]::FromArgb(28,28,30)
  Control   = [System.Drawing.Color]::FromArgb(37,37,38)
  Header    = [System.Drawing.Color]::FromArgb(45,45,48)
  Border    = [System.Drawing.Color]::FromArgb(90,90,90)
  Text      = [System.Drawing.Color]::FromArgb(243,243,243)
  Accent    = [System.Drawing.Color]::FromArgb(0,122,204)
  Select    = [System.Drawing.Color]::FromArgb(62,95,138)
  Gold      = [System.Drawing.Color]::Gold
  Pass      = [System.Drawing.Color]::LightGreen
  Fail      = [System.Drawing.Color]::Tomato
}

function New-RunDir {
  param([string]$BasePath)
  if ([string]::IsNullOrWhiteSpace($BasePath) -or -not (Test-Path $BasePath)) { $BasePath = (Get-Location).Path }
  $script:RunDir = Join-Path $BasePath ('VCFTrust-Run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
  New-Item -ItemType Directory -Force -Path $script:RunDir | Out-Null
  $script:LogFile = Join-Path $script:RunDir ('VCFTrust-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
  '' | Set-Content -Path $script:LogFile -Encoding UTF8
}
function Write-Log {
  param([string]$Message,[string]$Level='INFO')
  $line = '[{0}][{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'),$Level,$Message
  try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch {}
  try { $script:txtLog.AppendText($line + [Environment]::NewLine); $script:txtLog.SelectionStart = $script:txtLog.Text.Length; $script:txtLog.ScrollToCaret() } catch {}
  Write-Host $line
}
function Add-Result {
  param([string]$TargetName,[string]$Type,[string]$Step,[string]$Status,[string]$Message)
  $obj = [pscustomobject]@{ Host=$TargetName; Type=$Type; Step=$Step; Status=$Status; Message=$Message }
  $script:Results.Add($obj) | Out-Null
  try { [void]$script:gridResults.Rows.Add($TargetName,$Type,$Step,$Status,$Message) } catch {}
  $lvl = if($Status -eq 'Pass'){'PASS'}elseif($Status -eq 'Fail'){'FAIL'}elseif($Status -eq 'Warn'){'WARN'}else{'INFO'}
  Write-Log "[$TargetName][$Type][$Step] $Status - $Message" $lvl
}
function Export-Reports {
  $csv = Join-Path $script:RunDir 'Results.csv'
  $html = Join-Path $script:RunDir 'RemediationReport.html'
  $script:Results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
  $style = '<style>body{font-family:Segoe UI,Arial;background:#111;color:#eee}table{border-collapse:collapse}td,th{border:1px solid #555;padding:4px 8px}th{background:#333}</style>'
  $script:Results | ConvertTo-Html -Head $style -Title 'VCF Trust Remediation Report' -PreContent "<h1>VCF Trust Remediation Report</h1><p>Run folder: $script:RunDir</p>" | Set-Content -Path $html -Encoding UTF8
  Write-Log "Reports exported: $csv ; $html"
}
function Ensure-Module {
  param([string]$Name,[switch]$InstallIfMissing)
  if (-not (Get-Module -ListAvailable -Name $Name | Select-Object -First 1)) {
    if (-not $InstallIfMissing) { return $false }
    Write-Log "Installing module $Name..." 'WARN'
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null
    Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -ErrorAction Stop
  }
  Import-Module $Name -ErrorAction Stop | Out-Null
  return $true
}
function Check-Prereqs {
  try {
    $script:lblPS.Text = "PowerShell: $($PSVersionTable.PSVersion)"; $script:lblPS.ForeColor = $script:Colors.Pass
    if (Get-Module -ListAvailable -Name Posh-SSH | Select-Object -First 1) { $script:lblPosh.Text='Posh-SSH: Found'; $script:lblPosh.ForeColor=$script:Colors.Pass } else { $script:lblPosh.Text='Posh-SSH: Not found'; $script:lblPosh.ForeColor=$script:Colors.Gold }
    if (Get-Module -ListAvailable -Name VMware.PowerCLI | Select-Object -First 1) { $script:lblPCLI.Text='VMware.PowerCLI: Found'; $script:lblPCLI.ForeColor=$script:Colors.Pass } else { $script:lblPCLI.Text='VMware.PowerCLI: Not found'; $script:lblPCLI.ForeColor=$script:Colors.Gold }
  } catch { Write-Log "Prereq check failed: $($_.Exception.Message)" 'WARN' }
}
function Redact-Text { param([string]$Text,[string[]]$Secrets) $out=$Text+''; foreach($s in $Secrets){ if($s){ $out=$out -replace [regex]::Escape($s),'[REDACTED]' } }; $out }
function Remove-Ansi { param([string]$Text) if($null -eq $Text){return ''}; (($Text -replace "`e\[[0-9;?]*[ -/]*[@-~]", '') -replace "`r", '') }
function Wait-StreamText { param($Stream,[string]$Pattern,[int]$TimeoutSeconds=60,[string]$Step='wait',[string[]]$Secrets=@())
  $deadline=(Get-Date).AddSeconds($TimeoutSeconds); $buf=''
  while((Get-Date) -lt $deadline){ Start-Sleep -Milliseconds 250; try{ $chunk=$Stream.Read(); if($chunk){ $buf+=$chunk; if([regex]::IsMatch((Remove-Ansi $buf),$Pattern,[System.Text.RegularExpressions.RegexOptions]::Multiline)){ return $buf } } }catch{} }
  throw "Timed out during $Step waiting for pattern [$Pattern]. Last output: $(Redact-Text -Text (Remove-Ansi $buf) -Secrets $Secrets)"
}
function Invoke-RootStreamCommand { param($Stream,[string]$Command,[int]$TimeoutSeconds=900,[string]$Label='command',[string[]]$Secrets=@())
  $marker='VCFTRUST_DONE_' + ([guid]::NewGuid().ToString('N'))
  $Stream.WriteLine("$Command`necho $marker `$?")
  $out=Wait-StreamText -Stream $Stream -Pattern ([regex]::Escape($marker)+'\s+(\d+)') -TimeoutSeconds $TimeoutSeconds -Step $Label -Secrets $Secrets
  $m=[regex]::Match($out,[regex]::Escape($marker)+'\s+(\d+)'); $code=if($m.Success){[int]$m.Groups[1].Value}else{999}
  [pscustomobject]@{ExitCode=$code;Output=$out}
}
function Convert-CertToPemFile { param([string]$InputPath,[string]$OutPath)
  $ext=([IO.Path]::GetExtension($InputPath)+'').ToLowerInvariant()
  if($ext -in @('.pem','.crt','.cer')){ $raw=Get-Content $InputPath -Raw -ErrorAction Stop; if($raw -match '-----BEGIN CERTIFICATE-----'){ Set-Content $OutPath $raw -Encoding ASCII; return $OutPath } }
  $cert=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($InputPath)
  $b64=[Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert),[Base64FormattingOptions]::InsertLineBreaks)
  Set-Content $OutPath "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n" -Encoding ASCII; return $OutPath
}
function Open-RootShell { param([object]$Target)
  if(-not(Ensure-Module Posh-SSH)){ throw 'Posh-SSH module is required.' }
  $cred=[pscredential]::new($Target.Username,(ConvertTo-SecureString $Target.LoginPassword -AsPlainText -Force))
  $session=New-SSHSession -ComputerName $Target.TargetName -Port ([int]$Target.Port) -Credential $cred -AcceptKey -ConnectionTimeout 15 -ErrorAction Stop
  try{
    $stream=$session.Session.CreateShellStream('VCFTrustShell',120,40,0,0,4096); $secrets=@($Target.LoginPassword,$Target.RootPassword)
    $initial=Wait-StreamText -Stream $stream -Pattern '(?m)[#>$]\s*$' -TimeoutSeconds 60 -Step 'initial shell prompt' -Secrets $secrets
    try{ (Redact-Text -Text (Remove-Ansi $initial) -Secrets $secrets) | Set-Content (Join-Path $script:RunDir "InitialShellOutput-$($Target.TargetName -replace '[^A-Za-z0-9_.-]','_').txt") -Encoding UTF8 }catch{}
    Write-Log "[$($Target.TargetName)] Switching to root with interactive su - ..."; $stream.WriteLine('su -')
    [void](Wait-StreamText -Stream $stream -Pattern '(?i)password:' -TimeoutSeconds 30 -Step 'su password prompt' -Secrets $secrets)
    $stream.WriteLine($Target.RootPassword)
    $suOut=Wait-StreamText -Stream $stream -Pattern '(?m)#\s*$' -TimeoutSeconds 90 -Step 'root prompt after su' -Secrets $secrets
    if((Remove-Ansi $suOut) -match '(?i)authentication failure|su:'){ throw "su failed: $(Redact-Text -Text (Remove-Ansi $suOut) -Secrets $secrets)" }
    Write-Log "[$($Target.TargetName)] Root shell acquired." 'PASS'
    [pscustomobject]@{Session=$session;Stream=$stream;Secrets=$secrets}
  } catch { try{Remove-SSHSession -SSHSession $session|Out-Null}catch{}; throw }
}
function Save-KeytoolReport { param([string]$TargetName,[string]$Alias,[string]$Output)
  $safeHost=$TargetName -replace '[^A-Za-z0-9_.-]','_'; $safeAlias=$Alias -replace '[^A-Za-z0-9_.-]','_'
  $path=Join-Path $script:RunDir ("KeytoolList-{0}-{1}.txt" -f $safeHost,$safeAlias)
  $clean=Remove-Ansi $Output; $m=[regex]::Match($clean,'KEYTOOL_LIST_BEGIN\s*([\s\S]*?)\s*KEYTOOL_LIST_END')
  if($m.Success){ $m.Groups[1].Value.Trim() | Set-Content $path -Encoding UTF8 } else { $clean | Set-Content $path -Encoding UTF8 }
  $path
}
function Invoke-ImportOnly { param([object]$Target,[string]$CertPath,[string]$Alias)
  if(-not(Test-Path $CertPath)){ throw "Certificate file not found: $CertPath" }
  $root=Open-RootShell -Target $Target
  try{
    $pemLocal=Join-Path $script:RunDir ('NormalizedCertificate-' + ([guid]::NewGuid().ToString('N')) + '.pem'); Convert-CertToPemFile -InputPath $CertPath -OutPath $pemLocal|Out-Null
    $pemText=Get-Content $pemLocal -Raw -Encoding ASCII; $remotePem="/tmp/vcftrust-$Alias.pem"
    Write-Log "[$($Target.TargetName)] Uploading certificate to $remotePem via shell heredoc..."
    $token='VCFTRUSTCERT_'+([guid]::NewGuid().ToString('N')); $upload="cat > '$remotePem' <<'$token'`n$pemText`n$token`nchmod 600 '$remotePem'"
    $r=Invoke-RootStreamCommand -Stream $root.Stream -Command $upload -TimeoutSeconds 120 -Label 'upload cert' -Secrets $root.Secrets
    if($r.ExitCode -ne 0){ throw "Certificate upload failed. ExitCode=$($r.ExitCode)" }
    $kb=@"
set -u
KEY=`$(cat /etc/vmware/vcf/commonsvcs/trusted_certificates.key)
echo "KEY_READ=YES"
COMMON='/etc/vmware/vcf/commonsvcs/trusted_certificates.store'
JAVA='/etc/alternatives/jre/lib/security/cacerts'
CERT='$remotePem'
ALIAS='$Alias'
keytool -delete -alias "`$ALIAS" -keystore "`$COMMON" -storepass "`$KEY" >/dev/null 2>&1 || true
keytool -delete -alias "`$ALIAS" -keystore "`$JAVA" -storepass changeit >/dev/null 2>&1 || true
printf 'yes\n' | keytool -importcert -alias "`$ALIAS" -file "`$CERT" -keystore "`$COMMON" -storepass "`$KEY"
COMMON_RC=`$?
echo "COMMON_IMPORT_RC=`$COMMON_RC"
if [ "`$COMMON_RC" -ne 0 ]; then exit 20; fi
printf 'yes\n' | keytool -importcert -alias "`$ALIAS" -file "`$CERT" -keystore "`$JAVA" -storepass changeit
JAVA_RC=`$?
echo "JAVA_IMPORT_RC=`$JAVA_RC"
if [ "`$JAVA_RC" -ne 0 ]; then exit 21; fi
keytool -list -keystore "`$COMMON" -storepass "`$KEY" -alias "`$ALIAS" >/dev/null 2>&1
VALIDATE_ALIAS_RC=`$?
echo "VALIDATE_ALIAS_RC=`$VALIDATE_ALIAS_RC"
if [ "`$VALIDATE_ALIAS_RC" -ne 0 ]; then exit 22; fi
echo KEYTOOL_LIST_BEGIN
keytool -list -v -keystore "`$COMMON" -storepass "`$KEY"
echo KEYTOOL_LIST_END
"@
    Write-Log "[$($Target.TargetName)] Running import workflow as root. Restart is intentionally skipped."
    $res=Invoke-RootStreamCommand -Stream $root.Stream -Command $kb -TimeoutSeconds 1200 -Label 'import workflow' -Secrets $root.Secrets
    $red=Redact-Text -Text (Remove-Ansi $res.Output) -Secrets $root.Secrets
    $full=Join-Path $script:RunDir ("FullShellOutput-Import-{0}-{1}.txt" -f ($Target.TargetName -replace '[^A-Za-z0-9_.-]','_'),($Alias -replace '[^A-Za-z0-9_.-]','_'))
    $red | Set-Content $full -Encoding UTF8; $report=Save-KeytoolReport -TargetName $Target.TargetName -Alias $Alias -Output $red
    if($res.ExitCode -ne 0){ throw "Import workflow failed. ExitCode=$($res.ExitCode). Full output: $full" }
    if((Get-Content $report -Raw) -notmatch ('Alias name:\s*' + [regex]::Escape($Alias.ToLowerInvariant()))){ throw "Alias $Alias was not found in keytool report: $report" }
    [pscustomobject]@{Report=$report;FullOutput=$full}
  } finally { try{Remove-SSHSession -SSHSession $root.Session|Out-Null}catch{} }
}
function Invoke-RestartServices { param([object]$Target)
  $root=Open-RootShell -Target $Target
  try{
    $cmd="printf 'y\n' | /opt/vmware/vcf/operationsmanager/scripts/cli/sddcmanager_restart_services.sh`necho RESTART_RC `$?"
    Write-Log "[$($Target.TargetName)] Restarting SDDC Manager services on demand..."
    $res=Invoke-RootStreamCommand -Stream $root.Stream -Command $cmd -TimeoutSeconds 900 -Label 'restart services' -Secrets $root.Secrets
    $red=Redact-Text -Text (Remove-Ansi $res.Output) -Secrets $root.Secrets
    $path=Join-Path $script:RunDir ("RestartServices-{0}.txt" -f ($Target.TargetName -replace '[^A-Za-z0-9_.-]','_'))
    $red | Set-Content $path -Encoding UTF8
    if($res.ExitCode -ne 0){ throw "Restart command failed. ExitCode=$($res.ExitCode). Output: $path" }
    $path
  } finally { try{Remove-SSHSession -SSHSession $root.Session|Out-Null}catch{} }
}
function Invoke-ValidateKeystore { param([object]$Target,[string]$Alias)
  $root=Open-RootShell -Target $Target
  try{
    $cmd=@"
KEY=`$(cat /etc/vmware/vcf/commonsvcs/trusted_certificates.key)
COMMON='/etc/vmware/vcf/commonsvcs/trusted_certificates.store'
ALIAS='$Alias'
keytool -list -keystore "`$COMMON" -storepass "`$KEY" -alias "`$ALIAS" >/dev/null 2>&1
VALIDATE_ALIAS_RC=`$?
echo "VALIDATE_ALIAS_RC=`$VALIDATE_ALIAS_RC"
echo KEYTOOL_LIST_BEGIN
keytool -list -v -keystore "`$COMMON" -storepass "`$KEY"
echo KEYTOOL_LIST_END
if [ "`$VALIDATE_ALIAS_RC" -ne 0 ]; then exit 22; fi
"@
    Write-Log "[$($Target.TargetName)] Validating commonsvcs keystore..."
    $res=Invoke-RootStreamCommand -Stream $root.Stream -Command $cmd -TimeoutSeconds 900 -Label 'validate keystore' -Secrets $root.Secrets
    $red=Redact-Text -Text (Remove-Ansi $res.Output) -Secrets $root.Secrets; $report=Save-KeytoolReport -TargetName $Target.TargetName -Alias $Alias -Output $red
    if($res.ExitCode -ne 0){ throw "Validation failed. ExitCode=$($res.ExitCode). Report: $report" }
    $report
  } finally { try{Remove-SSHSession -SSHSession $root.Session|Out-Null}catch{} }
}

# ---------------- UI ----------------
[System.Windows.Forms.Application]::EnableVisualStyles()
New-RunDir -BasePath $script:ReportsBase
$form=New-Object System.Windows.Forms.Form
$form.Text="Achieve One - VCF Trusted Certificate Import UI v$script:Version"
$form.MinimumSize=New-Object System.Drawing.Size(1280,780)
$form.Size=New-Object System.Drawing.Size(1520,900)
$form.StartPosition='CenterScreen'; $form.BackColor=$script:Colors.Form; $form.ForeColor=$script:Colors.Text; $form.Font=New-Object System.Drawing.Font('Segoe UI',9)
function Style-Button($b){ $b.FlatStyle='Flat'; $b.FlatAppearance.BorderColor=$script:Colors.Border; $b.BackColor=$script:Colors.Control; $b.ForeColor=$script:Colors.Text; $b.Height=30 }
function New-Button($text,$parent){ $b=New-Object System.Windows.Forms.Button; $b.Text=$text; Style-Button $b; $parent.Controls.Add($b); $b }
function New-Group($text,$parent){ $g=New-Object System.Windows.Forms.GroupBox; $g.Text=$text; $g.ForeColor=$script:Colors.Text; $g.BackColor=$script:Colors.Form; $parent.Controls.Add($g); $g }
function New-Label($text,$parent){ $l=New-Object System.Windows.Forms.Label; $l.Text=$text; $l.ForeColor=$script:Colors.Text; $parent.Controls.Add($l); $l }
function New-TextBox($parent){ $t=New-Object System.Windows.Forms.TextBox; $t.BackColor=$script:Colors.Control; $t.ForeColor=$script:Colors.Text; $t.BorderStyle='FixedSingle'; $parent.Controls.Add($t); $t }
function Style-Grid($grid){
  $grid.AllowUserToAddRows=$false; $grid.RowHeadersVisible=$false; $grid.BackgroundColor=$script:Colors.Panel; $grid.BorderStyle='FixedSingle'; $grid.AutoSizeColumnsMode='Fill'; $grid.EnableHeadersVisualStyles=$false
  $grid.ColumnHeadersDefaultCellStyle.BackColor=$script:Colors.Header; $grid.ColumnHeadersDefaultCellStyle.ForeColor=$script:Colors.Text
  $grid.DefaultCellStyle.BackColor=$script:Colors.Panel; $grid.DefaultCellStyle.ForeColor=$script:Colors.Text; $grid.DefaultCellStyle.SelectionBackColor=$script:Colors.Select; $grid.DefaultCellStyle.SelectionForeColor=$script:Colors.Text
  $grid.GridColor=$script:Colors.Border
}
$grpPrereq=New-Group 'Prerequisites' $form
$grpCert=New-Group 'Certificate / Alias' $form
$grpTargets=New-Group 'Targets' $form
$grpInfo=New-Group 'Workflow Notes' $form
$grpResults=New-Group 'Per-Target Results' $form
$grpLog=New-Group 'Log' $form
$grpActions=New-Group 'Actions' $form

$script:lblPS=New-Label 'PowerShell: checking...' $grpPrereq; $script:lblPS.ForeColor=$script:Colors.Pass
$script:lblPosh=New-Label 'Posh-SSH: checking...' $grpPrereq
$script:lblPCLI=New-Label 'VMware.PowerCLI: checking...' $grpPrereq
$btnRecheck=New-Button 'Recheck' $grpPrereq; $btnInstallPosh=New-Button 'Install Posh-SSH' $grpPrereq; $btnInstallPCLI=New-Button 'Install PowerCLI' $grpPrereq

$txtCert=New-TextBox $grpCert; $btnBrowse=New-Button 'Browse Certificate...' $grpCert; $lblAlias=New-Label 'Alias:' $grpCert; $txtAlias=New-TextBox $grpCert; $txtAlias.Text='VCFSSLProxy'; $lblCertNote=New-Label 'Import does NOT restart services. Use Restart Services after one or more cert imports.' $grpCert; $lblCertNote.ForeColor=$script:Colors.Gold
$btnAdd=New-Button 'Add Row' $grpTargets; $btnRemove=New-Button 'Remove Selected' $grpTargets; $btnLoad=New-Button 'Load Targets' $grpTargets; $btnSave=New-Button 'Save Targets' $grpTargets; $btnExample=New-Button 'Generate Example JSON' $grpTargets
$gridTargets=New-Object System.Windows.Forms.DataGridView; $script:gridTargets=$gridTargets; Style-Grid $gridTargets; $grpTargets.Controls.Add($gridTargets)
[void]$gridTargets.Columns.Add('TargetName','Host (FQDN/IP)')
$typeCol=New-Object System.Windows.Forms.DataGridViewComboBoxColumn; $typeCol.Name='Type'; $typeCol.HeaderText='Type'; [void]$typeCol.Items.Add('SDDC-Manager'); [void]$typeCol.Items.Add('VCF-Installer'); $gridTargets.Columns.Add($typeCol)|Out-Null
[void]$gridTargets.Columns.Add('Username','Login Username'); [void]$gridTargets.Columns.Add('LoginPassword','Login Password'); [void]$gridTargets.Columns.Add('RootPassword','Root Password for su -'); [void]$gridTargets.Columns.Add('Port','Port')
$gridTargets.Columns['TargetName'].FillWeight=260; $gridTargets.Columns['Type'].FillWeight=90; $gridTargets.Columns['Username'].FillWeight=120; $gridTargets.Columns['LoginPassword'].FillWeight=120; $gridTargets.Columns['RootPassword'].FillWeight=140; $gridTargets.Columns['Port'].FillWeight=50
$gridTargets.add_CellFormatting({ param($sender,$e) if($e.ColumnIndex -ge 0){ $name=$sender.Columns[$e.ColumnIndex].Name; if($name -in @('LoginPassword','RootPassword') -and $e.Value){ $e.Value='●' * ([string]$e.Value).Length; $e.FormattingApplied=$true } } })
$gridTargets.add_EditingControlShowing({ param($sender,$e) if($e.Control -is [System.Windows.Forms.TextBox]){ $colName=$sender.Columns[$sender.CurrentCell.ColumnIndex].Name; if($colName -in @('LoginPassword','RootPassword')){$e.Control.UseSystemPasswordChar=$true}else{$e.Control.UseSystemPasswordChar=$false} } })
$lblWorkflow=New-Label 'Import = upload cert, su -, KEY=cat trusted_certificates.key, force delete alias, import commonsvcs, import Java cacerts, validate and save keytool report. Restart is separate.' $grpInfo; $lblWorkflow.ForeColor=$script:Colors.Gold
$gridResults=New-Object System.Windows.Forms.DataGridView; $script:gridResults=$gridResults; Style-Grid $gridResults; $gridResults.ReadOnly=$true; $grpResults.Controls.Add($gridResults)
[void]$gridResults.Columns.Add('Host','Host'); [void]$gridResults.Columns.Add('Type','Type'); [void]$gridResults.Columns.Add('Step','Step'); [void]$gridResults.Columns.Add('Status','Status'); [void]$gridResults.Columns.Add('Message','Message'); $gridResults.Columns['Message'].FillWeight=260
$btnOpenLog=New-Button 'Open Log' $grpLog; $txtLog=New-Object System.Windows.Forms.TextBox; $script:txtLog=$txtLog; $txtLog.Multiline=$true; $txtLog.ScrollBars='Vertical'; $txtLog.BackColor=$script:Colors.Control; $txtLog.ForeColor=$script:Colors.Text; $txtLog.BorderStyle='FixedSingle'; $grpLog.Controls.Add($txtLog)
$lblReports=New-Label 'Reports Path:' $grpActions; $txtReports=New-TextBox $grpActions; $txtReports.Text=$script:ReportsBase
$btnBrowseReports=New-Button 'Browse...' $grpActions; $btnTest=New-Button 'Test Login' $grpActions; $btnImport=New-Button 'Import Cert' $grpActions; $btnValidate=New-Button 'Validate Keystore' $grpActions; $btnRestart=New-Button 'Restart Services' $grpActions; $btnClose=New-Button 'Close' $grpActions

function Layout-Ui {
  $m=10; $w=$form.ClientSize.Width; $h=$form.ClientSize.Height
  $topH=118; $actionsH=74; $notesH=58; $targetsH=[Math]::Max(220,[int](($h-$topH-$notesH-$actionsH-70)*0.42)); $midY=$m+$topH+$m+$targetsH+$m+$notesH+$m; $midH=[Math]::Max(160,$h-$midY-$actionsH-$m*2)
  $leftW=[int](($w-$m*3)*0.55); $rightW=$w-$leftW-$m*3
  $grpPrereq.SetBounds($m,$m,430,$topH); $grpCert.SetBounds($m+440,$m,$w-450-$m,$topH)
  $grpTargets.SetBounds($m,$m+$topH+$m,$w-$m*2,$targetsH)
  $grpInfo.SetBounds($m,$grpTargets.Bottom+$m,$w-$m*2,$notesH)
  $grpResults.SetBounds($m,$midY,$leftW,$midH); $grpLog.SetBounds($grpResults.Right+$m,$midY,$rightW,$midH)
  $grpActions.SetBounds($m,$h-$actionsH-$m,$w-$m*2,$actionsH)
  $script:lblPS.SetBounds(15,25,240,22); $script:lblPosh.SetBounds(15,50,240,22); $script:lblPCLI.SetBounds(15,75,240,22)
  $btnRecheck.SetBounds(285,20,125,28); $btnInstallPosh.SetBounds(285,50,125,28); $btnInstallPCLI.SetBounds(285,80,125,28)
  $txtCert.SetBounds(15,25,[Math]::Max(250,$grpCert.Width-300),24); $btnBrowse.SetBounds($txtCert.Right+10,23,160,28)
  $lblAlias.SetBounds(15,63,50,22); $txtAlias.SetBounds(65,60,220,24); $lblCertNote.SetBounds(310,63,$grpCert.Width-330,22)
  $btnAdd.SetBounds(15,25,85,28); $btnRemove.SetBounds(110,25,125,28); $btnLoad.SetBounds(245,25,115,28); $btnSave.SetBounds(370,25,115,28); $btnExample.SetBounds(495,25,170,28); $gridTargets.SetBounds(15,65,$grpTargets.Width-30,$grpTargets.Height-80)
  $lblWorkflow.SetBounds(15,24,$grpInfo.Width-30,22)
  $gridResults.SetBounds(15,25,$grpResults.Width-30,$grpResults.Height-40)
  $btnOpenLog.SetBounds(15,23,$grpLog.Width-30,28); $txtLog.SetBounds(15,60,$grpLog.Width-30,$grpLog.Height-75)
  $lblReports.SetBounds(15,32,90,22); $txtReports.SetBounds(105,29,[Math]::Max(220,$grpActions.Width-850),24); $btnBrowseReports.SetBounds($txtReports.Right+10,27,90,28)
  $x=$grpActions.Width-585; foreach($pair in @(@($btnTest,110),@($btnImport,110),@($btnValidate,140),@($btnRestart,135),@($btnClose,70))){ $pair[0].SetBounds($x,27,$pair[1],28); $x += $pair[1]+10 }
}
$form.Add_Resize({ Layout-Ui })
function Get-TargetsFromGrid { $targets=@(); foreach($row in $gridTargets.Rows){ if($row.IsNewRow){continue}; $targets += [pscustomobject]@{ TargetName=[string]$row.Cells['TargetName'].Value; Type=if($row.Cells['Type'].Value){[string]$row.Cells['Type'].Value}else{'SDDC-Manager'}; Username=if($row.Cells['Username'].Value){[string]$row.Cells['Username'].Value}else{'vcf'}; LoginPassword=[string]$row.Cells['LoginPassword'].Value; RootPassword=[string]$row.Cells['RootPassword'].Value; Port=if($row.Cells['Port'].Value){[int]$row.Cells['Port'].Value}else{22} } }; $targets }
function Add-DefaultRow { $idx=$gridTargets.Rows.Add(); $gridTargets.Rows[$idx].Cells['Type'].Value='SDDC-Manager'; $gridTargets.Rows[$idx].Cells['Username'].Value='vcf'; $gridTargets.Rows[$idx].Cells['Port'].Value='22' }
function Set-Busy([bool]$Busy){ foreach($b in @($btnTest,$btnImport,$btnValidate,$btnRestart,$btnClose,$btnBrowse,$btnLoad,$btnSave,$btnAdd,$btnRemove)){ $b.Enabled = -not $Busy }; if($Busy){$form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor}else{$form.Cursor=[System.Windows.Forms.Cursors]::Default} }

$btnRecheck.Add_Click({Check-Prereqs}); $btnInstallPosh.Add_Click({try{Ensure-Module Posh-SSH -InstallIfMissing|Out-Null;Check-Prereqs}catch{Write-Log $_.Exception.Message 'ERROR'}}); $btnInstallPCLI.Add_Click({try{Ensure-Module VMware.PowerCLI -InstallIfMissing|Out-Null;Check-Prereqs}catch{Write-Log $_.Exception.Message 'ERROR'}})
$btnAdd.Add_Click({Add-DefaultRow}); $btnRemove.Add_Click({foreach($r in @($gridTargets.SelectedRows)){if(-not $r.IsNewRow){$gridTargets.Rows.Remove($r)}}})
$btnBrowse.Add_Click({$d=New-Object System.Windows.Forms.OpenFileDialog;$d.Filter='Certificate files (*.pem;*.crt;*.cer;*.der)|*.pem;*.crt;*.cer;*.der|All files (*.*)|*.*';if($d.ShowDialog() -eq 'OK'){$txtCert.Text=$d.FileName}})
$btnBrowseReports.Add_Click({$d=New-Object System.Windows.Forms.FolderBrowserDialog;if($d.ShowDialog() -eq 'OK'){$script:ReportsBase=$d.SelectedPath;$txtReports.Text=$script:ReportsBase;New-RunDir $script:ReportsBase;Write-Log "New run folder: $script:RunDir"}})
$btnOpenLog.Add_Click({if(Test-Path $script:LogFile){Invoke-Item $script:LogFile}}); $btnClose.Add_Click({$form.Close()})
$btnSave.Add_Click({$d=New-Object System.Windows.Forms.SaveFileDialog;$d.Filter='JSON (*.json)|*.json';$d.FileName='VCFTrust-Targets.json';if($d.ShowDialog() -eq 'OK'){Get-TargetsFromGrid|ForEach-Object{[pscustomobject]@{TargetName=$_.TargetName;Type=$_.Type;Username=$_.Username;Port=$_.Port}}|ConvertTo-Json -Depth 4|Set-Content $d.FileName -Encoding UTF8;Write-Log "Targets saved without passwords: $($d.FileName)"}})
$btnLoad.Add_Click({$d=New-Object System.Windows.Forms.OpenFileDialog;$d.Filter='JSON (*.json)|*.json|All files (*.*)|*.*';if($d.ShowDialog() -eq 'OK'){$gridTargets.Rows.Clear();$data=Get-Content $d.FileName -Raw|ConvertFrom-Json;foreach($e in @($data)){$idx=$gridTargets.Rows.Add();$gridTargets.Rows[$idx].Cells['TargetName'].Value=[string]$e.TargetName;$gridTargets.Rows[$idx].Cells['Type'].Value=if($e.Type){[string]$e.Type}else{'SDDC-Manager'};$gridTargets.Rows[$idx].Cells['Username'].Value=if($e.Username){[string]$e.Username}else{'vcf'};$gridTargets.Rows[$idx].Cells['Port'].Value=if($e.Port){[string]$e.Port}else{'22'}};Write-Log 'Targets loaded. Passwords are intentionally not stored.'}})
$btnExample.Add_Click({$d=New-Object System.Windows.Forms.SaveFileDialog;$d.Filter='JSON (*.json)|*.json';$d.FileName='VCFTrust-Targets-Example.json';if($d.ShowDialog() -eq 'OK'){@([pscustomobject]@{TargetName='sddc-manager01.example.local';Type='SDDC-Manager';Username='vcf';Port=22},[pscustomobject]@{TargetName='vcf-installer01.example.local';Type='VCF-Installer';Username='vcf';Port=22})|ConvertTo-Json -Depth 4|Set-Content $d.FileName -Encoding UTF8;Write-Log "Example JSON saved: $($d.FileName)"}})
$btnTest.Add_Click({try{Set-Busy $true;$script:Results.Clear();$gridResults.Rows.Clear();Write-Log '==== Test Login started ====';foreach($t in Get-TargetsFromGrid){try{if(-not(Ensure-Module Posh-SSH)){throw 'Posh-SSH missing.'};$cred=[pscredential]::new($t.Username,(ConvertTo-SecureString $t.LoginPassword -AsPlainText -Force));$s=New-SSHSession -ComputerName $t.TargetName -Port $t.Port -Credential $cred -AcceptKey -ConnectionTimeout 15;try{$r=Invoke-SSHCommand -SSHSession $s -Command 'whoami; hostname' -TimeOut 60;Add-Result $t.TargetName $t.Type 'Test' 'Pass' (($r.Output+$r.Error)-join '; ')}finally{Remove-SSHSession -SSHSession $s|Out-Null}}catch{Add-Result $t.TargetName $t.Type 'Test' 'Fail' $_.Exception.Message}};Export-Reports;Write-Log '==== Test Login finished ===='}catch{Write-Log $_.Exception.Message 'ERROR'}finally{Set-Busy $false}})
$btnImport.Add_Click({try{Set-Busy $true;if(-not(Test-Path $txtCert.Text)){throw 'Select a certificate file first.'};$alias=$txtAlias.Text.Trim();if(-not $alias){throw 'Alias is required.'};$script:Results.Clear();$gridResults.Rows.Clear();Write-Log '==== Import Cert started ====';foreach($t in Get-TargetsFromGrid){try{$r=Invoke-ImportOnly -Target $t -CertPath $txtCert.Text -Alias $alias;Add-Result $t.TargetName $t.Type 'Import' 'Pass' "Imported and validated. Keytool report: $($r.Report). Restart not run."}catch{Add-Result $t.TargetName $t.Type 'Import' 'Fail' $_.Exception.Message}};Export-Reports;Write-Log '==== Import Cert finished ===='}catch{Write-Log $_.Exception.Message 'ERROR';[System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Import failed')|Out-Null}finally{Set-Busy $false}})
$btnValidate.Add_Click({try{Set-Busy $true;$alias=$txtAlias.Text.Trim();if(-not $alias){throw 'Alias is required.'};$script:Results.Clear();$gridResults.Rows.Clear();Write-Log '==== Validate Keystore started ====';foreach($t in Get-TargetsFromGrid){try{$report=Invoke-ValidateKeystore -Target $t -Alias $alias;Add-Result $t.TargetName $t.Type 'Validate' 'Pass' "Alias found. Keytool report: $report"}catch{Add-Result $t.TargetName $t.Type 'Validate' 'Fail' $_.Exception.Message}};Export-Reports;Write-Log '==== Validate Keystore finished ===='}catch{Write-Log $_.Exception.Message 'ERROR'}finally{Set-Busy $false}})
$btnRestart.Add_Click({try{Set-Busy $true;$script:Results.Clear();$gridResults.Rows.Clear();Write-Log '==== Restart Services started ====';foreach($t in Get-TargetsFromGrid){try{$out=Invoke-RestartServices -Target $t;Add-Result $t.TargetName $t.Type 'Restart' 'Pass' "Restart initiated. Output: $out"}catch{Add-Result $t.TargetName $t.Type 'Restart' 'Fail' $_.Exception.Message}};Export-Reports;Write-Log '==== Restart Services finished ===='}catch{Write-Log $_.Exception.Message 'ERROR'}finally{Set-Busy $false}})

Add-DefaultRow
Layout-Ui
Write-Log "==== VCF Trust UI started v$script:Version ===="
Write-Log "Run folder: $script:RunDir"
Check-Prereqs
[void]$form.ShowDialog()
