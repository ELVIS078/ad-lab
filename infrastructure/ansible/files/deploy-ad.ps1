<#
.SYNOPSIS
    One-shot AD lab bootstrap for dc01: promotes the domain controller
    (if not already done via Ansible), creates the vulnerable-by-design
    test accounts the attack chain targets, and turns on the logging
    trinity (Sysmon, ScriptBlockLogging, process-creation auditing with
    command line) everything else in ttps/ depends on.

    This is the manual/standalone equivalent of
    ansible/playbooks/promote-dc.yml + part of ansible/playbooks/site.yml -
    use it if you want to run Day 1 by hand on the console instead of via
    Ansible/WinRM, or to see exactly what those playbooks automate.

.NOTES
    Run as Administrator on dc01, inside the isolated lab network only.
    Every account/password here is intentionally weak - that IS the lab
    scenario (Kerberoasting / AS-REP roasting targets). Never reuse these
    patterns outside this lab.
#>

param(
    [string]$DomainName    = "lab.local",
    [string]$DomainNetbios = "LAB",
    [string]$SafeModePwd   = "ChangeMe_Lab123!"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "`n[*] $msg" -ForegroundColor Cyan }

# ---------------------------------------------------------------------
# 1. Promote to Domain Controller (skips cleanly if already promoted)
# ---------------------------------------------------------------------
Write-Step "Checking AD DS status..."
$alreadyDC = Get-Service NTDS -ErrorAction SilentlyContinue
if (-not $alreadyDC) {
    Write-Step "Installing AD-Domain-Services + DNS features..."
    Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools

    Write-Step "Promoting dc01 to first DC of new forest '$DomainName'..."
    $securePwd = ConvertTo-SecureString $SafeModePwd -AsPlainText -Force
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $DomainNetbios `
        -SafeModeAdministratorPassword $securePwd `
        -InstallDns `
        -Force `
        -NoRebootOnCompletion:$false
    # Box reboots here. Re-run this script after logon to continue
    # with steps 2-4 (it will skip this block since NTDS now exists).
    return
}
Write-Host "    Already a DC - continuing." -ForegroundColor DarkGray

# ---------------------------------------------------------------------
# 2. Vulnerable-by-design test accounts (the whole point of this lab)
# ---------------------------------------------------------------------
Import-Module ActiveDirectory
$baseDN = (Get-ADDomain).DistinguishedName

Write-Step "Creating OUs..."
foreach ($ou in "Workstations", "ServiceAccounts", "LabUsers") {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path $baseDN
    }
}

Write-Step "Creating svc-sql (Kerberoasting target: weak password + SPN)..."
$svcPwd = ConvertTo-SecureString "SvcAcct_Weak123" -AsPlainText -Force
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc-sql'" -ErrorAction SilentlyContinue)) {
    New-ADUser -Name "svc-sql" `
        -SamAccountName "svc-sql" `
        -AccountPassword $svcPwd `
        -PasswordNeverExpires $true `
        -Enabled $true `
        -Path "OU=ServiceAccounts,$baseDN"
    # The SPN is what makes it roastable - any authenticated user can
    # request a TGS for it.
    setspn -A MSSQLSvc/dc01.$DomainName:1433 svc-sql
}

Write-Step "Creating backup-svc (AS-REP roasting target: no pre-auth required)..."
$backupPwd = ConvertTo-SecureString "Backup_Weak456" -AsPlainText -Force
if (-not (Get-ADUser -Filter "SamAccountName -eq 'backup-svc'" -ErrorAction SilentlyContinue)) {
    New-ADUser -Name "backup-svc" `
        -SamAccountName "backup-svc" `
        -AccountPassword $backupPwd `
        -PasswordNeverExpires $true `
        -Enabled $true `
        -Path "OU=ServiceAccounts,$baseDN"
}
Set-ADAccountControl -Identity "backup-svc" -DoesNotRequirePreAuth $true

Write-Step "Creating helpdesk + jsmith (ACL-abuse path: helpdesk gets GenericAll on jsmith)..."
foreach ($u in @(
    @{ Name = "helpdesk"; Pwd = "Helpdesk_Weak789" },
    @{ Name = "jsmith";   Pwd = "Jsmith_Weak789" }
)) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Name)'" -ErrorAction SilentlyContinue)) {
        $p = ConvertTo-SecureString $u.Pwd -AsPlainText -Force
        New-ADUser -Name $u.Name -SamAccountName $u.Name -AccountPassword $p `
            -PasswordNeverExpires $true -Enabled $true -Path "OU=LabUsers,$baseDN"
    }
}
$jsmithDN    = (Get-ADUser jsmith).DistinguishedName
$helpdeskSID = (Get-ADUser helpdesk).SID
$acl = Get-Acl "AD:\$jsmithDN"
$identity = [System.Security.Principal.IdentityReference] $helpdeskSID
$adRight  = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
$type     = [System.Security.AccessControl.AccessControlType] "Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRight, $type, $inheritanceType)
$acl.AddAccessRule($ace)
Set-Acl -Path "AD:\$jsmithDN" -AclObject $acl

Write-Step "Granting a mid-tier group DCSync rights (domain-compromise target)..."
# In a real environment this would be a misconfiguration someone
# inherited, not something granted on purpose - that's the point.
if (-not (Get-ADGroup -Filter "Name -eq 'Tier1-Admins'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name "Tier1-Admins" -GroupScope Global -Path $baseDN
}
$dcsyncRights = "Replicating Directory Changes", "Replicating Directory Changes All"
# Granting these cleanly requires dsacls against the domain root; kept
# as a documented manual step since it's a one-off per lab build:
Write-Host "    Run manually (dsacls output is verbose, not worth wrapping here):" -ForegroundColor Yellow
Write-Host "    dsacls `"$baseDN`" /I:S /G `"$DomainNetbios\Tier1-Admins:CA;$($dcsyncRights[0])`"" -ForegroundColor Yellow
Write-Host "    dsacls `"$baseDN`" /I:S /G `"$DomainNetbios\Tier1-Admins:CA;$($dcsyncRights[1])`"" -ForegroundColor Yellow
Write-Host "    Then: Add-ADGroupMember Tier1-Admins -Members jsmith   # once jsmith is compromised via ACL abuse" -ForegroundColor Yellow

# ---------------------------------------------------------------------
# 3. Logging trinity: Sysmon + ScriptBlockLogging + 4688 w/ command line
# ---------------------------------------------------------------------
Write-Step "Enabling PowerShell ScriptBlockLogging..."
$sblPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $sblPath -Force | Out-Null
Set-ItemProperty -Path $sblPath -Name "EnableScriptBlockLogging" -Value 1

Write-Step "Enabling process-creation auditing with command line (Event ID 4688)..."
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
$cmdLinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $cmdLinePath -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $cmdLinePath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

Write-Step "Enabling Kerberos auditing (needed for 4768/4769 - Kerberoasting/AS-REP detection)..."
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null

Write-Step "Enabling directory service access auditing (needed for 4662/5136 - DCSync/ACL change detection)..."
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null

Write-Host "`n[+] Sysmon itself is installed via ansible/roles/sysmon (separate step - needs the" -ForegroundColor Green
Write-Host "    SwiftOnSecurity config downloaded, not worth duplicating in a PS1)." -ForegroundColor Green
Write-Host "[+] Day 1 bootstrap complete. Snapshot this VM now, before any attack runs." -ForegroundColor Green
