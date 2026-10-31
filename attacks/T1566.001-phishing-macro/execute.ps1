<#
.SYNOPSIS
    Benign simulation of T1566.001 (phishing macro execution), modeled on
    Atomic Red Team's approach: it does NOT download, persist, exfiltrate,
    or alter the system. It only reproduces the process-ancestry pattern
    (Office app -> cmd -> powershell) that a real macro payload produces,
    so Sysmon/Wazuh telemetry can be generated and the detection content
    in ../sigma and ../detection validated against real events.

.NOTES
    Run this AS THE LOGGED-IN TEST USER on client01, inside the isolated
    lab network only. It deliberately does nothing a real malicious macro
    would do beyond spawning the child process chain.
#>

Write-Host "[*] Simulating macro-triggered execution (T1566.001)..."

# In a real attack, Document_Open() in the macro would shell out roughly
# like this. We reproduce only the parent/child process chain, with a
# harmless payload (writing a marker file) standing in for whatever the
# real second stage would be.
$marker = "$env:TEMP\ttp_T1566_001_marker.txt"

# cmd.exe spawned as a child of this process (stand-in for WINWORD.EXE,
# since launching an actual Office process isn't needed to validate the
# detection logic, which keys off the cmd/powershell parent-child chain)
Start-Process -FilePath "cmd.exe" `
  -ArgumentList "/c powershell.exe -NoProfile -Command `"Set-Content -Path '$marker' -Value 'T1566.001 lab simulation — $(Get-Date)'`"" `
  -Wait

if (Test-Path $marker) {
    Write-Host "[+] Simulation complete. Marker written: $marker"
    Write-Host "[+] Check Sysmon Event ID 1 for the cmd.exe -> powershell.exe chain."
} else {
    Write-Warning "[-] Marker file not found — simulation may not have run as expected."
}
