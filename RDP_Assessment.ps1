# AUTO_INJECT_RDP_Assessment.ps1

Write-Host "`n===== RDP Security Assessment =====" -ForegroundColor Cyan

# Check RDP status
$rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

if ($rdp.fDenyTSConnections -eq 0) {
    Write-Host "[!] RDP is Enabled" -ForegroundColor Yellow
} else {
    Write-Host "[+] RDP is Disabled" -ForegroundColor Green
}

# Check Network Level Authentication
$nla = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

if ($nla.UserAuthentication -eq 1) {
    Write-Host "[+] NLA is Enabled" -ForegroundColor Green
} else {
    Write-Host "[!] NLA is Disabled" -ForegroundColor Red
}

# Check RDP firewall rules
Write-Host "`n===== RDP Firewall Rules =====" -ForegroundColor Cyan

Get-NetFirewallRule -DisplayGroup "Remote Desktop" |
    Select-Object DisplayName, Enabled, Direction, Action |
    Format-Table -AutoSize

# Check allowed source IPs
Write-Host "`n===== Allowed Source IPs =====" -ForegroundColor Cyan

Get-NetFirewallRule -DisplayGroup "Remote Desktop" |
    Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" } |
    Get-NetFirewallAddressFilter |
    Select-Object RemoteAddress |
    Format-Table -AutoSize

# Hardening recommendations
Write-Host "`n===== Recommendations =====" -ForegroundColor Cyan
Write-Host "- Disable RDP if not required."
Write-Host "- Enable NLA if RDP is required."
Write-Host "- Restrict RDP access to trusted IP addresses."
Write-Host "- Review inbound RDP firewall rules."

Write-Host "`nAssessment Complete." -ForegroundColor Green