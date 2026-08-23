$ErrorActionPreference = 'Stop'
Remove-NetFirewallRule -Group 'AVON' -ErrorAction SilentlyContinue
$outside = @(Get-NetAdapter | Where-Object { $_.Name -ne 'avon0' } | Select-Object -ExpandProperty Name)
if ($outside.Count -gt 0) {
  New-NetFirewallRule -DisplayName 'AVON block 10.0.0.0/8 off-tunnel' -Group 'AVON' -Direction Outbound -Action Block -RemoteAddress '10.0.0.0/8' -InterfaceAlias $outside | Out-Null
  New-NetFirewallRule -DisplayName 'AVON block 172.16.0.0/12 off-tunnel' -Group 'AVON' -Direction Outbound -Action Block -RemoteAddress '172.16.0.0/12' -InterfaceAlias $outside | Out-Null
}
