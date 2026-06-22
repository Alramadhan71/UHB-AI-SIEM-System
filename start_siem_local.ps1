Set-Location -LiteralPath $PSScriptRoot

$Url = "http://localhost:5000"
$PortInUse = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue

if ($PortInUse) {
    Write-Host "SIEM is already running on port 5000."
    Write-Host "Restarting it so the latest code changes are loaded..."
    $PortInUse | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object {
        Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
}

Write-Host "Starting SIEM local server..."
Write-Host "URL: $Url"
Write-Host "Login: admin / admin123"
Write-Host ""
Write-Host "Keep this window open while using the dashboard."
Write-Host "Press Ctrl+C here to stop the server."
Write-Host ""

Start-Job -ScriptBlock {
    Start-Sleep -Seconds 2
    Start-Process "http://localhost:5000"
} | Out-Null

python .\siem_web.py *>> .\server.run.log
