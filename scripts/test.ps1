# Runs the full verification suite locally. Usage: powershell -File scripts/test.ps1
$ErrorActionPreference = "Stop"

Write-Host "== pytest (default, fast) =="
py -m pytest tests

Write-Host "== pytest (full incl. slow NIST 90B) =="
py -m pytest tests -m ""

Write-Host "== entropy validation report =="
py -m cli.validate

Write-Host "== e2e demo (smoke) =="
py -m cli.demo --quick

Write-Host "ALL CHECKS PASSED"
