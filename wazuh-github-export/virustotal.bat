@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$input | & '%~dp0virustotal.ps1'"
