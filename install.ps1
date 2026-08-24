[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$projectDirectory = $PSScriptRoot
$launcherPath = Join-Path $projectDirectory "scripts\flagkit.ps1"
$startMenuDirectory = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$desktopDirectory = [Environment]::GetFolderPath("Desktop")
$shortcutLocations = @(
    (Join-Path $startMenuDirectory "FlagKit CTF Toolbox.lnk"),
    (Join-Path $desktopDirectory "FlagKit CTF Toolbox.lnk")
)

if (-not (Test-Path $launcherPath -PathType Leaf)) {
    throw "FlagKit launcher was not found at $launcherPath"
}

if (-not (Get-Command "py.exe" -ErrorAction SilentlyContinue) -and
    -not (Get-Command "python.exe" -ErrorAction SilentlyContinue)) {
    throw "Python 3 is required. Install it from https://www.python.org/downloads/windows/ and run setup again."
}

$shell = New-Object -ComObject WScript.Shell
$powershellPath = Join-Path $PSHOME "powershell.exe"

foreach ($shortcutLocation in $shortcutLocations) {
    $shortcut = $shell.CreateShortcut($shortcutLocation)
    $shortcut.TargetPath = $powershellPath
    $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`""
    $shortcut.WorkingDirectory = $projectDirectory
    $shortcut.Description = "Local toolbox for legal CTF challenges and security labs"
    $shortcut.Save()
}

Write-Host "FlagKit setup is complete." -ForegroundColor Green
Write-Host "Use the FlagKit CTF Toolbox shortcut on your desktop or in the Start menu."
