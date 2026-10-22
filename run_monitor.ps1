<#
.SYNOPSIS
    Setup and launch script for Windows Network Observability Monitor.

.DESCRIPTION
    Ensures all prerequisite Windows tools and Python 3.10+ are available,
    creates and maintains a dedicated Python virtual environment (.venv),
    installs/verifies all required packages from requirements.txt (including ctxlogkit),
    and starts the monitor in unified mode (or custom flags).

.PARAMETER Headless
    Runs the monitor without the terminal curses TUI (great for background/server use).

.PARAMETER Web
    Starts the web dashboard inside the same process (defaults to true).

.PARAMETER Port
    Web dashboard port (default: 5000).

.PARAMETER ListenHost
    Web dashboard host (default: 127.0.0.1). Use 0.0.0.0 to expose to LAN.

.PARAMETER Debug
    Enables verbose subprocess debug logging to logs/network_monitor_debug.log.

.EXAMPLE
    .\run_monitor.ps1
    # Sets up .venv, verifies dependencies, and launches monitor with web dashboard at http://127.0.0.1:5000

.EXAMPLE
    .\run_monitor.ps1 -Headless -Web -Port 8080 -ListenHost 0.0.0.0
    # Runs headless with web dashboard on all network interfaces on port 8080
#>

[CmdletBinding()]
param (
    [switch]$Headless,
    [switch]$Web = $true,
    [int]$Port = 5000,
    [string]$ListenHost = "127.0.0.1",
    [switch]$Debug
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Fatal {
    param([string]$Message)
    Write-Host "[X] Error: $Message" -ForegroundColor Red
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Windows Network Observability Monitor Setup & Runner   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Platform verification
if ($PSVersionTable.PSEdition -ne "Desktop" -and (-not $IsWindows)) {
    Write-Fatal "This application requires Microsoft Windows 10 or later."
}

# 2. Check essential Windows networking utilities
$tools = @("ping", "tracert", "ipconfig", "netsh", "git")
foreach ($tool in $tools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Fatal "Required utility '$tool' is not found on your system PATH."
    }
}
Write-Success "All required Windows system utilities and git found on PATH."

# 3. Locate Python (3.10+)
$pyCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pyCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pyCmd = "py"
} else {
    Write-Fatal "Python was not found on PATH. Please install Python 3.10 or later from https://python.org or via winget."
}

# Verify Python version >= 3.10
$pyVerStr = (& $pyCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
$pyVerMajor, $pyVerMinor = $pyVerStr.Split('.') | ForEach-Object { [int]$_ }
if ($pyVerMajor -lt 3 -or ($pyVerMajor -eq 3 -and $pyVerMinor -lt 10)) {
    Write-Fatal "Python 3.10+ is required. Detected version: $pyVerStr"
}
Write-Success "Detected Python $pyVerStr ($pyCmd)."

# 4. Virtual environment setup (.venv)
$repoRoot = $PSScriptRoot
$venvDir = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$venvPip = Join-Path $venvDir "Scripts\pip.exe"

if (-not (Test-Path $venvPython)) {
    Write-Step "Creating dedicated virtual environment at '$venvDir'..."
    & $pyCmd -m venv $venvDir
    if (-not (Test-Path $venvPython)) {
        Write-Fatal "Failed to create virtual environment."
    }
    Write-Success "Virtual environment created successfully."
} else {
    Write-Success "Virtual environment (.venv) already exists."
}

# 5. Ensure dependencies from requirements.txt are installed
$reqFile = Join-Path $repoRoot "requirements.txt"
if (Test-Path $reqFile) {
    Write-Step "Verifying and updating installed Python packages..."
    # Check if packages are already importable in venv
    $importCheck = & $venvPython -c "import psutil, flask, requests, yaml, curses, ctxlogkit; print('OK')" 2>$null
    if ($importCheck -ne "OK") {
        Write-Step "Installing/updating dependencies in .venv..."
        & $venvPip install --quiet --upgrade pip
        & $venvPip install -r $reqFile
        if ($LASTEXITCODE -ne 0) {
            Write-Fatal "Failed to install required Python packages."
        }
        Write-Success "All dependencies installed successfully."
    } else {
        Write-Success "All required packages are already installed in .venv."
    }
} else {
    Write-WarnMsg "requirements.txt not found. Skipping dependency installation."
}

# 6. Assemble monitor command line arguments
$appArgs = @()
if ($Headless) {
    $appArgs += "--headless"
}
if ($Web) {
    $appArgs += "--web"
    $appArgs += "--port"
    $appArgs += $Port
    $appArgs += "--host"
    $appArgs += $ListenHost
}
if ($Debug) {
    $appArgs += "--debug"
}

$monitorScript = Join-Path $repoRoot "advanced_network_monitor.py"

Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
Write-Step "Launching Network Observability Monitor..."
if ($Web) {
    Write-Host "Web Dashboard URL: http://${ListenHost}:${Port}" -ForegroundColor Green
}
if ($Headless) {
    Write-Host "Mode: Headless (Background). Press Ctrl+C to terminate." -ForegroundColor Yellow
} else {
    Write-Host "Mode: Terminal Curses TUI (Press 'Q' to exit cleanly)." -ForegroundColor Yellow
}
Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray

# 7. Execute application within .venv
Set-Location $repoRoot
& $venvPython $monitorScript @appArgs
