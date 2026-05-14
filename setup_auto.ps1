# Automated Dependency Setup - PowerShell

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  PHASE 1: Python Environment" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$venv_path = ".\env\Scripts\Activate.ps1"
if (Test-Path $venv_path) {
    Write-Host "  [OK] Virtual environment found" -ForegroundColor Green
    & $venv_path
    Write-Host "  [OK] Activated" -ForegroundColor Green
} else {
    Write-Host "  [INFO] Creating virtual environment..." -ForegroundColor Yellow
    python -m venv env
    & $venv_path
    Write-Host "  [OK] Virtual environment created" -ForegroundColor Green
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  PHASE 2: Python Packages" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$packages = @(
    "numpy",
    "scipy",
    "scikit-learn",
    "networkx",
    "pandas",
    "torch",
    "faiss-cpu",
    "langchain",
    "langchain-community",
    "ollama",
    "pydantic",
    "python-dotenv",
    "requests",
    "pyyaml",
    "sympy"
)

Write-Host "  Checking packages..." -ForegroundColor Yellow
$missing = @()

foreach ($package in $packages) {
    $pkg = $package.Split("-")[0]
    $check = python -c "import $pkg" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [OK] $package" -ForegroundColor Green
    } else {
        $missing += $package
        Write-Host "    [MISS] $package" -ForegroundColor Yellow
    }
}

if ($missing.Count -gt 0) {
    Write-Host "  Installing missing packages..." -ForegroundColor Yellow
    pip install --upgrade pip 2>&1 | Out-Null
    
    foreach ($pkg in $missing) {
        Write-Host "    Installing $pkg..." -ForegroundColor Yellow
        pip install $pkg 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    [OK] $pkg" -ForegroundColor Green
        } else {
            Write-Host "    [FAIL] $pkg" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  [OK] All packages installed" -ForegroundColor Green
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  PHASE 3: Ollama" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$check_ollama = ollama --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Ollama installed" -ForegroundColor Green
    
    Write-Host "  Pulling qwen model..." -ForegroundColor Yellow
    ollama pull qwen:7b
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] qwen:7b ready" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Model pull failed" -ForegroundColor Red
    }
} else {
    Write-Host "  [NOT FOUND] Ollama not installed" -ForegroundColor Red
    Write-Host "  Download: https://ollama.ai" -ForegroundColor Yellow
    Write-Host "  Or run: winget install Ollama.Ollama" -ForegroundColor Yellow
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  PHASE 4: Requirements" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

if (Test-Path "requirements.txt") {
    Write-Host "  Installing requirements.txt..." -ForegroundColor Yellow
    pip install -r requirements.txt 2>&1 | Out-Null
    Write-Host "  [OK] Installed" -ForegroundColor Green
} else {
    Write-Host "  [NOT FOUND] requirements.txt" -ForegroundColor Yellow
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  PHASE 5: Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$critical = @{
    "numpy" = "NumPy";
    "scipy" = "SciPy";
    "sklearn" = "Scikit-Learn";
    "networkx" = "NetworkX";
    "langchain" = "LangChain"
}

$all_ok = $true
foreach ($mod in $critical.Keys) {
    $test = python -c "import $mod" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [OK] $($critical[$mod])" -ForegroundColor Green
    } else {
        Write-Host "    [FAIL] $($critical[$mod])" -ForegroundColor Red
        $all_ok = $false
    }
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

if ($all_ok) {
    Write-Host "  [SUCCESS] All dependencies ready!" -ForegroundColor Green
    Write-Host "  Next: python incident_pipeline.py" -ForegroundColor Green
} else {
    Write-Host "  [WARNING] Review errors above" -ForegroundColor Yellow
}

Write-Host "`n==========================================" -ForegroundColor Cyan
