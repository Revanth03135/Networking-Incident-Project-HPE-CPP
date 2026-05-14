# =========================================================
# AUTOMATED DEPENDENCY SETUP SCRIPT (PowerShell)
# =========================================================
# This script checks and installs all required dependencies
# for the Networking Incident Project
# =========================================================

param(
    [switch]$SkipOllama,
    [switch]$SkipModels,
    [switch]$Interactive = $true
)

# Color output
function Write-Success { Write-Host $args -ForegroundColor Green }
function Write-Error_ { Write-Host $args -ForegroundColor Red }
function Write-Warning_ { Write-Host $args -ForegroundColor Yellow }
function Write-Info { Write-Host $args -ForegroundColor Cyan }

# =========================================================
# PHASE 1: PYTHON ENVIRONMENT
# =========================================================

Write-Info "`n========== PHASE 1: Python Environment =========="

# Activate virtual environment
$venv_path = ".\env\Scripts\Activate.ps1"
if (Test-Path $venv_path) {
    Write-Info "✓ Virtual environment found, activating..."
    & $venv_path
    Write-Success "✓ Virtual environment activated"
} else {
    Write-Error_ "✗ Virtual environment not found at $venv_path"
    Write-Info "Creating virtual environment..."
    python -m venv env
    & $venv_path
    Write-Success "✓ Virtual environment created and activated"
}

# =========================================================
# PHASE 2: PYTHON PACKAGES
# =========================================================

Write-Info "`n========== PHASE 2: Python Packages =========="

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

Write-Info "Checking Python packages..."
$missing_packages = @()

foreach ($package in $packages) {
    $pkg_name = $package -split "-" | Select-Object -First 1
    $import_test = python -c "import $pkg_name" 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "✓ $package"
    } else {
        $missing_packages += $package
        Write-Warning_ "✗ $package (missing)"
    }
}

if ($missing_packages.Count -gt 0) {
    Write-Info "`nInstalling missing packages: $($missing_packages -join ', ')"
    pip install --upgrade pip
    foreach ($package in $missing_packages) {
        Write-Info "Installing $package..."
        pip install $package
        if ($LASTEXITCODE -eq 0) {
            Write-Success "✓ $package installed"
        } else {
            Write-Error_ "✗ Failed to install $package"
        }
    }
} else {
    Write-Success "`n✓ All Python packages installed"
}

# =========================================================
# PHASE 3: OLLAMA SETUP
# =========================================================

if (-not $SkipOllama) {
    Write-Info "`n========== PHASE 3: Ollama Setup =========="
    
    # Check if Ollama is installed
    try {
        $ollama_version = ollama --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "✓ Ollama found: $ollama_version"
        } else {
            throw "Ollama not accessible"
        }
    } catch {
        Write-Error_ "✗ Ollama not found"
        Write-Info "Download from: https://ollama.ai"
        Write-Info "Or install via: winget install Ollama.Ollama"
        
        $response = Read-Host "Install Ollama now? (yes/no)"
        if ($response -eq "yes") {
            Write-Info "Installing Ollama..."
            winget install Ollama.Ollama
            Write-Info "Please restart terminal after Ollama installation completes"
        }
    }
}

# =========================================================
# PHASE 4: OLLAMA MODELS
# =========================================================

if (-not $SkipModels) {
    Write-Info "`n========== PHASE 4: Ollama Models =========="
    
    $ollama_check = ollama --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        $models_to_check = @("qwen:7b")
        
        foreach ($model in $models_to_check) {
            Write-Info "Setting up model: $model"
            
            if ($model -eq "qwen:7b") {
                Write-Info "Pulling Qwen 7B model (this may take 5-10 minutes)..."
                ollama pull qwen:7b
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "✓ qwen:7b model ready"
                } else {
                    Write-Error_ "✗ Failed to pull qwen:7b"
                }
            }
        }
    } else {
        Write-Warning_ "⚠ Ollama not available, skipping model setup"
    }
}

# =========================================================
# PHASE 5: REQUIREMENTS FILE
# =========================================================

Write-Info "`n========== PHASE 5: Requirements File =========="

if (Test-Path "requirements.txt") {
    Write-Info "Installing from requirements.txt..."
    pip install -r requirements.txt
    Write-Success "✓ requirements.txt installed"
} else {
    Write-Warning_ "⚠ requirements.txt not found"
}

# =========================================================
# PHASE 6: ENVIRONMENT VERIFICATION
# =========================================================

Write-Info "`n========== PHASE 6: Environment Verification =========="

# Verify critical imports
$critical_imports = @{
    "numpy" = "NumPy";
    "scipy" = "SciPy";
    "sklearn" = "Scikit-Learn";
    "networkx" = "NetworkX";
    "langchain" = "LangChain";
    "ollama" = "Ollama Python Client"
}

$all_ok = $true
foreach ($module in $critical_imports.Keys) {
    $import_test = python -c "import $module" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "✓ $($critical_imports[$module])"
    } else {
        Write-Error_ "✗ $($critical_imports[$module])"
        $all_ok = $false
    }
}

# =========================================================
# SUMMARY
# =========================================================

Write-Info "`n========== SETUP SUMMARY =========="

if ($all_ok) {
    Write-Success "`n✓ All dependencies verified successfully!"
    Write-Success "You can now run: python incident_pipeline.py"
} else {
    Write-Warning_ "`n⚠ Some dependencies may be missing. Please review errors above."
    Write-Info "For issues, check: SETUP_GUIDE.md"
}

write_info "\n========== NEXT STEPS =========="
write_info "1. Review any error messages above"
write_info "2. If Ollama was just installed, restart your terminal"
write_info "3. Run: python incident_pipeline.py"
write_info "========================================`n"
