#!/bin/bash

# =========================================================
# AUTOMATED DEPENDENCY SETUP SCRIPT (Bash)
# =========================================================
# This script checks and installs all required dependencies
# for the Networking Incident Project
# Run: bash setup_dependencies.sh
# =========================================================

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

write_success() { echo -e "${GREEN}✓ $1${NC}"; }
write_error() { echo -e "${RED}✗ $1${NC}"; }
write_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }
write_info() { echo -e "${CYAN}$1${NC}"; }

# Parse arguments
SKIP_OLLAMA=false
SKIP_MODELS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-ollama) SKIP_OLLAMA=true; shift ;;
        --skip-models) SKIP_MODELS=true; shift ;;
        *) shift ;;
    esac
done

# =========================================================
# PHASE 1: PYTHON ENVIRONMENT
# =========================================================

write_info "\n========== PHASE 1: Python Environment =========="

if [ -f "env/bin/activate" ]; then
    write_info "Virtual environment found, activating..."
    source env/bin/activate
    write_success "Virtual environment activated"
else
    write_error "Virtual environment not found"
    write_info "Creating virtual environment..."
    python3 -m venv env
    source env/bin/activate
    write_success "Virtual environment created and activated"
fi

# =========================================================
# PHASE 2: PYTHON PACKAGES
# =========================================================

write_info "\n========== PHASE 2: Python Packages =========="

packages=(
    "numpy"
    "scipy"
    "scikit-learn"
    "networkx"
    "pandas"
    "torch"
    "faiss-cpu"
    "langchain"
    "langchain-community"
    "ollama"
    "pydantic"
    "python-dotenv"
    "requests"
    "pyyaml"
    "sympy"
)

write_info "Checking Python packages..."
missing_packages=()

for package in "${packages[@]}"; do
    pkg_name=$(echo "$package" | cut -d'-' -f1)
    if python3 -c "import $pkg_name" 2>/dev/null; then
        write_success "$package"
    else
        missing_packages+=("$package")
        write_warning "$package (missing)"
    fi
done

if [ ${#missing_packages[@]} -gt 0 ]; then
    write_info "\nInstalling missing packages: ${missing_packages[*]}"
    pip install --upgrade pip
    for package in "${missing_packages[@]}"; do
        write_info "Installing $package..."
        pip install "$package"
        if [ $? -eq 0 ]; then
            write_success "$package installed"
        else
            write_error "Failed to install $package"
        fi
    done
else
    write_success "\nAll Python packages installed"
fi

# =========================================================
# PHASE 3: OLLAMA SETUP
# =========================================================

if [ "$SKIP_OLLAMA" = false ]; then
    write_info "\n========== PHASE 3: Ollama Setup =========="
    
    if command -v ollama &> /dev/null; then
        ollama_version=$(ollama --version)
        write_success "Ollama found: $ollama_version"
    else
        write_error "Ollama not found"
        write_info "Download from: https://ollama.ai"
        write_info "Or install via: curl -fsSL https://ollama.ai/install.sh | sh"
        
        read -p "Install Ollama now? (yes/no): " response
        if [ "$response" = "yes" ]; then
            write_info "Installing Ollama..."
            curl -fsSL https://ollama.ai/install.sh | sh
            write_info "Please restart terminal after Ollama installation completes"
        fi
    fi
fi

# =========================================================
# PHASE 4: OLLAMA MODELS
# =========================================================

if [ "$SKIP_MODELS" = false ]; then
    write_info "\n========== PHASE 4: Ollama Models =========="
    
    if command -v ollama &> /dev/null; then
        models=("qwen:7b" "rag_model")
        
        for model in "${models[@]}"; do
            write_info "Checking model: $model"
            
            if [ "$model" = "qwen:7b" ]; then
                write_info "Pulling Qwen 7B model (this may take 5-10 minutes)..."
                ollama pull qwen:7b
                if [ $? -eq 0 ]; then
                    write_success "qwen:7b model ready"
                else
                    write_error "Failed to pull qwen:7b"
                fi
            elif [ "$model" = "rag_model" ]; then
                write_warning "RAG model setup may require custom configuration"
                write_info "Check schema_conversion/rag_module/README.md for RAG model setup"
            fi
        done
    else
        write_warning "Ollama not available, skipping model setup"
    fi
fi

# =========================================================
# PHASE 5: REQUIREMENTS FILE
# =========================================================

write_info "\n========== PHASE 5: Requirements File =========="

if [ -f "requirements.txt" ]; then
    write_info "Installing from requirements.txt..."
    pip install -r requirements.txt
    write_success "requirements.txt installed"
else
    write_warning "requirements.txt not found"
fi

# =========================================================
# PHASE 6: ENVIRONMENT VERIFICATION
# =========================================================

write_info "\n========== PHASE 6: Environment Verification =========="

declare -A critical_imports=(
    ["numpy"]="NumPy"
    ["scipy"]="SciPy"
    ["sklearn"]="Scikit-Learn"
    ["networkx"]="NetworkX"
    ["langchain"]="LangChain"
    ["ollama"]="Ollama Python Client"
)

all_ok=true
for module in "${!critical_imports[@]}"; do
    if python3 -c "import $module" 2>/dev/null; then
        write_success "${critical_imports[$module]}"
    else
        write_error "${critical_imports[$module]}"
        all_ok=false
    fi
done

# =========================================================
# SUMMARY
# =========================================================

write_info "\n========== SETUP SUMMARY =========="

if [ "$all_ok" = true ]; then
    write_success "\nAll dependencies verified successfully!"
    write_success "You can now run: python incident_pipeline.py"
else
    write_warning "\nSome dependencies may be missing. Please review errors above."
    write_info "For issues, check: SETUP_GUIDE.md"
fi

write_info "\n========== NEXT STEPS =========="
write_info "1. Review any error messages above"
write_info "2. If Ollama was just installed, restart your terminal"
write_info "3. Run: python incident_pipeline.py"
write_info "========================================\n"
