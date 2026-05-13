@echo off
REM RAG Pipeline Runner - Windows Batch Script
REM This script activates the Python virtual environment and runs the RAG pipeline

setlocal enabledelayedexpansion

REM Get the directory where this batch file is located
set SCRIPT_DIR=%~dp0
set VENV_PATH=%SCRIPT_DIR%env
set PYTHON_EXE=%VENV_PATH%\Scripts\python.exe
set RAG_SCRIPT=%SCRIPT_DIR%run_rag.py

REM Colors for output
set GREEN=[92m
set YELLOW=[93m
set RED=[91m
set RESET=[0m

echo.
echo ============================================================================
echo RAG PIPELINE RUNNER - Windows Batch
echo ============================================================================
echo.

REM Check if virtual environment exists
if not exist "%VENV_PATH%" (
    echo.
    echo %RED%[ERROR]%RESET% Virtual environment not found at: %VENV_PATH%
    echo.
    echo Please create the virtual environment first:
    echo   1. Open PowerShell or Command Prompt
    echo   2. Run: python -m venv env
    echo   3. Run this script again
    echo.
    pause
    exit /b 1
)

REM Check if Python executable exists
if not exist "%PYTHON_EXE%" (
    echo.
    echo %RED%[ERROR]%RESET% Python executable not found at: %PYTHON_EXE%
    echo.
    pause
    exit /b 1
)

echo [INFO] Virtual Environment: %VENV_PATH%
echo [INFO] Python Executable: %PYTHON_EXE%
echo [INFO] RAG Script: %RAG_SCRIPT%
echo.

REM Parse command line arguments
set "CONFIG_FLAG="
set "LOG_FILE="
set "VENDOR="

:parse_args
if "%1"=="" goto start_pipeline
if "%1"=="--config" (
    set CONFIG_FLAG=1
    shift
    goto parse_args
)
if "%1"=="--log-file" (
    set LOG_FILE=%2
    shift
    shift
    goto parse_args
)
if "%1"=="--vendor" (
    set VENDOR=%2
    shift
    shift
    goto parse_args
)
shift
goto parse_args

:start_pipeline
REM Show configuration if requested
if defined CONFIG_FLAG (
    echo [INFO] Displaying configuration...
    echo.
    "%PYTHON_EXE%" "%RAG_SCRIPT%" --config
    goto end
)

REM Process log file if provided
if defined LOG_FILE (
    echo [INFO] Processing log file: %LOG_FILE%
    if defined VENDOR (
        echo [INFO] Using vendor hint: %VENDOR%
        "%PYTHON_EXE%" "%RAG_SCRIPT%" --log-file "%LOG_FILE%" --vendor "%VENDOR%"
    ) else (
        "%PYTHON_EXE%" "%RAG_SCRIPT%" --log-file "%LOG_FILE%"
    )
    goto end
)

REM Run test pipeline by default
echo [INFO] Running RAG pipeline with test data...
echo.
"%PYTHON_EXE%" "%RAG_SCRIPT%"

:end
echo.
echo [INFO] Pipeline execution completed
echo.
pause
exit /b 0
