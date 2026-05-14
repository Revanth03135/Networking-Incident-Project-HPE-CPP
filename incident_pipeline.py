import sys
import subprocess
import platform
from pathlib import Path


# =========================================================
# ADD PROJECT ROOT
# =========================================================

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


# =========================================================
# IMPORTS
# =========================================================

from schema_conversion.run_pipeline import (
    process_logs
)

from timeline_reconstruction import (
    run_pipeline as reconstruct_timeline
)


TIMELINE_OUTPUT = (
    project_root / "timeline_output.json"
)


# =========================================================
# AUTO SETUP FUNCTION
# =========================================================

def run_auto_setup():
    """Run setup_auto.ps1 to check and install dependencies"""
    
    if platform.system() != "Windows":
        print("⚠ Auto-setup requires Windows/PowerShell")
        print("  Run: bash setup_dependencies.sh")
        return False
    
    setup_script = project_root / "setup_auto.ps1"
    
    if not setup_script.exists():
        print(f"⚠ Setup script not found: {setup_script}")
        return False
    
    print("\n" + "=" * 70)
    print(" AUTO SETUP — Checking Dependencies ")
    print("=" * 70)
    
    try:
        # Run PowerShell script
        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy", "RemoteSigned",
            "-File", str(setup_script)
        ]
        
        result = subprocess.run(cmd, check=False)
        
        if result.returncode == 0:
            print("\n✓ Setup completed successfully")
            return True
        else:
            print("\n✗ Setup encountered issues (exit code: {})".format(result.returncode))
            return False
            
    except Exception as e:
        print(f"\n✗ Error running setup: {e}")
        return False


# =========================================================
# CONFIG
# =========================================================

TIMELINE_OUTPUT = (
    project_root / "timeline_output.json"
)


# =========================================================
# MAIN PIPELINE
# =========================================================

def main():

    print("\n" + "=" * 70)
    print(" CHECKING DEPENDENCIES ")
    print("=" * 70)
    
    # Run auto setup
    if not run_auto_setup():
        print("\n⚠ Dependency check failed. Proceeding anyway...")
        print("  If errors occur, run setup manually:")
        if platform.system() == "Windows":
            print("  PowerShell: .\\setup_auto.ps1")
        else:
            print("  Bash: ./setup_dependencies.sh")
    
    input_file = input(
        "\nEnter raw log file path: "
    ).strip()

    input_path = Path(input_file)

    if not input_path.exists():

        print("Input file not found")

        return

    print("\n" + "=" * 70)
    print(" STAGE 1 — SCHEMA CONVERSION ")
    print("=" * 70)

    normalized_output_path = process_logs(
        input_file
    )

    print("\n" + "=" * 70)
    print(" STAGE 2 — TIMELINE RECONSTRUCTION ")
    print("=" * 70)

    incidents = reconstruct_timeline(
        normalized_output_path,
        TIMELINE_OUTPUT
    )

    print("\n" + "=" * 70)
    print(" PIPELINE COMPLETE ")
    print("=" * 70)

    print(
        f"\nNormalized Events : {normalized_output_path}"
    )

    print(
        f"Timeline Output   : {TIMELINE_OUTPUT}"
    )

    print(
        f"Incidents Built   : {len(incidents)}"
    )


# =========================================================
# ENTRY
# =========================================================

if __name__ == "__main__":

    main()