import sys
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

    input_file = input(
        "Enter raw log file path: "
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