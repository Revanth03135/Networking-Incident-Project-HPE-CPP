import json
from pathlib import Path
import os


# ============================================================
# PROJECT ROOT PATH
# ============================================================

def get_project_root():
    """
    Get the project root directory
    Works regardless of where script is run from
    """
    # Get the directory of the schema_conversion folder
    schema_conversion_dir = Path(__file__).parent
    # Project root is parent of schema_conversion
    project_root = schema_conversion_dir.parent
    return project_root


PROJECT_ROOT = get_project_root()

# ============================================================
# SCHEMA CONVERSION DIRECTORY
# ============================================================

SCHEMA_CONVERSION_DIR = Path(__file__).parent

# ============================================================
# FILE PATHS
# ============================================================

# Output files are in project root
STAGE3_FILE = PROJECT_ROOT / "output.json"
TEMPLATE_FILE = PROJECT_ROOT / "template1_output.json"

# Template registry is in schema_conversion folder
REGISTRY_FILE = SCHEMA_CONVERSION_DIR / "template_registry.json"
OUTPUT_FILE = SCHEMA_CONVERSION_DIR / "template_registry.json"


# ============================================================
# LOAD JSON
# ============================================================

def load_json(path):

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================
# SAFE GET
# ============================================================

def safe_get(obj, *keys):

    current = obj

    for key in keys:

        if current is None:
            return None

        current = current.get(key)

    return current


# ============================================================
# MERGE TEMPLATES FROM TEMPLATE1_OUTPUT.JSON
# ============================================================

def merge_new_templates(existing_registry, new_templates):
    """
    Merge newly generated templates into existing registry
    
    Args:
        existing_registry: List of templates from template_registry.json
        new_templates: List of templates from template1_output.json
    
    Returns:
        Merged and deduplicated list
    """
    
    if not new_templates:
        return existing_registry
    
    # Create hash map of existing templates
    registry_by_hash = {
        entry.get("template_hash"): entry
        for entry in existing_registry
        if entry.get("template_hash")
    }
    
    added_count = 0
    
    # Merge new templates
    for template in new_templates:
        
        if "error" in template:
            # Skip error entries
            continue
        
        template_hash = template.get("template_hash")
        
        if not template_hash:
            # Skip templates without hash
            continue
        
        if template_hash not in registry_by_hash:
            # New template - add to registry
            # Note: At this point, we only have template data
            # Full schema will be added in build_registry()
            
            new_entry = {
                "template_hash": template_hash,
                "template": template.get("template"),
                "regex_pattern": template.get("regex_pattern"),
                "dynamic_fields": template.get("dynamic_entities", []),
                "schema": {
                    # These will be populated when matched with output.json
                    "type": None,
                    "subtype": None,
                    "severity": None,
                    "vendor": None,
                    "os": None
                }
            }
            
            registry_by_hash[template_hash] = new_entry
            added_count += 1
            
            print(f"  [OK] Added new template: {template.get('template')}")
    
    print(f"\n  Newly added templates: {added_count}")
    
    return list(registry_by_hash.values())


# ============================================================
# BUILD TEMPLATE REGISTRY
# ============================================================

def build_registry(stage3_data, template_data):

    registry = []

    # --------------------------------------------------------
    # Ensure equal lengths
    # --------------------------------------------------------

    total = min(len(stage3_data), len(template_data))

    print(f"\nProcessing {total} entries...\n")

    # --------------------------------------------------------
    # Merge entries
    # --------------------------------------------------------

    for idx in range(total):

        stage3 = stage3_data[idx]
        template = template_data[idx]

        # ----------------------------------------------------
        # Extract schema metadata
        # ----------------------------------------------------

        schema = {

            "type":
                safe_get(stage3, "event", "type"),

            "subtype":
                safe_get(stage3, "event", "subtype"),

            "severity":
                safe_get(stage3, "event", "severity"),

            "vendor":
                safe_get(stage3, "device", "vendor"),

            "os":
                safe_get(stage3, "device", "os")
        }

        # ----------------------------------------------------
        # Build registry entry
        # ----------------------------------------------------

        registry_entry = {

            "template_hash":
                template.get("template_hash"),

            "template":
                template.get("template"),

            "regex_pattern":
                template.get("regex_pattern"),

            "dynamic_fields":
                template.get("dynamic_entities", []),

            "schema":
                schema
        }

        registry.append(registry_entry)

        print(f"[{idx+1}] Added template:")
        print(f"    Template : {template.get('template')}")
        print(f"    Type     : {schema['type']}")
        print(f"    Subtype  : {schema['subtype']}")
        print()

    return registry


# ============================================================
# CONSTRUCT GENERIC INTERFACE_ID FROM TEMPLATE
# ============================================================

def construct_generic_interface_id(interface_id_from_log, dynamic_fields):
    """
    Replace actual values with placeholders in interface_id
    to create a generic template version
    
    Args:
        interface_id_from_log: The interface_id extracted from the log
        dynamic_fields: List of {"placeholder": "<X>", "value": "actual_value"} dicts
    
    Returns:
        Generic interface_id with placeholders, or original if no replacements
    """
    
    if not interface_id_from_log or not dynamic_fields:
        return interface_id_from_log
    
    generic_id = interface_id_from_log
    
    # Replace each actual value with its placeholder (longest first to avoid partial matches)
    sorted_fields = sorted(dynamic_fields, key=lambda x: len(x.get("value", "")), reverse=True)
    
    # Track placeholder usage to handle duplicates
    placeholder_usage = {}
    
    for field in sorted_fields:
        placeholder = field.get("placeholder")
        value = field.get("value")
        
        if placeholder and value:
            # Count how many times this placeholder has been used
            if placeholder not in placeholder_usage:
                placeholder_usage[placeholder] = 0
            
            # Check if value exists in generic_id
            if str(value) in generic_id:
                placeholder_usage[placeholder] += 1
                
                # If this is a duplicate placeholder usage, make it unique
                if placeholder_usage[placeholder] > 1:
                    unique_placeholder = f"{placeholder[:-1]}__{placeholder_usage[placeholder]}>"
                    generic_id = generic_id.replace(str(value), unique_placeholder, 1)
                else:
                    generic_id = generic_id.replace(str(value), placeholder, 1)
    
    return generic_id


# ============================================================
# REMOVE DUPLICATES
# ============================================================

def deduplicate_registry(registry):

    unique = {}

    for entry in registry:

        template_hash = entry.get("template_hash")

        if template_hash not in unique:

            unique[template_hash] = entry

    return list(unique.values())


# ============================================================
# SAVE JSON
# ============================================================

def save_json(data, path):

    with open(path, "w", encoding="utf-8") as f:

        json.dump(data, f, indent=2)

    print(f"\nSaved registry to: {path}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    try:

        # ────────────────────────────────────────────────
        # STEP 1: Load files
        # ────────────────────────────────────────────────

        print("\n" + "="*70)
        print("TEMPLATE REGISTRY UPDATE")
        print("="*70)
        print("\nLoading files...\n")

        # Load output and templates
        stage3_data = load_json(STAGE3_FILE) if Path(STAGE3_FILE).exists() else []
        template_data = load_json(TEMPLATE_FILE) if Path(TEMPLATE_FILE).exists() else []
        existing_registry = load_json(REGISTRY_FILE) if Path(REGISTRY_FILE).exists() else []

        print(f"Loaded stage3 entries   : {len(stage3_data)}")
        print(f"Loaded template entries : {len(template_data)}")
        print(f"Loaded existing registry: {len(existing_registry)}")

        # ────────────────────────────────────────────────
        # STEP 2: Merge new templates into registry
        # ────────────────────────────────────────────────

        print("\nMerging new templates into registry...\n")
        
        registry = merge_new_templates(
            existing_registry,
            template_data
        )
        
        print(f"\nMerged registry size: {len(registry)}")

        # ────────────────────────────────────────────────
        # STEP 3: Enrich registry with schema from output
        # ────────────────────────────────────────────────

        if stage3_data and template_data:
            
            print("\nEnriching registry with schema data...\n")
            
            # Create mapping of template_hash to schema
            schema_map = {}
            
            for idx in range(min(len(stage3_data), len(template_data))):
                
                template = template_data[idx]
                stage3 = stage3_data[idx]
                
                if "error" in template or "error" in stage3:
                    continue
                
                template_hash = template.get("template_hash")
                
                if template_hash:
                    # Extract interface_id from log
                    interface_id_from_log = safe_get(stage3, "network", "interface_id")
                    
                    # Get dynamic fields from template to construct generic interface_id
                    dynamic_fields = template.get("dynamic_entities", [])
                    
                    # Construct generic interface_id with placeholders instead of actual values
                    generic_interface_id = construct_generic_interface_id(
                        interface_id_from_log,
                        dynamic_fields
                    )
                    
                    # Extract schema from stage3 output
                    schema = {
                        "type": safe_get(stage3, "event", "type"),
                        "subtype": safe_get(stage3, "event", "subtype"),
                        "severity": safe_get(stage3, "event", "severity"),
                        "vendor": safe_get(stage3, "device", "vendor"),
                        "os": safe_get(stage3, "device", "os"),
                        "interface_id": generic_interface_id  # Use generic version
                    }
                    
                    schema_map[template_hash] = schema
            
            # Update registry entries with schema
            updated_count = 0
            for entry in registry:
                template_hash = entry.get("template_hash")
                
                if template_hash in schema_map:
                    entry["schema"] = schema_map[template_hash]
                    updated_count += 1
            
            print(f"Updated {updated_count} entries with schema data\n")

        # ────────────────────────────────────────────────
        # STEP 4: Deduplicate
        # ────────────────────────────────────────────────

        print("Deduplicating registry...\n")
        
        registry = deduplicate_registry(registry)
        
        print(f"Deduplicated registry size: {len(registry)}")

        # ────────────────────────────────────────────────
        # STEP 5: Save updated registry
        # ────────────────────────────────────────────────

        save_json(
            registry,
            OUTPUT_FILE
        )

        print("\n" + "="*70)
        print("[OK] TEMPLATE REGISTRY UPDATE COMPLETE")
        print("="*70)
        print(f"Final registry size: {len(registry)} templates\n")

    except Exception as e:

        print(f"\n[FAIL] ERROR: {e}\n")