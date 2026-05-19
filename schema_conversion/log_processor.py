"""
Unified Log Processor
---------------------

Processes logs one at a time through the complete pipeline:

FLOW FOR EACH LOG:
------------------
1. STAGE 1: Extract core_message
2. STAGE 1.5: Generate template hash and match against registry
3. IF MATCH: Use registry to auto-convert to schema
4. IF NO MATCH: 
   - STAGE 2: Semantic analysis
   - STAGE 3: Format output
   - Generate new template and save

Output: output.json (accumulated results)

TEMPLATE REGISTRY UPDATE:
------------------------
When logs are processed with LLM (new patterns):
- Templates are automatically generated
- New templates are added to template_registry.json
- Registry is saved at end of processing

To explicitly rebuild/update registry from generated templates:
  python template2.py
  
This will:
- Load template1_output.json (newly generated templates)
- Merge with existing template_registry.json
- Enrich with schema from output.json
- Save updated registry_registry.json
"""

import json
import sys
import argparse
import re
from pathlib import Path
from typing import Dict, Any, Optional
import subprocess


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


class LogProcessor:
    """
    Unified log processor that handles per-log processing
    with template matching optimization.
    """
    
    def __init__(
        self,
        stage1_output_file=None,
        template_registry_file=None,
        final_output_file=None
    ):
        # Schema conversion directory (where this script is located)
        schema_conversion_dir = Path(__file__).parent
        
        # Use project root for output files, schema_conversion for template registry
        if stage1_output_file is None:
            stage1_output_file = PROJECT_ROOT / "stage1_output.json"
        if template_registry_file is None:
            # Template registry is in schema_conversion folder
            template_registry_file = schema_conversion_dir / "template_registry.json"
        if final_output_file is None:
            final_output_file = PROJECT_ROOT / "output.json"
        
        # Convert to Path objects if they're strings
        self.stage1_output_file = Path(stage1_output_file)
        self.template_registry_file = Path(template_registry_file)
        self.final_output_file = Path(final_output_file)
        
        # Load or initialize template registry
        self.template_registry = self.load_template_registry()
        
        # Accumulated output
        self.output_records = []
        self.stats = {
            "total": 0,
            "template_matched": 0,
            "requires_llm": 0,
            "errors": 0
        }
    
    # ========================================================
    # TEMPLATE REGISTRY MANAGEMENT
    # ========================================================
    
    def load_template_registry(self) -> list:
        """Load existing template registry"""
        
        if not Path(self.template_registry_file).exists():
            print(f"[OK] Template registry not found, creating new one")
            return []
        
        try:
            with open(self.template_registry_file, "r", encoding="utf-8") as f:
                registry = json.load(f)
            
            print(f"[OK] Loaded {len(registry)} templates from registry")
            return registry
            
        except Exception as e:
            print(f"[FAIL] Error loading template registry: {e}")
            return []
    
    def save_template_registry(self):
        """Save updated template registry"""
        
        try:
            with open(self.template_registry_file, "w", encoding="utf-8") as f:
                json.dump(self.template_registry, f, indent=2)
            
            print(f"[OK] Updated template registry with {len(self.template_registry)} templates")
            
        except Exception as e:
            print(f"[FAIL] Error saving template registry: {e}")
    
    # ========================================================
    # TEMPLATE MATCHING
    # ========================================================
    
    def match_template(
        self,
        core_message: str,
        template_hash: str
    ) -> Optional[Dict]:
        """
        Find matching template in registry by hash
        
        Args:
            core_message: The core message to match
            template_hash: Pre-calculated template hash
        
        Returns:
            Matching template entry or None
        """
        
        for template_entry in self.template_registry:
            if template_entry.get("template_hash") == template_hash:
                return template_entry
        
        return None
    
    # ========================================================
    # AUTO-CONVERT USING TEMPLATE
    # ========================================================
    
    def auto_convert_to_schema(
        self,
        stage1_entry: Dict,
        template_entry: Dict,
        line_number: int
    ) -> Dict:
        """
        Auto-convert log to final schema using template registry
        
        Args:
            stage1_entry: Entry from stage1_output.json
            template_entry: Matching entry from template_registry
            line_number: Sequential line number
        
        Returns:
            Formatted event record
        """
        
        raw_log = stage1_entry.get("raw_log", "")
        core_message = stage1_entry.get("core_message", "")
        timestamp = stage1_entry.get("timestamp")
        hostname = stage1_entry.get("hostname")
        ip = stage1_entry.get("ip")
        vendor = stage1_entry.get("vendor") or "unknown"
        os = stage1_entry.get("os")
        
        schema = template_entry.get("schema", {})
        
        # Get interface_id from schema (may have placeholders)
        interface_id = schema.get("interface_id")
        
        # Try to extract actual values and replace placeholders
        regex_pattern = template_entry.get("regex_pattern")
        if regex_pattern and interface_id and "<" in interface_id:
            try:
                # Match the core_message against the regex to extract values
                match = re.match(regex_pattern, core_message)
                if match:
                    extracted_values = match.groupdict()
                    
                    # Map for standard placeholders to field names
                    placeholder_to_field = {
                        "<IP>": ["ip"],
                        "<VNI_ID>": ["vni_id"],
                        "<VLAN>": ["vlan"],
                        "<IFACE>": ["interface"],
                        "<PERCENT>": ["percent", "percent_2", "percent_3"],  # Handle counted variants
                        "<DURATION>": ["duration", "duration_2", "duration_3"],
                        "<SECONDS>": ["seconds", "seconds_2", "seconds_3"],
                        "<AGGREGATE>": ["aggregate", "aggregate_2", "aggregate_3"],
                        "<VPN_NAME>": ["vpn_name"],
                        "<USER>": ["user"],
                        "<NUM>": ["num"],
                        "<INSTANCE_ID>": ["instance_id"],
                    }
                    
                    # Replace placeholders with actual values
                    for placeholder, field_names in placeholder_to_field.items():
                        if placeholder in interface_id:
                            # Try to find a matching extracted value
                            for field_name in field_names:
                                if field_name in extracted_values:
                                    actual_value = extracted_values[field_name]
                                    interface_id = interface_id.replace(placeholder, str(actual_value), 1)
                                    break
            except Exception as e:
                # If extraction fails, keep the placeholder as is
                pass
        
        return {
            "event": {
                "event_uid": line_number,
                "event_id": None,
                "type": schema.get("type") or "generic",
                "subtype": schema.get("subtype"),
                "severity": schema.get("severity") or "info",
                "message": core_message
            },
            "device": {
                "hostname": hostname,
                "ip": ip,
                "vendor": vendor,
                "os": os
            },
            "network": {
                "interface_id": interface_id,
                "vlan": None
            },
            "timestamps": {
                "event_time": timestamp
            },
            "raw": {
                "message": raw_log
            }
        }
    
    # ========================================================
    # STAGE 1: EXTRACT SINGLE LOG
    # ========================================================
    
    def process_stage1_single_log(self, raw_log: str) -> Dict:
        """
        Extract single log using Stage1 extractor
        
        Args:
            raw_log: Raw log text
        
        Returns:
            Stage1 extracted data
        """
        
        # Create temporary input file
        temp_input = "__temp_single_log.txt"
        
        try:
            with open(temp_input, "w", encoding="utf-8") as f:
                f.write(raw_log)
            
            # Run stage1.py in single-log mode
            stage1_script = str(Path(__file__).parent / "stage1.py")
            cmd = [
                sys.executable,
                stage1_script,
                "--logs", temp_input,
                "--output", "__temp_stage1.json",
                "--single-log"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                return {"error": f"Stage1 failed: {result.stderr}"}
            
            # Load result
            with open("__temp_stage1.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Return first entry (single log)
            if isinstance(data, list) and len(data) > 0:
                return data[0]
            
            return {"error": "No result from stage1"}
            
        except Exception as e:
            return {"error": f"Stage1 error: {str(e)}"}
        
        finally:
            # Cleanup
            for f in [temp_input, "__temp_stage1.json"]:
                if Path(f).exists():
                    Path(f).unlink()
    
    # ========================================================
    # GENERATE TEMPLATE FOR SINGLE LOG
    # ========================================================
    
    def generate_template_single_log(
        self,
        core_message: str
    ) -> Optional[Dict]:
        """
        Generate template for single log
        
        Args:
            core_message: Core message text
        
        Returns:
            Template entry with hash, template, regex, dynamic_entities
        """
        
        try:
            # Create temporary input file with single message
            temp_stage1 = "__temp_single_template.json"
            
            with open(temp_stage1, "w", encoding="utf-8") as f:
                json.dump([{"core_message": core_message}], f)
            
            # Run template1.py in single-log mode
            template1_script = str(Path(__file__).parent / "template1.py")
            cmd = [
                sys.executable,
                template1_script,
                "--input", temp_stage1,
                "--output", "__temp_template.json",
                "--single-log"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                print(f"[FAIL] Template generation failed: {result.stderr}")
                return None
            
            # Load result
            with open("__temp_template.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            
            if isinstance(data, list) and len(data) > 0:
                return data[0]
            
            return None
            
        except Exception as e:
            print(f"[FAIL] Template generation error: {e}")
            return None
        
        finally:
            # Cleanup
            for f in [temp_stage1, "__temp_template.json"]:
                if Path(f).exists():
                    Path(f).unlink()
    
    # ========================================================
    # STAGE 2: ANALYZE SINGLE LOG
    # ========================================================
    
    def process_stage2_single_log(self, stage1_entry: Dict) -> Dict:
        """
        Semantic analysis for single log
        
        Args:
            stage1_entry: Stage1 extracted data
        
        Returns:
            Stage2 semantic analysis
        """
        
        try:
            # Create temporary input file
            temp_stage1 = "__temp_stage1_s2.json"
            
            with open(temp_stage1, "w", encoding="utf-8") as f:
                json.dump([stage1_entry], f)
            
            # Run stage2.py in single-log mode
            stage2_script = str(Path(__file__).parent / "stage2.py")
            cmd = [
                sys.executable,
                stage2_script,
                "--input", temp_stage1,
                "--output", "__temp_stage2.json",
                "--single-log"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                return {"error": f"Stage2 failed: {result.stderr}"}
            
            # Load result
            with open("__temp_stage2.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            
            if isinstance(data, list) and len(data) > 0:
                return data[0]
            
            return {"error": "No result from stage2"}
            
        except Exception as e:
            return {"error": f"Stage2 error: {str(e)}"}
        
        finally:
            # Cleanup
            for f in [temp_stage1, "__temp_stage2.json"]:
                if Path(f).exists():
                    Path(f).unlink()
    
    # ========================================================
    # STAGE 3: FORMAT SINGLE LOG
    # ========================================================
    
    def process_stage3_single_log(
        self,
        stage1_entry: Dict,
        stage2_entry: Dict,
        line_number: int
    ) -> Dict:
        """
        Format single log to final schema
        
        Args:
            stage1_entry: Stage1 extracted data
            stage2_entry: Stage2 semantic analysis
            line_number: Sequential line number
        
        Returns:
            Formatted event record
        """
        
        raw_log = stage1_entry.get("raw_log", "")
        core_message = stage1_entry.get("core_message", "")
        timestamp = stage1_entry.get("timestamp")
        hostname = stage1_entry.get("hostname")
        ip = stage1_entry.get("ip")
        vendor = stage1_entry.get("vendor") or "unknown"
        os = stage1_entry.get("os")
        
        event_type = stage2_entry.get("type") or "generic"
        subtype = stage2_entry.get("subtype")
        severity = stage2_entry.get("severity") or "info"
        interface_id = stage2_entry.get("interface_id")
        
        return {
            "event": {
                "event_uid": line_number,
                "event_id": None,
                "type": event_type,
                "subtype": subtype,
                "severity": severity,
                "message": core_message
            },
            "device": {
                "hostname": hostname,
                "ip": ip,
                "vendor": vendor,
                "os": os
            },
            "network": {
                "interface_id": interface_id,
                "vlan": None
            },
            "timestamps": {
                "event_time": timestamp
            },
            "raw": {
                "message": raw_log
            }
        }
    
    # ========================================================
    # ADD TO REGISTRY
    # ========================================================
    
    def add_to_registry(
        self,
        template_entry: Dict,
        stage1_entry: Dict,
        stage2_entry: Dict
    ):
        """
        Add new template to registry
        
        Args:
            template_entry: Generated template
            stage1_entry: Stage1 data
            stage2_entry: Stage2 data
        """
        
        if not template_entry or "error" in template_entry:
            return
        
        # Extract interface_id from stage2
        interface_id_from_log = stage2_entry.get("interface_id")
        
        # Get dynamic entities from template
        dynamic_entities = template_entry.get("dynamic_entities", [])
        
        # Construct generic interface_id by replacing actual values with placeholders
        generic_interface_id = interface_id_from_log
        if interface_id_from_log and dynamic_entities:
            # Track placeholder usage to handle duplicates
            placeholder_usage = {}
            
            # Sort by length (longest first) to avoid partial matches
            sorted_entities = sorted(
                dynamic_entities,
                key=lambda x: len(x.get("value", "")),
                reverse=True
            )
            
            for entity in sorted_entities:
                placeholder = entity.get("placeholder")
                value = entity.get("value")
                if placeholder and value and str(value) in generic_interface_id:
                    # Count how many times this placeholder has been used
                    if placeholder not in placeholder_usage:
                        placeholder_usage[placeholder] = 0
                    
                    placeholder_usage[placeholder] += 1
                    
                    # If this is a duplicate placeholder usage, make it unique
                    if placeholder_usage[placeholder] > 1:
                        unique_placeholder = f"{placeholder[:-1]}__{placeholder_usage[placeholder]}>"
                        generic_interface_id = generic_interface_id.replace(str(value), unique_placeholder, 1)
                    else:
                        generic_interface_id = generic_interface_id.replace(str(value), placeholder, 1)
        
        schema = {
            "type": stage2_entry.get("type"),
            "subtype": stage2_entry.get("subtype"),
            "severity": stage2_entry.get("severity"),
            "vendor": stage1_entry.get("vendor"),
            "os": stage1_entry.get("os"),
            "interface_id": generic_interface_id
        }
        
        registry_entry = {
            "template_hash": template_entry.get("template_hash"),
            "template": template_entry.get("template"),
            "regex_pattern": template_entry.get("regex_pattern"),
            "dynamic_fields": template_entry.get("dynamic_entities", []),
            "schema": schema
        }
        
        # Check for duplicate
        exists = any(
            e.get("template_hash") == registry_entry["template_hash"]
            for e in self.template_registry
        )
        
        if not exists:
            self.template_registry.append(registry_entry)
            print(f"[OK] Added new template to registry")
    
    # ========================================================
    # PROCESS SINGLE LOG
    # ========================================================
    
    def process_single_log(
        self,
        raw_log: str,
        line_number: int
    ) -> Optional[Dict]:
        """
        Process single log through complete flow
        
        Args:
            raw_log: Raw log text
            line_number: Sequential line number
        
        Returns:
            Formatted event record or None on error
        """
        
        print(f"\n{'-'*70}")
        print(f"LOG #{line_number}")
        print(f"{'-'*70}")
        
        self.stats["total"] += 1
        
        # ========================================================
        # STAGE 1: EXTRACTION
        # ========================================================
        
        print("-> STAGE 1: Extracting core message...")
        
        stage1_entry = self.process_stage1_single_log(raw_log)
        
        if "error" in stage1_entry:
            print(f"[FAIL] {stage1_entry['error']}")
            self.stats["errors"] += 1
            return None
        
        core_message = stage1_entry.get("core_message")
        print(f"[OK] Core message: {core_message[:60]}...")
        
        # ========================================================
        # STAGE 1.5: TEMPLATE MATCHING
        # ========================================================
        
        print("-> STAGE 1.5: Generating template hash...")
        
        template_entry = self.generate_template_single_log(core_message)
        
        if template_entry and "error" not in template_entry:
            
            template_hash = template_entry.get("template_hash")
            template_text = template_entry.get("template")
            
            print(f"[OK] Template: {template_text}")
            
            # Try to match
            matched_template = self.match_template(core_message, template_hash)
            
            if matched_template:
                
                print(f"[OK] TEMPLATE MATCHED! Using auto-conversion...")
                
                # Auto-convert
                output_record = self.auto_convert_to_schema(
                    stage1_entry,
                    matched_template,
                    line_number
                )
                
                self.stats["template_matched"] += 1
                
                print(f"[OK] Auto-converted successfully")
                
                return output_record
        
        # =========================================================
        # NO MATCH: Run STAGE 2 + STAGE 3
        # =========================================================
        
        print("-> No template match, proceeding with LLM analysis...")
        self.stats["requires_llm"] += 1
        
        # STAGE 2
        print("-> STAGE 2: Semantic analysis...")
        
        stage2_entry = self.process_stage2_single_log(stage1_entry)
        
        if "error" in stage2_entry:
            print(f"[FAIL] {stage2_entry['error']}")
            self.stats["errors"] += 1
            return None
        
        print(f"[OK] Type: {stage2_entry.get('type')}, Severity: {stage2_entry.get('severity')}")
        
        # STAGE 3
        print("-> STAGE 3: Formatting output...")
        
        output_record = self.process_stage3_single_log(
            stage1_entry,
            stage2_entry,
            line_number
        )
        
        print(f"[OK] Formatted successfully")
        
        # Add to registry for future matches
        if template_entry and "error" not in template_entry:
            self.add_to_registry(template_entry, stage1_entry, stage2_entry)
        
        return output_record
    
    # ========================================================
    # PROCESS LOG FILE
    # ========================================================
    
    def process_logs_file(self, logs_file: str) -> list:
        """
        Process all logs from file, one at a time
        
        Args:
            logs_file: Path to logs file
        
        Returns:
            List of processed records
        """
        
        if not Path(logs_file).exists():
            print(f"[FAIL] Error: Logs file not found: {logs_file}")
            return []
        
        # Read logs
        try:
            with open(logs_file, "r", encoding="utf-8") as f:
                logs = f.readlines()
        except Exception as e:
            print(f"[FAIL] Error reading logs file: {e}")
            return []
        
        print(f"\n{'='*70}")
        print(f"UNIFIED LOG PROCESSOR")
        print(f"{'='*70}")
        print(f"Total logs to process: {len(logs)}")
        
        # Clear output file at the start
        try:
            with open(self.final_output_file, "w", encoding="utf-8") as f:
                json.dump([], f)
        except Exception as e:
            print(f"[WARN] Could not initialize output file: {e}")
        
        # Process each log
        for idx, raw_log in enumerate(logs, 1):
            
            raw_log = raw_log.strip()
            if not raw_log:
                continue
            
            output_record = self.process_single_log(raw_log, idx)
            
            if output_record:
                self.output_records.append(output_record)
                # Save immediately to output file
                self.append_record_to_output(output_record)
        
        return self.output_records
    
    # ========================================================
    # SAVE OUTPUT
    # ========================================================
    
    def append_record_to_output(self, record: Dict):
        """Append a single record immediately to the output file"""
        
        try:
            # Load existing records if file exists
            if Path(self.final_output_file).exists():
                with open(self.final_output_file, "r", encoding="utf-8") as f:
                    try:
                        records = json.load(f)
                    except json.JSONDecodeError:
                        records = []
            else:
                records = []
            
            # Append new record
            records.append(record)
            
            # Write back to file
            with open(self.final_output_file, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, ensure_ascii=False)
            
        except Exception as e:
            print(f"[FAIL] Error appending record to output: {e}")
    
    def save_output(self):
        """Save processed records to output file"""
        
        try:
            with open(self.final_output_file, "w", encoding="utf-8") as f:
                json.dump(self.output_records, f, indent=2, ensure_ascii=False)
            
            print(f"\n[OK] Saved {len(self.output_records)} records to {self.final_output_file}")
            
        except Exception as e:
            print(f"[FAIL] Error saving output: {e}")
    
    # ========================================================
    # PRINT STATISTICS
    # ========================================================
    
    def print_stats(self):
        """Print processing statistics"""
        
        print(f"\n{'='*70}")
        print("PROCESSING STATISTICS")
        print(f"{'='*70}")
        print(f"Total logs processed:        {self.stats['total']}")
        print(f"Template matched (fast):     {self.stats['template_matched']}")
        print(f"Requires LLM analysis:       {self.stats['requires_llm']}")
        print(f"Errors:                      {self.stats['errors']}")
        print(f"\nTemplate registry size:      {len(self.template_registry)}")
        print(f"Output records generated:    {len(self.output_records)}")
        
        # Show note about explicit registry update
        if self.stats['requires_llm'] > 0:
            print(f"\n{'-'*70}")
            print("NOTE: New templates were generated from LLM analysis.")
            print("To explicitly update/rebuild the template registry:")
            print("  python template2.py")
            print(f"{'-'*70}")
        
        print(f"{'='*70}\n")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        description="Unified Log Processor with Template Matching Optimization"
    )
    
    parser.add_argument(
        "--logs",
        type=str,
        default=str(PROJECT_ROOT / "logs.txt"),
        help=f"Input logs file (default: {PROJECT_ROOT / 'logs.txt'})"
    )
    
    parser.add_argument(
        "--stage1-output",
        type=str,
        default=str(PROJECT_ROOT / "stage1_output.json"),
        help=f"Stage1 output file (default: {PROJECT_ROOT / 'stage1_output.json'})"
    )
    
    parser.add_argument(
        "--template-registry",
        type=str,
        default=str(Path(__file__).parent / "template_registry.json"),
        help=f"Template registry file (default: schema_conversion/template_registry.json)"
    )
    
    parser.add_argument(
        "--final-output",
        type=str,
        default=str(PROJECT_ROOT / "output.json"),
        help=f"Final output file (default: {PROJECT_ROOT / 'output.json'})"
    )
    
    args = parser.parse_args()
    
    # Create processor
    processor = LogProcessor(
        stage1_output_file=args.stage1_output,
        template_registry_file=args.template_registry,
        final_output_file=args.final_output
    )
    
    # Process logs
    processor.process_logs_file(args.logs)
    
    # Save results
    processor.save_output()
    
    # Update registry
    processor.save_template_registry()
    
    # Print statistics
    processor.print_stats()
