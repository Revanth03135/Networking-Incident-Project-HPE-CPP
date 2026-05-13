#!/usr/bin/env python3
"""
RAG Pipeline Runner
Orchestrates the complete RAG (Retrieval-Augmented Generation) pipeline
for network event log processing and normalization.

Usage:
    python run_rag.py                           # Run with test data
    python run_rag.py --log-file <path>        # Process from log file
    python run_rag.py --config                 # Show config
"""

import sys
import os
import json
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, List

# Add schema_convertor to path
schema_convertor_path = Path(__file__).parent / "schema_convertor" / "rag_module"
sys.path.insert(0, str(schema_convertor_path))
sys.path.insert(0, str(schema_convertor_path / "Core_RAG"))
sys.path.insert(0, str(schema_convertor_path / "schema_former"))

# Import modules
from config import (
    get_config_summary, ensure_directories_exist,
    RAG_TOP_K, RAG_CANDIDATE_POOL_SIZE
)
from retriever import RAGRetriever
from normalize_events import normalize_event


def print_config():
    """Display current configuration"""
    print("\n" + "=" * 70)
    print("RAG PIPELINE CONFIGURATION")
    print("=" * 70)
    config = get_config_summary()
    for key, value in config.items():
        print(f"  {key:.<40} {value}")
    print("=" * 70 + "\n")


def run_test_pipeline():
    """Run the RAG pipeline with test data"""
    print("\n" + "=" * 70)
    print("RAG PIPELINE - TEST RUN")
    print("=" * 70)
    
    test_logs = [
        {
            "event_time": "2026-04-03T10:20:11Z",
            "hostname": "sw1",
            "ip": None,
            "message": "Port 1/1/10-re-auth timeout 30 too short."
        },
        {
            "event_time": "2026-04-03T10:25:00Z",
            "hostname": "sw1",
            "ip": None,
            "message": "Unable to resolve the Activate activate.example.com https://activate.example.com."
        },
        {
            "event_time": "2026-04-03T10:30:00Z",
            "hostname": "fw1",
            "ip": None,
            "message": "%ASA-2-106001: Inbound TCP connection denied from 10.10.1.5/443 to 192.168.1.10/5151 flags SYN on interface inside"
        },
    ]

    vendors = ["aruba", "aruba", "cisco"]
    
    try:
        retriever = RAGRetriever()
        print(f"\n✓ RAGRetriever initialized successfully")
        print(f"  - Index contains {retriever.index.ntotal} records\n")
        
        for i, (raw_log, vendor) in enumerate(zip(test_logs, vendors), 1):
            print(f"\n{'-' * 70}")
            print(f"TEST {i}: {vendor.upper()}")
            print(f"{'-' * 70}")
            print(f"Raw Log: {raw_log['message']}\n")
            
            try:
                retrieval = retriever.search(
                    raw_log=raw_log["message"],
                    top_k=RAG_TOP_K,
                    vendor_hint=vendor,
                    candidate_pool_size=RAG_CANDIDATE_POOL_SIZE,
                )
                
                print("=== Retrieval Results ===")
                if retrieval["results"]:
                    for j, result in enumerate(retrieval["results"], 1):
                        print(f"{j}. ID: {result['record_id']} | "
                              f"Score: {result['final_score']:.4f} | "
                              f"Template: {result['message_template']}")
                else:
                    print("⚠ No retrieval results found")
                    continue
                
                top_result = retrieval["results"][0]
                
                rag_result = {
                    "vendor": top_result["vendor"],
                    "event_id": top_result["event_id"],
                    "category": top_result["category"],
                    "severity": top_result["severity"],
                    "message_template": top_result["message_template"],
                    "product_family": "ArubaOS-Switch" if top_result["vendor"] == "aruba" else "Cisco Security Appliance",
                }
                
                normalized = normalize_event(raw_log, rag_result)
                
                print("\n=== Normalized Event ===")
                print(json.dumps(normalized, indent=2))
                print("✓ Event normalized successfully")
                
            except Exception as e:
                print(f"✗ Error processing log: {e}")
                import traceback
                traceback.print_exc()
    
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        print("\n⚠ WARNING: Required index files not found!")
        print("Please ensure the following files exist:")
        from config import EVENT_INDEX_PATH, EMBEDDING_METADATA_PATH
        print(f"  - {EVENT_INDEX_PATH}")
        print(f"  - {EMBEDDING_METADATA_PATH}")
        return False
    
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 70)
    print("TEST RUN COMPLETED")
    print("=" * 70 + "\n")
    return True


def process_log_file(log_file: str, vendor_hint: Optional[str] = None) -> bool:
    """Process logs from a file"""
    log_path = Path(log_file)
    
    if not log_path.exists():
        print(f"✗ Log file not found: {log_path}")
        return False
    
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        
        if not isinstance(logs, list):
            print(f"✗ Log file must contain a JSON array")
            return False
        
        print(f"\n✓ Loaded {len(logs)} logs from {log_path}")
        
        retriever = RAGRetriever()
        results = []
        
        for i, log_entry in enumerate(logs, 1):
            try:
                message = log_entry.get("message")
                vendor = vendor_hint or log_entry.get("vendor", "unknown")
                
                retrieval = retriever.search(
                    raw_log=message,
                    top_k=RAG_TOP_K,
                    vendor_hint=vendor if vendor != "unknown" else None,
                    candidate_pool_size=RAG_CANDIDATE_POOL_SIZE,
                )
                
                if retrieval["results"]:
                    top_result = retrieval["results"][0]
                    rag_result = {
                        "vendor": top_result["vendor"],
                        "event_id": top_result["event_id"],
                        "category": top_result["category"],
                        "severity": top_result["severity"],
                        "message_template": top_result["message_template"],
                        "product_family": top_result.get("product_family", "Unknown"),
                    }
                    
                    normalized = normalize_event(log_entry, rag_result)
                    results.append(normalized)
                    print(f"✓ Processed log {i}/{len(logs)}")
                else:
                    print(f"⚠ No match found for log {i}/{len(logs)}")
            
            except Exception as e:
                print(f"✗ Error processing log {i}: {e}")
        
        # Save results
        output_file = log_path.with_name(f"{log_path.stem}_normalized.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✓ Processed {len(results)} logs successfully")
        print(f"✓ Results saved to: {output_file}")
        return True
    
    except Exception as e:
        print(f"✗ Error processing log file: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="RAG Pipeline Runner - Network Event Log Processing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_rag.py                          # Run with test data
  python run_rag.py --config                # Show configuration
  python run_rag.py --log-file logs.json    # Process log file
  python run_rag.py --log-file logs.json --vendor aruba  # With vendor hint
        """
    )
    
    parser.add_argument('--config', action='store_true',
                        help='Display configuration and exit')
    parser.add_argument('--log-file', type=str,
                        help='Path to JSON file with logs to process')
    parser.add_argument('--vendor', type=str,
                        help='Vendor hint for retrieval (aruba, cisco, etc.)')
    
    args = parser.parse_args()
    
    # Ensure required directories exist
    ensure_directories_exist()
    
    # Show config if requested
    if args.config:
        print_config()
        return 0
    
    # Process log file if provided
    if args.log_file:
        success = process_log_file(args.log_file, args.vendor)
        return 0 if success else 1
    
    # Run test pipeline by default
    success = run_test_pipeline()
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
