"""
Advanced RAG Pipeline Test with Performance Monitoring
Tests the RAG system with custom inputs and detailed performance metrics
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Add modules to path
rag_module_dir = Path(__file__).parent / "schema_convertor" / "rag_model"
sys.path.insert(0, str(rag_module_dir))
sys.path.insert(0, str(rag_module_dir / "Core_RAG"))
sys.path.insert(0, str(rag_module_dir / "schema_former"))

from config import get_config_summary
from retriever import RAGRetriever
from normalize_events import normalize_event


class PerformanceMonitor:
    """Monitor system performance during RAG pipeline execution"""
    
    def __init__(self):
        self.start_time = None
        self.metrics = {
            "queries": [],
            "total_execution_time": 0,
            "avg_query_time": 0,
        }
    
    def start(self):
        """Start performance monitoring"""
        self.start_time = time.time()
    
    def record_query(self, query_time: float, query_name: str = ""):
        """Record a single query execution time"""
        self.metrics["queries"].append({
            "name": query_name,
            "time_ms": round(query_time * 1000, 2)
        })
    
    def end(self):
        """End performance monitoring"""
        end_time = time.time()
        
        self.metrics["total_execution_time"] = round(end_time - self.start_time, 2)
        
        if self.metrics["queries"]:
            total_query_time = sum(q["time_ms"] for q in self.metrics["queries"])
            self.metrics["avg_query_time"] = round(total_query_time / len(self.metrics["queries"]), 2)
    
    def get_report(self) -> Dict[str, Any]:
        """Get performance report"""
        return self.metrics


def print_header(title: str, width: int = 80):
    """Print formatted header"""
    print("\n" + "=" * width)
    print(title.center(width))
    print("=" * width)


def print_section(title: str, width: int = 80):
    """Print formatted section"""
    print("\n" + "-" * width)
    print(f"  {title}")
    print("-" * width)


def test_single_query(retriever: RAGRetriever, raw_log: Dict[str, Any], 
                     vendor_hint: str, test_name: str, monitor: PerformanceMonitor) -> bool:
    """Test a single RAG query"""
    
    print(f"\n📝 {test_name}")
    print(f"   Vendor: {vendor_hint}")
    print(f"   Message: {raw_log['message'][:70]}...")
    
    try:
        # Measure retrieval time
        query_start = time.time()
        retrieval = retriever.search(
            raw_log=raw_log["message"],
            top_k=3,
            vendor_hint=vendor_hint,
            candidate_pool_size=80,
        )
        query_time = time.time() - query_start
        monitor.record_query(query_time, test_name)
        
        # Display results
        if not retrieval["results"]:
            print("   ⚠️  No retrieval results found")
            return False
        
        print(f"   ✓ Retrieval completed in {query_time*1000:.2f}ms")
        
        # Show top results
        print(f"\n   📊 Top Results:")
        for i, result in enumerate(retrieval["results"][:3], 1):
            print(f"      {i}. Score: {result['final_score']:.4f} | "
                  f"ID: {result['record_id']} | "
                  f"Template: {result['message_template'][:50]}...")
        
        # Normalize event
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
        
        print(f"\n   📋 Normalized Event:")
        print(f"      Event UID: {normalized['event_uid']}")
        print(f"      Type: {normalized['type']} | Subtype: {normalized['subtype']}")
        print(f"      Severity: {normalized['severity']}")
        print(f"      Hostname: {normalized['hostname']}")
        if normalized.get('interface_id'):
            print(f"      Interface: {normalized['interface_id']}")
        if normalized.get('ip'):
            print(f"      IP: {normalized['ip']}")
        
        print(f"\n   ✅ Test passed")
        return True
        
    except Exception as e:
        print(f"   ❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main test execution"""
    
    print_header("🚀 RAG PIPELINE - ADVANCED PERFORMANCE TEST", 90)
    
    # Initialize monitor
    monitor = PerformanceMonitor()
    monitor.start()
    
    # Display configuration
    print_section("Configuration", 90)
    config = get_config_summary()
    print(f"  Project Root: {config['project_root']}")
    print(f"  Embedding Model: {config['embedding_model']}")
    print(f"  Top-K Results: {config['rag_top_k']}")
    print(f"  Candidate Pool Size: {config['rag_candidate_pool_size']}")
    
    # Initialize RAG Retriever
    print_section("Initializing RAGRetriever", 90)
    try:
        retriever = RAGRetriever()
        print(f"  ✓ RAGRetriever initialized successfully")
        print(f"  ✓ Index contains {retriever.index.ntotal} vectors")
        print(f"  ✓ Metadata records: {len(retriever.metadata)}")
    except FileNotFoundError as e:
        print(f"  ❌ Error: {e}")
        print(f"\n  ⚠️  Required files not found:")
        print(f"     - {config['event_index_path']}")
        print(f"     - {config['embedding_metadata_path']}")
        return
    except Exception as e:
        print(f"  ❌ Error initializing retriever: {e}")
        return
    
    # Test Data - Original + Custom
    test_cases = [
        {
            "name": "TEST 1: Aruba Re-Auth Timeout",
            "vendor": "aruba",
            "log": {
                "event_time": "2026-04-03T10:20:11Z",
                "hostname": "sw1",
                "ip": None,
                "message": "Port 1/1/10-re-auth timeout 30 too short."
            }
        },
        {
            "name": "TEST 2: Aruba DNS Resolution Failure",
            "vendor": "aruba",
            "log": {
                "event_time": "2026-04-03T10:25:00Z",
                "hostname": "sw1",
                "ip": None,
                "message": "Unable to resolve the Activate activate.example.com https://activate.example.com."
            }
        },
        {
            "name": "TEST 3: Cisco Connection Denied",
            "vendor": "cisco",
            "log": {
                "event_time": "2026-04-03T10:30:00Z",
                "hostname": "fw1",
                "ip": None,
                "message": "%ASA-2-106001: Inbound TCP connection denied from 10.10.1.5/443 to 192.168.1.10/5151 flags SYN on interface inside"
            }
        },
        {
            "name": "TEST 4: Custom - Authentication Failure",
            "vendor": "aruba",
            "log": {
                "event_time": "2026-04-03T11:00:00Z",
                "hostname": "switch-core",
                "ip": "192.168.1.1",
                "message": "Authentication failed for supp Port 2/3/5 after 3 retry attempts."
            }
        },
        {
            "name": "TEST 5: Custom - Port ACL Modification",
            "vendor": "aruba",
            "log": {
                "event_time": "2026-04-03T11:15:00Z",
                "hostname": "access-switch",
                "ip": "10.0.0.50",
                "message": "Unable to modify ACL Port-5/1/3- ACL is applied. Configuration rejected."
            }
        },
        {
            "name": "TEST 6: Custom - Multiple Auth Timeouts",
            "vendor": "aruba",
            "log": {
                "event_time": "2026-04-03T11:30:00Z",
                "hostname": "sw2",
                "ip": None,
                "message": "45 auth-timeouts for the last 60 sec. Check authentication server connectivity."
            }
        },
        {
            "name": "TEST 7: Custom - Cisco ACL Denied",
            "vendor": "cisco",
            "log": {
                "event_time": "2026-04-03T11:45:00Z",
                "hostname": "fw-main",
                "ip": "172.16.0.1",
                "message": "%ASA-3-106010: Deny inbound TCP connection attempt from 203.45.67.89/12345 to 192.168.1.5/22 on interface outside, Connection-id=58923"
            }
        },
    ]
    
    # Run tests
    print_section("Running Tests", 90)
    results = []
    passed = 0
    failed = 0
    
    for i, test_case in enumerate(test_cases, 1):
        success = test_single_query(
            retriever=retriever,
            raw_log=test_case["log"],
            vendor_hint=test_case["vendor"],
            test_name=test_case["name"],
            monitor=monitor
        )
        results.append({
            "test": test_case["name"],
            "passed": success
        })
        if success:
            passed += 1
        else:
            failed += 1
    
    # Performance metrics
    monitor.end()
    metrics = monitor.get_report()
    
    # Summary
    print_section("Test Summary", 90)
    print(f"  Total Tests: {len(test_cases)}")
    print(f"  ✅ Passed: {passed}")
    print(f"  ❌ Failed: {failed}")
    print(f"  Success Rate: {(passed/len(test_cases))*100:.1f}%")
    
    print_section("Performance Metrics", 90)
    print(f"  Total Execution Time: {metrics['total_execution_time']:.2f}s")
    print(f"  Number of Queries: {len(metrics['queries'])}")
    print(f"  Average Query Time: {metrics['avg_query_time']:.2f}ms")
    
    if metrics['queries']:
        times = [q['time_ms'] for q in metrics['queries']]
        print(f"  Fastest Query: {min(times):.2f}ms")
        print(f"  Slowest Query: {max(times):.2f}ms")
        print(f"  Total Query Time: {sum(times):.2f}ms")
    
    print(f"  Average Time per Query: {metrics['total_execution_time']/len(test_cases):.2f}s")
    
    # Detailed query times
    print_section("Query Execution Times", 90)
    for i, query in enumerate(metrics['queries'], 1):
        print(f"  {i}. {query['name']}: {query['time_ms']:.2f}ms")
    
    # Final report
    print_header("✨ TEST REPORT COMPLETE", 90)
    print(f"\n  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Status: {'🟢 ALL TESTS PASSED' if failed == 0 else f'🟡 {failed} TESTS FAILED'}")
    print(f"  System Performance: {'✅ Excellent' if metrics['avg_query_time'] < 200 else '⚠️  Good' if metrics['avg_query_time'] < 500 else '❌ Needs Optimization'}")
    print("\n" + "=" * 90 + "\n")


if __name__ == "__main__":
    main()
