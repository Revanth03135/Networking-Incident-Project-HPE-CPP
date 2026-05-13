import sys
from pathlib import Path
from .config import CORE_RAG_DIR, SCHEMA_FORMER_DIR, EVENT_INDEX_PATH, EMBEDDING_METADATA_PATH, RAG_TOP_K, RAG_CANDIDATE_POOL_SIZE

# Import modules from subpackages
from .Core_RAG.retriever import RAGRetriever
from .schema_former.normalize_events import normalize_event

def run_pipeline(raw_log_input: dict, vendor_hint: str):
    retriever = RAGRetriever(
        index_path=str(EVENT_INDEX_PATH),
        metadata_path=str(EMBEDDING_METADATA_PATH),
    )

    retrieval = retriever.search(
        raw_log=raw_log_input["message"],
        top_k=3,
        vendor_hint=vendor_hint,
        candidate_pool_size=80,
    )

    print("\n=== Retrieval Results ===")
    for i, r in enumerate(retrieval["results"], start=1):
        print(f"{i}. {r['record_id']} | score={r['final_score']} | template={r['message_template']}")

    if not retrieval["results"]:
        print("No retrieval results")
        return

    top = retrieval["results"][0]

    rag_result = {
        "vendor": top["vendor"],
        "event_id": top["event_id"],
        "category": top["category"],
        "severity": top["severity"],
        "message_template": top["message_template"],
        "product_family": "ArubaOS-Switch" if top["vendor"] == "aruba" else "Cisco Security Appliance",
    }

    normalized = normalize_event(raw_log_input, rag_result)

    print("\n=== Normalized Event ===")
    print(normalized)


if __name__ == "__main__":
    raw_log_1 = {
        "event_time": "2026-04-03T10:20:11Z",
        "hostname": "sw1",
        "ip": None,
        "message": "Port 1/1/10-re-auth timeout 30 too short."
    }

    raw_log_2 = {
        "event_time": "2026-04-03T10:25:00Z",
        "hostname": "sw1",
        "ip": None,
        "message": "Unable to resolve the Activate activate.example.com https://activate.example.com."
    }

    raw_log_3 = {
        "event_time": "2026-04-03T10:30:00Z",
        "hostname": "fw1",
        "ip": None,
        "message": "%ASA-2-106001: Inbound TCP connection denied from 10.10.1.5/443 to 192.168.1.10/5151 flags SYN on interface inside"
    }

    print("\n############################")
    print("TEST 1")
    print("############################")
    run_pipeline(raw_log_1, vendor_hint="aruba")

    print("\n############################")
    print("TEST 2")
    print("############################")
    run_pipeline(raw_log_2, vendor_hint="aruba")

    print("\n############################")
    print("TEST 3")
    print("############################")
    run_pipeline(raw_log_3, vendor_hint="cisco")