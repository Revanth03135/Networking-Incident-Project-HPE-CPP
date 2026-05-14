from pprint import pprint
from pathlib import Path
from .retriever import RAGRetriever

# Get paths relative to project root
from schema_conversion.rag_module.schema_convertor.rag_model.config import (
    EVENT_INDEX_PATH,
    EMBEDDING_METADATA_PATH
)


def main():
    retriever = RAGRetriever(
        index_path=str(EVENT_INDEX_PATH),
        metadata_path=str(EMBEDDING_METADATA_PATH),
    )

    test_logs = [
        {
            "raw_log": "Port 1/1/10-re-auth timeout 30 too short.",
            "vendor_hint": "",
        },
        {
            "raw_log": "Authentication failed for supp 1/1/24.",
            "vendor_hint": "aruba",
        },
        {
            "raw_log": "Unable to resolve the Activate activate.example.com https://activate.example.com.",
            "vendor_hint": "aruba",
        },
        {
            "raw_log": "%ASA-2-106001: Inbound TCP connection denied from 10.10.1.5/443 to 192.168.1.10/5151 flags SYN",
            "vendor_hint": "cisco",
        },
    ]

    for i, item in enumerate(test_logs, start=1):
        print("\n" + "=" * 100)
        print(f"TEST #{i}")
        print("=" * 100)

        result = retriever.search(
            raw_log=item["raw_log"],
            top_k=5,
            vendor_hint=item["vendor_hint"],
        )

        print("RAW QUERY       :", result["query_raw"])
        print("NORMALIZED QUERY:", result["query_normalized"])
        print("VENDOR HINT     :", result["vendor_hint"])
        print("\nTOP RESULTS:\n")

        for rank, rec in enumerate(result["results"], start=1):
            print(f"Rank #{rank}")
            print(f"  record_id        : {rec['record_id']}")
            print(f"  vendor           : {rec['vendor']}")
            print(f"  event_id         : {rec['event_id']}")
            print(f"  category         : {rec['category']}")
            print(f"  severity         : {rec['severity']}")
            print(f"  similarity_score : {rec['similarity_score']}")
            print(f"  trust_score      : {rec['trust_score']}")
            print(f"  final_score      : {rec['final_score']}")
            print(f"  message_template : {rec['message_template']}")
            print(f"  quality_flags    : {rec['quality_flags']}")
            print("-" * 80)


if __name__ == "__main__":
    main()