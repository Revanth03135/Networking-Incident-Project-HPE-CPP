import json
import re
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from schema_conversion.rag_module.schema_convertor.rag_model.config import (
    EMBEDDING_MODEL_NAME,
    EVENT_INDEX_PATH,
    EMBEDDING_METADATA_PATH,
)


# =========================================================
# CONFIG
# =========================================================

MODEL_NAME = EMBEDDING_MODEL_NAME

TOP_K = 5

MIN_CONFIDENCE = 0.60

HARD_MATCH_CONFIDENCE = 0.92


# =========================================================
# LOADERS
# =========================================================

def load_metadata(path: str):

    with open(path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    if not isinstance(metadata, list):
        raise ValueError("Metadata must be list")

    return metadata


# =========================================================
# BASIC HELPERS
# =========================================================

def clean_text(text: str):

    text = text.strip()

    text = re.sub(r"\s+", " ", text)

    return text


def generate_uid(raw_log: str):

    return hashlib.sha1(raw_log.encode()).hexdigest()


# =========================================================
# EXTRACTION
# =========================================================

EVENT_CODE_PATTERN = re.compile(
    r"%([A-Z0-9\\-]+):"
)

IP_PATTERN = re.compile(
    r"\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b"
)

INTERFACE_PATTERN = re.compile(
    r"(GigabitEthernet\\S+|FastEthernet\\S+|Ethernet\\S+|Port-channel\\S+|\\d+/\\d+/\\d+)"
)

TIMESTAMP_PATTERN = re.compile(
    r"^([0-9T:.\-]+Z?)"
)

HOSTNAME_PATTERN = re.compile(
    r"^[0-9T:.\-Z]+\s+([A-Za-z0-9\-_]+)"
)

# =========================================================
# TOKENIZATION
# =========================================================

STOPWORDS = {
    "the", "a", "an", "is", "are", "to", "for",
    "of", "on", "with", "and", "or", "this",
    "that", "from", "in", "at", "by"
}


def tokenize(text: str):

    return re.findall(
        r"[a-zA-Z0-9_./:%+-]+",
        text.lower()
    )


def filtered_tokens(text: str):

    return [
        t for t in tokenize(text)
        if t not in STOPWORDS
    ]


# =========================================================
# EXTRACTION HELPERS
# =========================================================

def extract_event_code(text: str):

    m = EVENT_CODE_PATTERN.search(text)

    if not m:
        return None

    return m.group(1)


def extract_ip(text: str):

    m = IP_PATTERN.search(text)

    if not m:
        return None

    return m.group(0)


def extract_interface(text: str):

    m = INTERFACE_PATTERN.search(text)

    if not m:
        return None

    return m.group(1)


def extract_timestamp(text: str):

    m = TIMESTAMP_PATTERN.search(text)

    if not m:
        return None

    return m.group(1)


def extract_hostname(text: str):

    m = HOSTNAME_PATTERN.search(text)

    if not m:
        return None

    return m.group(1)


def extract_vendor(text: str):

    t = text.lower()

    if "cisco" in t:
        return "cisco"

    if "aruba" in t:
        return "aruba"

    if "arista" in t:
        return "arista"

    if "juniper" in t:
        return "juniper"

    if "fortinet" in t:
        return "fortinet"

    return None


# =========================================================
# CANONICALIZATION
# =========================================================

EVENT_TYPE_MAP = {

    "bgp": "routing",
    "ospf": "routing",
    "eigrp": "routing",

    "link": "interface",
    "interface": "interface",

    "transceiver": "hardware",
    "fan": "hardware",
    "power": "hardware",

    "auth": "security",
    "aaa": "security",
    "acl": "security",
}


def canonical_type(event_code: Optional[str]):

    if not event_code:
        return "system"

    e = event_code.lower()

    for key, value in EVENT_TYPE_MAP.items():

        if key in e:
            return value

    return "system"


def canonical_subtype(event_code: Optional[str]):

    if not event_code:
        return "unknown"

    e = event_code.lower()

    e = e.replace("-", "_")

    return e


# =========================================================
# SCORING
# =========================================================

def jaccard_similarity(a: str, b: str):

    sa = set(filtered_tokens(a))
    sb = set(filtered_tokens(b))

    if not sa or not sb:
        return 0.0

    return len(sa & sb) / len(sa | sb)


def exact_event_boost(
    query_event: Optional[str],
    candidate_text: str
):

    if not query_event:
        return 0.0

    if query_event.lower() in candidate_text.lower():
        return 0.35

    return 0.0


def interface_boost(
    query_interface: Optional[str],
    candidate_text: str
):

    if not query_interface:
        return 0.0

    if query_interface.lower() in candidate_text.lower():
        return 0.15

    return 0.0


def vendor_boost(
    query_vendor: Optional[str],
    candidate_vendor: Optional[str]
):

    if not query_vendor:
        return 0.0

    if not candidate_vendor:
        return 0.0

    if query_vendor == candidate_vendor.lower():
        return 0.20

    return -0.20


def confidence_from_score(score: float):

    if score >= 0.92:
        return "very_high"

    if score >= 0.82:
        return "high"

    if score >= 0.70:
        return "medium"

    if score >= 0.60:
        return "low"

    return "reject"


# =========================================================
# RETRIEVER
# =========================================================

class RAGRetriever:

    def __init__(self):

        self.index = faiss.read_index(
            str(EVENT_INDEX_PATH)
        )

        self.metadata = load_metadata(
            str(EMBEDDING_METADATA_PATH)
        )

        self.model = SentenceTransformer(
            MODEL_NAME
        )

        if self.index.ntotal != len(self.metadata):

            raise ValueError(
                "Index and metadata mismatch"
            )

    # =====================================================

    def embed(self, text: str):

        vec = self.model.encode(
            [text],
            normalize_embeddings=True,
            convert_to_numpy=True
        )

        return vec.astype(np.float32)

    # =====================================================

    def search(
        self,
        raw_log: str,
        top_k: int = TOP_K
    ):

        raw_log = clean_text(raw_log)

        query_event = extract_event_code(raw_log)

        query_vendor = extract_vendor(raw_log)

        query_ip = extract_ip(raw_log)

        query_interface = extract_interface(raw_log)

        query_hostname = extract_hostname(raw_log)

        query_time = extract_timestamp(raw_log)

        query_vec = self.embed(raw_log)

        scores, indices = self.index.search(
            query_vec,
            50
        )

        candidates = []

        for score, idx in zip(
            scores[0],
            indices[0]
        ):

            if idx < 0:
                continue

            if idx >= len(self.metadata):
                continue

            record = self.metadata[idx]

            candidate_text = (
                str(record.get("message_template", "")) +
                " " +
                str(record.get("description", ""))
            )

            semantic = jaccard_similarity(
                raw_log,
                candidate_text
            )

            event_bonus = exact_event_boost(
                query_event,
                candidate_text
            )

            iface_bonus = interface_boost(
                query_interface,
                candidate_text
            )

            vboost = vendor_boost(
                query_vendor,
                record.get("vendor")
            )

            final_score = (
                0.55 * float(score) +
                0.20 * semantic +
                event_bonus +
                iface_bonus +
                vboost
            )

            confidence_label = confidence_from_score(
                final_score
            )

            candidates.append({

                "record": record,

                "score": round(final_score, 4),

                "confidence": confidence_label,

                "score_breakdown": {

                    "embedding_score": round(float(score), 4),

                    "semantic_score": round(semantic, 4),

                    "event_bonus": round(event_bonus, 4),

                    "interface_bonus": round(iface_bonus, 4),

                    "vendor_bonus": round(vboost, 4)
                }
            })

        candidates.sort(
            key=lambda x: x["score"],
            reverse=True
        )

        candidates = candidates[:top_k]

        if not candidates:

            return {
                "match_found": False,
                "confidence": "reject"
            }

        best = candidates[0]

        if best["score"] < MIN_CONFIDENCE:

            return {
                "match_found": False,
                "confidence": "reject",
                "top_candidate_score": best["score"]
            }

        record = best["record"]

        schema = {

            "event_uid": generate_uid(raw_log),

            "event_id": record.get("event_id"),

            "type": canonical_type(query_event),

            "subtype": canonical_subtype(query_event),

            "severity": record.get("severity"),

            "message": record.get("description"),

            "hostname": query_hostname,

            "ip": query_ip,

            "vendor": query_vendor,

            "os": None,

            "interface_id": query_interface,

            "vlan": None,

            "event_time": query_time,

            "raw": {
                "message": raw_log
            }
        }

        return {

            "match_found": True,

            "confidence": best["confidence"],

            "confidence_score": best["score"],

            "schema": schema,

            "top_matches": [

                {

                    "event_id": c["record"].get("event_id"),

                    "vendor": c["record"].get("vendor"),

                    "message_template": c["record"].get("message_template"),

                    "score": c["score"],

                    "confidence": c["confidence"],

                    "score_breakdown": c["score_breakdown"]

                }

                for c in candidates
            ]
        }