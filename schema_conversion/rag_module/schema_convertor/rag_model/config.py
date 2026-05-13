"""
Centralized Configuration for RAG Module
Uses relative paths for cross-platform compatibility
"""
import os
from pathlib import Path


# Get the project root directory (where this config file is located)
RAG_MODULE_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = RAG_MODULE_DIR.parent.parent.resolve()

# Core RAG paths
CORE_RAG_DIR = RAG_MODULE_DIR / "Core_RAG"
SCHEMA_FORMER_DIR = RAG_MODULE_DIR / "schema_former"
EMBEDDING_DIR = RAG_MODULE_DIR / "Embedding"
PREREQ_DIR = RAG_MODULE_DIR / "PreRequirementSteps"

# Embedding-related paths
BUILD_INDEX_DIR = EMBEDDING_DIR / "build_index"
EVENT_INDEX_PATH = BUILD_INDEX_DIR / "event_index.faiss"
EMBEDDING_METADATA_PATH = EMBEDDING_DIR / "embedding_metadata.json"
RETRIEVAL_READY_KB_PATH = EMBEDDING_DIR / "retrieval_ready_kb.json"

# Pattern generation paths
PATTERN_GENERATION_DIR = PROJECT_ROOT / "pattern_generation"
PATTERN_REGISTRY_PATH = PROJECT_ROOT / "pattern_registry.json"
DATASET_PATH = PROJECT_ROOT / "dataset.json"
LOGS_PATH = PROJECT_ROOT / "logs.txt"

# Embedding model configuration
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_BATCH_SIZE = 64

# RAG Retrieval parameters
RAG_TOP_K = 3
RAG_CANDIDATE_POOL_SIZE = 80

# Ensure required directories exist
def ensure_directories_exist():
    """Create necessary directories if they don't exist"""
    for directory in [BUILD_INDEX_DIR, EMBEDDING_DIR, PATTERN_GENERATION_DIR]:
        directory.mkdir(parents=True, exist_ok=True)


def get_config_summary() -> dict:
    """Return a dictionary of all configuration paths"""
    return {
        "project_root": str(PROJECT_ROOT),
        "rag_module_dir": str(RAG_MODULE_DIR),
        "core_rag_dir": str(CORE_RAG_DIR),
        "schema_former_dir": str(SCHEMA_FORMER_DIR),
        "embedding_dir": str(EMBEDDING_DIR),
        "event_index_path": str(EVENT_INDEX_PATH),
        "embedding_metadata_path": str(EMBEDDING_METADATA_PATH),
        "retrieval_ready_kb_path": str(RETRIEVAL_READY_KB_PATH),
        "pattern_registry_path": str(PATTERN_REGISTRY_PATH),
        "embedding_model": EMBEDDING_MODEL_NAME,
        "rag_top_k": RAG_TOP_K,
        "rag_candidate_pool_size": RAG_CANDIDATE_POOL_SIZE,
    }


if __name__ == "__main__":
    import json
    print("RAG Module Configuration")
    print("=" * 60)
    config = get_config_summary()
    print(json.dumps(config, indent=2))
