import json
from pathlib import Path
from typing import Any, List, Dict
import sys

import numpy as np
import faiss

# Get paths relative to project root
config_path = Path(__file__).parent.parent.parent / "config.py"
if config_path.exists():
    from config import EMBEDDING_DIR
else:
    EMBEDDING_DIR = Path(__file__).parent.parent.parent / "Embedding"



def load_and_fix_embeddings(input_path: str, output_path: str) -> None:
    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.exists():
        raise FileNotFoundError(f"Embeddings file not found: {input_file}")

    # Temporary allow_pickle only to recover a wrongly saved object array.
    embeddings = np.load(input_file, allow_pickle=True)

    print("Loaded embeddings")
    print("Original dtype :", embeddings.dtype)
    print("Original shape :", embeddings.shape)

    # If it is an object array, convert it into a proper 2D numeric matrix.
    if embeddings.dtype == object:
        try:
            embeddings = np.vstack(embeddings)
        except Exception as exc:
            raise ValueError(
                "Failed to convert object embeddings into a numeric matrix. "
                "The saved file likely contains inconsistent objects."
            ) from exc

    # Ensure numpy array and float32 for FAISS
    embeddings = np.asarray(embeddings, dtype=np.float32)

    # Ensure 2D
    if embeddings.ndim != 2:
        raise ValueError(
            f"Expected embeddings to be 2D with shape (N, D), got shape {embeddings.shape}"
        )

    # Optional sanity checks
    if embeddings.shape[0] == 0:
        raise ValueError("Embeddings array is empty.")
    if embeddings.shape[1] == 0:
        raise ValueError("Embedding dimension is zero.")

    np.save(output_file, embeddings)

    print("\nFixed embeddings")
    print("Fixed dtype    :", embeddings.dtype)
    print("Fixed shape    :", embeddings.shape)
    print("Saved clean embeddings to:", output_file)

def load_embeddings(path: str) -> np.ndarray:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Embeddings file not found: {file_path}")

    embeddings = np.load(file_path)

    if not isinstance(embeddings, np.ndarray):
        raise TypeError("Loaded embeddings are not a NumPy array.")

    if embeddings.dtype != np.float32:
        embeddings = embeddings.astype(np.float32)

    if embeddings.ndim != 2:
        raise ValueError(
            f"Expected embeddings to be 2D with shape (N, D), got {embeddings.shape}"
        )

    return embeddings


def load_metadata(path: str) -> List[Dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Metadata file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    if not isinstance(metadata, list):
        raise ValueError("Metadata JSON must contain a list of records.")

    return metadata


def validate_alignment(embeddings: np.ndarray, metadata: List[Dict[str, Any]]) -> None:
    if embeddings.shape[0] != len(metadata):
        raise ValueError(
            f"Mismatch between embeddings and metadata: "
            f"{embeddings.shape[0]} embeddings vs {len(metadata)} metadata rows"
        )

    # Optional strict check: embedding_row_id should match row position
    for idx, record in enumerate(metadata):
        row_id = record.get("embedding_row_id")
        if row_id is None:
            raise ValueError(f"Missing embedding_row_id in metadata row {idx}")
        if int(row_id) != idx:
            raise ValueError(
                f"Metadata alignment error at row {idx}: embedding_row_id={row_id}"
            )


class FAISSIndexBuilder:
    def __init__(self, embeddings: np.ndarray):
        self.embeddings = embeddings
        self.dimension = embeddings.shape[1]
        self.index: faiss.Index | None = None

    def build(self) -> faiss.Index:
        """
        Uses IndexFlatIP. This assumes embeddings are already normalized
        if you want cosine similarity behavior.
        """
        index = faiss.IndexFlatIP(self.dimension)
        index.add(self.embeddings)
        self.index = index
        return index

    def save(self, output_path: str) -> None:
        if self.index is None:
            raise RuntimeError("Index has not been built yet.")
        faiss.write_index(self.index, output_path)


def main(
    embeddings_path: str = None,
    metadata_path: str = None,
    index_path: str = "event_index.faiss",
) -> None:
    if embeddings_path is None:
        embeddings_path = str(EMBEDDING_DIR / "build_index" / "event_embeddings_fixed.npy")
    if metadata_path is None:
        metadata_path = str(EMBEDDING_DIR / "embedding_metadata.json")
    
    load_and_fix_embeddings(
        str(EMBEDDING_DIR / "event_embeddings.npy"),
        str(EMBEDDING_DIR / "build_index" / "event_embeddings_fixed.npy")
    )
    print("Loading embeddings...")
    embeddings = load_embeddings(embeddings_path)

    print("Loading metadata...")
    metadata = load_metadata(metadata_path)

    print("Validating alignment...")
    validate_alignment(embeddings, metadata)

    print("Building FAISS index...")
    builder = FAISSIndexBuilder(embeddings)
    index = builder.build()

    print("Saving FAISS index...")
    builder.save(index_path)

    print("\nFAISS index built successfully")
    print("Embeddings file  :", embeddings_path)
    print("Metadata file    :", metadata_path)
    print("Index file       :", index_path)
    print("Vector count     :", index.ntotal)
    print("Vector dimension :", embeddings.shape[1])
    print("Embedding dtype  :", embeddings.dtype)


if __name__ == "__main__":
    main()