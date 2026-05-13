import json
from pathlib import Path
from typing import List, Dict, Any

import numpy as np
from sentence_transformers import SentenceTransformer

# Import config
from ..config import EMBEDDING_MODEL_NAME, EMBEDDING_BATCH_SIZE, RETRIEVAL_READY_KB_PATH

# ----------------------------
# Config
# ----------------------------

MODEL_NAME = EMBEDDING_MODEL_NAME
DEFAULT_BATCH_SIZE = EMBEDDING_BATCH_SIZE


# ----------------------------
# IO helpers
# ----------------------------

def load_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list")
    return data


def save_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ----------------------------
# Embedder
# ----------------------------

class KBEmbedder:
    def __init__(self, model_name: str = MODEL_NAME):
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)

    def encode_texts(
        self,
        texts: List[str],
        batch_size: int = DEFAULT_BATCH_SIZE,
        normalize: bool = True,
    ) -> np.ndarray:
        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            show_progress_bar=True,
            convert_to_numpy=True,
            normalize_embeddings=normalize,
        )
        return embeddings

    def build_embeddings(
        self,
        records: List[Dict[str, Any]],
        text_field: str = "retrieval_text",
        batch_size: int = DEFAULT_BATCH_SIZE,
        normalize: bool = True,
    ) -> Dict[str, Any]:
        """
        Returns:
            {
                "embeddings": np.ndarray,
                "metadata": List[dict]
            }
        """
        texts: List[str] = []
        metadata: List[Dict[str, Any]] = []

        for idx, record in enumerate(records):
            text = record.get(text_field)
            if not text or not isinstance(text, str) or not text.strip():
                continue

            texts.append(text)

            meta = dict(record)
            meta["embedding_row_id"] = len(metadata)
            metadata.append(meta)

        embeddings = self.encode_texts(
            texts=texts,
            batch_size=batch_size,
            normalize=normalize,
        )

        return {
            "embeddings": embeddings,
            "metadata": metadata,
        }


# ----------------------------
# Main pipeline
# ----------------------------

def main(
    input_path: str = None,
    embeddings_path: str = "event_embeddings.npy",
    metadata_path: str = "embedding_metadata.json",
    model_name: str = MODEL_NAME,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> None:
    # Use config default if not provided
    if input_path is None:
        input_path = str(RETRIEVAL_READY_KB_PATH)
    
    records = load_json(input_path)

    embedder = KBEmbedder(model_name=model_name)
    result = embedder.build_embeddings(
        records=records,
        text_field="retrieval_text",
        batch_size=batch_size,
        normalize=True,
    )

    embeddings: np.ndarray = result["embeddings"]
    metadata: List[Dict[str, Any]] = result["metadata"]

    np.save(embeddings_path, embeddings)
    save_json(metadata_path, metadata)

    print("Embedding generation complete")
    print(f"Model used          : {model_name}")
    print(f"Input records       : {len(records)}")
    print(f"Embedded records    : {len(metadata)}")
    print(f"Embedding shape     : {embeddings.shape}")
    print(f"Saved embeddings to : {embeddings_path}")
    print(f"Saved metadata to   : {metadata_path}")


if __name__ == "__main__":
    main()