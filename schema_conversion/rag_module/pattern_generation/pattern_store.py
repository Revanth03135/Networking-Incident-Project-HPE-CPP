import json
from pathlib import Path
from typing import List, Dict, Any, Optional

# Import config
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "schema_convertor" / "rag_module"))
from config import PATTERN_REGISTRY_PATH


class PatternStore:
    def __init__(self, path: str = None):
        # Use config default if not provided
        if path is None:
            path = str(PATTERN_REGISTRY_PATH)
        self.path = Path(path)
        self.data = {
            "version": "1.0",
            "patterns": []
        }
        self.load()

    def load(self) -> None:
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        else:
            self.save()

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

    def get_all(self) -> List[Dict[str, Any]]:
        return self.data.get("patterns", [])

    def get_by_id(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        for pattern in self.get_all():
            if pattern.get("pattern_id") == pattern_id:
                return pattern
        return None

    def add_or_update(self, pattern: Dict[str, Any]) -> None:
        patterns = self.get_all()

        for i, existing in enumerate(patterns):
            if existing.get("pattern_id") == pattern.get("pattern_id"):
                patterns[i] = pattern
                self.save()
                return

        patterns.append(pattern)
        self.save()

    def increment_usage(self, pattern_id: str) -> None:
        patterns = self.get_all()
        for pattern in patterns:
            if pattern.get("pattern_id") == pattern_id:
                pattern["usage_count"] = int(pattern.get("usage_count", 0)) + 1
                break
        self.save()