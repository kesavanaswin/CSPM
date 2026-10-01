"""
storage/json_store.py
----------------------
Lightweight JSON-file storage layer. Since the project intentionally
avoids an external database, this module centralizes all read/write
access to the /data and /output JSON files, with safe error handling.
"""

import json
import os
from typing import Any, List

from utils.logger import get_logger

logger = get_logger("storage.json_store")


class JSONStore:
    """Simple helper for loading and persisting JSON data on disk."""

    @staticmethod
    def load(path: str) -> Any:
        if not os.path.exists(path):
            logger.warning(f"Data file not found: {path}")
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info(f"Loaded {path} successfully.")
            return data
        except json.JSONDecodeError as e:
            logger.critical(f"Malformed JSON in {path}: {e}")
            return []
        except OSError as e:
            logger.critical(f"Failed to read {path}: {e}")
            return []

    @staticmethod
    def save(path: str, data: Any) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"Saved output to {path}")
            return True
        except OSError as e:
            logger.critical(f"Failed to write {path}: {e}")
            return False

    @staticmethod
    def append(path: str, record: Any) -> bool:
        """Append a single record to a JSON array file, creating it if needed."""
        existing: List[Any] = []
        if os.path.exists(path):
            existing = JSONStore.load(path)
            if not isinstance(existing, list):
                existing = []
        existing.append(record)
        return JSONStore.save(path, existing)
