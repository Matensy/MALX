"""Shannon entropy helpers (0.0 – 8.0 bits per byte)."""

from __future__ import annotations

from pathlib import Path

import numpy as np

from backend.core.storage import iter_chunks


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    return _from_counts(counts, len(data))


def _from_counts(counts: np.ndarray, total: int) -> float:
    if total == 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(round(-(p * np.log2(p)).sum(), 4))


def file_entropy(path: Path, limit: int | None = None) -> float:
    counts = np.zeros(256, dtype=np.int64)
    total = 0
    for chunk in iter_chunks(path, limit=limit):
        counts += np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
        total += len(chunk)
    return _from_counts(counts, total)


def entropy_profile(path: Path, size: int, points: int = 128) -> list[float]:
    """Entropy of evenly distributed windows across the file (for the entropy chart)."""
    if size <= 0:
        return []
    window = max(256, min(65536, size // points or 256))
    step = max(1, size // points)
    out: list[float] = []
    with open(path, "rb") as fh:
        for i in range(points):
            offset = i * step
            if offset >= size:
                break
            fh.seek(offset)
            out.append(shannon(fh.read(window)))
    return out


def classify_entropy(value: float) -> str:
    if value >= 7.2:
        return "very high (compressed/encrypted-like)"
    if value >= 6.5:
        return "high"
    if value >= 4.0:
        return "typical"
    return "low"
