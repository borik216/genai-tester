from __future__ import annotations

import random
from pathlib import Path

import yaml

from genai_tester.models import Category

CorpusData = dict[str, list[str]]

REQUIRED_CATEGORIES: frozenset[str] = frozenset(
    {"clean", "pii", "credential", "source_with_secret", "internal_codename", "customer_data"}
)

# Per-department weights over violation categories only (clean handled separately).
# Values are relative; they are normalised before sampling.
DEPT_VIOLATION_WEIGHTS: dict[str, dict[str, float]] = {
    "engineering": {
        "source_with_secret": 0.50,
        "internal_codename": 0.30,
        "credential": 0.10,
        "pii": 0.10,
    },
    "hr": {
        "pii": 0.60,
        "customer_data": 0.30,
        "credential": 0.10,
    },
    "finance": {
        "customer_data": 0.50,
        "credential": 0.20,
        "pii": 0.20,
        "internal_codename": 0.10,
    },
    "legal": {
        "customer_data": 0.40,
        "internal_codename": 0.40,
        "pii": 0.20,
    },
    "default": {
        "pii": 0.34,
        "credential": 0.33,
        "internal_codename": 0.33,
    },
}


def load_corpus(path: str | Path) -> CorpusData:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    cats: dict[str, list[str]] = raw["categories"]
    missing = REQUIRED_CATEGORIES - cats.keys()
    if missing:
        raise ValueError(f"Corpus missing categories: {sorted(missing)}")
    for name, prompts in cats.items():
        if not prompts:
            raise ValueError(f"Category '{name}' has no prompts")
    return cats


def pick_prompt(
    corpus: CorpusData,
    department: str,
    violation_ratio: float,
    rng: random.Random,
) -> tuple[str, Category]:
    if rng.random() < violation_ratio:
        dept_weights = DEPT_VIOLATION_WEIGHTS.get(department, DEPT_VIOLATION_WEIGHTS["default"])
        # Filter to categories that exist in this corpus
        available = {k: v for k, v in dept_weights.items() if k in corpus}
        if not available:
            available = {"pii": 1.0}
        categories = list(available.keys())
        weights = list(available.values())
        total = sum(weights)
        normalised = [w / total for w in weights]
        category: Category = rng.choices(categories, weights=normalised, k=1)[0]  # type: ignore[assignment]
    else:
        category = "clean"

    prompt = rng.choice(corpus[category])
    return prompt, category
