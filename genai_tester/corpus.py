from __future__ import annotations

import random
from pathlib import Path

import yaml

from genai_tester.models import Category

CorpusData = dict[str, list[str]]

REQUIRED_CATEGORIES: frozenset[str] = frozenset({
    "credentials",
    "pci_credit_cards",
    "pii",
    "employee_names",
    "employee_email_addresses",
    "us_employer_identification_number",
    "us_social_security_numbers",
    "email_address",
    "phone_number",
    "israel_id",
    "uk_national_insurance_number",
    "source_code",
})


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
    violation_ratio: float,
    rng: random.Random,
    weights: dict[str, float] | None = None,
) -> tuple[str, Category]:
    if rng.random() < violation_ratio or "clean" not in corpus:
        if weights:
            # Filter to categories that exist in this corpus; drop unknowns silently
            available = {k: v for k, v in weights.items() if k in corpus and k != "clean"}
        else:
            available = {}
        if not available:
            # Equal weights across all violation categories present in corpus
            available = {k: 1.0 for k in corpus if k != "clean"}
        if not available:
            available = {"pii": 1.0}
        cats = list(available.keys())
        raw_weights = list(available.values())
        total = sum(raw_weights)
        normalised = [w / total for w in raw_weights]
        category: Category = rng.choices(cats, weights=normalised, k=1)[0]  # type: ignore[assignment]
    else:
        category = "clean"

    prompt = rng.choice(corpus[category])
    return prompt, category
