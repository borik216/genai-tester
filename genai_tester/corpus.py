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

# Per-department weights over violation categories only (clean handled separately).
# Values are relative; they are normalised before sampling.
DEPT_VIOLATION_WEIGHTS: dict[str, dict[str, float]] = {
    "engineering": {
        "source_code": 0.50,
        "credentials": 0.30,
        "employee_email_addresses": 0.10,
        "email_address": 0.10,
    },
    "hr": {
        "pii": 0.30,
        "employee_names": 0.25,
        "employee_email_addresses": 0.20,
        "us_social_security_numbers": 0.25,
    },
    "finance": {
        "pci_credit_cards": 0.35,
        "us_social_security_numbers": 0.25,
        "us_employer_identification_number": 0.20,
        "credentials": 0.20,
    },
    "legal": {
        "pii": 0.30,
        "us_social_security_numbers": 0.25,
        "israel_id": 0.25,
        "uk_national_insurance_number": 0.20,
    },
    "default": {
        "pii": 0.34,
        "credentials": 0.33,
        "pci_credit_cards": 0.33,
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
    if rng.random() < violation_ratio or "clean" not in corpus:
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
