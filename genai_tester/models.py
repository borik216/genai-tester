from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Outcome = Literal["sent", "blocked-by-gw", "network-error", "timeout"]
Chatbot = Literal["anthropic", "openai", "google", "xai", "deepseek", "perplexity", "copilot"]
Category = Literal[
    "clean", "pii", "credential", "source_with_secret", "internal_codename", "customer_data"
]


@dataclass(frozen=True)
class RunConfig:
    employees: int = 5
    departments: dict[str, int] = field(default_factory=lambda: {"default": 5})
    rate_per_employee: float = 1 / 60
    duration: float = 300.0
    violation_ratio: float = 0.3
    insecure_local: bool = False
    server_host: str = "localhost"
    server_port: int = 443
    ca_cert: str = "certs/ca.pem"
    log_file: str | None = None
    corpus_path: str = "corpus/prompts.yaml"
    proxy: str | None = None
    proxy_ca: str | None = None


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 443
    cert_file: str = "certs/server.pem"
    key_file: str = "certs/server.key"


@dataclass
class LogRecord:
    timestamp: str
    employee_id: str
    department: str
    target_chatbot: Chatbot
    prompt_category: Category
    prompt_hash: str
    http_status: int | None
    outcome: Outcome
    response_summary: str
