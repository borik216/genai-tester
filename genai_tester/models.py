from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# fmt: off
Chatbot = Literal[
    # ChatGPT (chatgpt.com) — chatgpt_parser / chatgpt file upload parser in nbnbnb.C
    "chatgpt_chat", "chatgpt_upload",
    # Claude (claude.ai) — claude file parser / claude file upload parser
    "claude_chat", "claude_upload",
    # Copilot consumer (copilot.microsoft.com) — copilot file parser / copilot file upload parser
    "copilot_chat", "copilot_upload",
    # Teams Copilot (substrate.office.com) — teams_copilot_parser / teams_copilot_upload_parser
    "teams_copilot_chat", "teams_copilot_upload",
    # DeepSeek (chat.deepseek.com) — deepseek file parser / deepseek file upload parser
    "deepseek_chat", "deepseek_upload",
    # DuckDuckGo AI (duck.ai) — duck file parser
    "duck_chat",
    # Gemini (gemini.google.com) — gemini file parser / gemini file upload parser
    "gemini_chat", "gemini_upload",
    # Grok (grok.com) — grok file parser / grok file upload parser
    "grok_chat", "grok_upload",
    # HuggingFace (router.huggingface.co) — three parsers: completions, prompt, inputs
    "hf_completions", "hf_prompt", "hf_inputs",
    # Lovable (api.lovable.dev) — lovable file parser
    "lovable_chat",
    # Perplexity (perplexity.ai) — perplexity file parser / perplexity file upload parser
    "perplexity_chat", "perplexity_upload",
]
# fmt: on

FlowType = Literal["chat", "file_upload"]

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
    flow_type: FlowType
    prompt_category: Category
    prompt_hash: str
    http_status: int | None
    outcome: str
    response_summary: str
