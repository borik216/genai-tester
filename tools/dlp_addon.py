"""
mitmproxy addon — stand-in DLP engine for local end-to-end testing.

Short-circuits every request to a target chatbot hostname: returns 403 on
a pattern match (BLOCK) or a shape-correct 200 (PASS).  No traffic ever
reaches the real upstream APIs; the harness runs fully offline.

Usage:
    mitmdump -s tools/dlp_addon.py --listen-port 8080
"""
from __future__ import annotations

import json
import re
import time
import uuid

from mitmproxy import http

CHATBOT_HOSTS: frozenset[str] = frozenset(
    {
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        "claude.ai",
        "chatgpt.com",
    }
)

# Each entry: (corpus_category, pattern_name, compiled_regex).
# Order matters — first match wins.
DLP_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # ── pii ──────────────────────────────────────────────────────────────────
    ("pii", "us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    (
        "pii",
        "pii_keyword",
        re.compile(
            r"\b(?:SSN|DOB|MRN|Medicare\s+ID|employee\s+ID|patient\s+ID)\b",
            re.IGNORECASE,
        ),
    ),
    ("pii", "internal_email", re.compile(r"@[a-z0-9.-]+\.internal\b", re.IGNORECASE)),
    # ── credential ───────────────────────────────────────────────────────────
    ("credential", "aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("credential", "github_pat", re.compile(r"\bghp_[A-Za-z0-9]+\b")),
    (
        "credential",
        "bearer_jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+"),
    ),
    ("credential", "ssh_private_key", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
    ("credential", "cred_keyword", re.compile(r"\b(?:password|passwd)\b", re.IGNORECASE)),
    # ── source_with_secret ───────────────────────────────────────────────────
    (
        "source_with_secret",
        "secret_assignment",
        re.compile(
            r"\b\w*(?:key|pass|secret|token|auth)\w*\s*=\s*[\"'][^\"']{4,}",
            re.IGNORECASE,
        ),
    ),
    (
        "source_with_secret",
        "env_export_secret",
        re.compile(r"\bexport\s+[A-Z_]*(?:KEY|PASS|SECRET|TOKEN|AUTH)[A-Z_]*=\S{4,}"),
    ),
    # ── internal_codename ────────────────────────────────────────────────────
    (
        "internal_codename",
        "codename",
        re.compile(r"\b(?:Project|Operation|Codename|Initiative)\s+[A-Z][A-Z0-9_-]{2,}\b"),
    ),
    # ── customer_data ────────────────────────────────────────────────────────
    ("customer_data", "arr_figure", re.compile(r"\$[\d,.]+[MmKk]?\s*ARR\b")),
    (
        "customer_data",
        "contract_ref",
        re.compile(r"\b(?:contract|PO)\s+#[A-Z0-9-]+\b", re.IGNORECASE),
    ),
    ("customer_data", "account_id_kw", re.compile(r"\baccount\s+(?:ID|id)\s+\d+\b")),
    (
        "customer_data",
        "business_metric",
        re.compile(
            r"\b(?:SLA\s+breach|renewal\s+probability|churn\s+(?:rate|factor)|MRR|ACV|TCV)\b",
            re.IGNORECASE,
        ),
    ),
]


def _fake_response(host: str) -> dict[str, object]:
    if "anthropic" in host or "claude" in host:
        return {
            "id": f"msg_{uuid.uuid4().hex}",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "OK"}],
            "model": "claude-3-5-sonnet-20241022",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 1},
        }
    if "openai" in host or "chatgpt" in host:
        return {
            "id": f"chatcmpl-{uuid.uuid4().hex}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "OK"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11},
        }
    # google / gemini
    return {
        "candidates": [
            {
                "content": {"parts": [{"text": "OK"}], "role": "model"},
                "finishReason": "STOP",
                "index": 0,
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 1,
            "totalTokenCount": 11,
        },
    }


class DLPAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if host not in CHATBOT_HOSTS:
            return

        body = flow.request.text or ""

        for category, name, pattern in DLP_PATTERNS:
            if pattern.search(body):
                print(
                    f"[DLP] BLOCK host={host} match={name} category={category}",
                    flush=True,
                )
                flow.response = http.Response.make(
                    403,
                    json.dumps({"error": "blocked_by_dlp", "match": name}),
                    {"Content-Type": "application/json"},
                )
                return

        print(
            f"[DLP] PASS host={host} bytes={len(flow.request.content)}",
            flush=True,
        )
        flow.response = http.Response.make(
            200,
            json.dumps(_fake_response(host)),
            {"Content-Type": "application/json"},
        )


addons = [DLPAddon()]
