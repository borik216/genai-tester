"""
mitmproxy addon — stand-in DLP engine for local end-to-end testing.

HTTP chatbots: short-circuits every request (returns 403 on a pattern match or a
shape-correct 200). No traffic reaches real upstream APIs; the harness runs fully offline.

Copilot consumer (WSS): detects WebSocket upgrade by header, redirects the upgrade to
the local fake server (FAKE_SERVER_HOST:FAKE_SERVER_PORT), then inspects each client→server
WebSocket frame. Frame matches → flow.kill() (client sees connection closed = blocked).
Frame clean → fake server responds.

Service coverage derived from nbnbnb.C (cpcode version 5).

Usage:
    FAKE_SERVER_PORT=8444 mitmdump -s tools/dlp_addon.py --listen-port 8080 --ssl-insecure
"""

from __future__ import annotations

import email.parser
import json
import os
import re
import time
import uuid

from mitmproxy import http

# Fake server coordinates for Copilot WebSocket redirect.
FAKE_SERVER_HOST: str = os.environ.get("FAKE_SERVER_HOST", "127.0.0.1")
FAKE_SERVER_PORT: int = int(os.environ.get("FAKE_SERVER_PORT", "8444"))

# All hosts whose traffic is intercepted for DLP inspection.
# Derived from nbnbnb.C parser domain matches (cpcode version 5).
CHATBOT_HOSTS: frozenset[str] = frozenset(
    {
        # chatgpt_parser
        "chatgpt.com",
        "files.oaiusercontent.com",
        # claude file parser / claude file upload parser
        "claude.ai",
        # copilot file parser / copilot file upload parser
        "copilot.microsoft.com",
        "copilot.com",
        "www.copilot.com",
        # teams_copilot_parser / teams_copilot_upload_parser
        "substrate.office.com",
        "oncprealp-my.sharepoint.com",
        # deepseek file parser / deepseek file upload parser
        "chat.deepseek.com",
        # duck file parser
        "duck.ai",
        # gemini file parser / gemini file upload parser
        "gemini.google.com",
        "push.clients6.google.com",
        "clients6.google.com",
        # grok file parser / grok file upload parser
        "grok.com",
        # huggingface parsers
        "router.huggingface.co",
        # lovable file parser
        "api.lovable.dev",
        # perplexity file parser / perplexity file upload parser
        "perplexity.ai",
        "ppl-ai-file-upload.s3.amazonaws.com",
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

# Hosts that use WebSocket and need redirect to the fake server.
_WS_HOSTS: frozenset[str] = frozenset({"copilot.microsoft.com", "copilot.com", "www.copilot.com"})


def _extract_text(flow: http.HTTPFlow) -> str:
    """Extract the user-visible text from a request body for DLP scanning."""
    raw = flow.request.content or b""
    ct = flow.request.headers.get("Content-Type", "")
    host = flow.request.pretty_host

    # Multipart form data (file uploads): extract text/plain parts
    if "multipart/form-data" in ct:
        try:
            # Build a MIME message so email.parser can find parts
            mime_header = f"Content-Type: {ct}\r\n\r\n"
            msg = email.parser.BytesParser().parsebytes(mime_header.encode() + raw)
            parts: list[str] = []
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode("utf-8", errors="replace"))
            if parts:
                return "\n".join(parts)
        except Exception:
            pass
        return raw.decode("utf-8", errors="replace")

    # Gemini: text/plain body is a JSON array; prompt at [5][0][0]
    if "text/plain" in ct and "gemini" in host:
        try:
            arr = json.loads(raw)
            return arr[5][0][0]
        except Exception:
            pass
        return raw.decode("utf-8", errors="replace")

    # JSON bodies: extract from the field the parser inspects
    if "application/json" in ct or ct == "":
        try:
            body = json.loads(raw)
            if isinstance(body, dict):
                # chatgpt: parts list
                if "messages" in body and isinstance(body["messages"], list):
                    texts = []
                    for m in body["messages"]:
                        content = m.get("content", "")
                        if isinstance(content, list):
                            for c in content:
                                if isinstance(c, dict):
                                    texts.extend(c.get("parts", []))
                        elif isinstance(content, str):
                            texts.append(content)
                    if texts:
                        return "\n".join(str(t) for t in texts)
                if "prompt" in body:       # claude_chat, hf_prompt
                    return str(body["prompt"])
                if "query" in body:        # perplexity_chat
                    return str(body["query"])
                if "inputs" in body:       # hf_inputs
                    return str(body["inputs"])
                if "message" in body:      # grok_chat (str value)
                    msg_val = body["message"]
                    if isinstance(msg_val, str):
                        return msg_val
                if "query" in body:        # duck_chat
                    return str(body["query"])
                if "arguments" in body:    # teams_copilot_chat
                    try:
                        return str(body["arguments"][0]["source"])
                    except (IndexError, KeyError, TypeError):
                        pass
                # fallback: dump the whole thing
                return json.dumps(body)
        except Exception:
            pass

    return raw.decode("utf-8", errors="replace")


def _fake_response_body(host: str, path: str) -> tuple[str, str]:
    """Return (content_type, json_body_str) for a clean pass."""
    uid = uuid.uuid4().hex

    if "claude.ai" in host:
        if "upload-file" in path:
            return "application/json", json.dumps({"file_uuid": uid})
        return "application/json", json.dumps(
            {
                "id": f"msg_{uid}",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "OK"}],
                "model": "claude-3-5-sonnet-20241022",
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 10, "output_tokens": 1},
            }
        )

    if "gemini.google.com" in host:
        return "text/plain", json.dumps([None, None, "OK"])

    if "push.clients6.google.com" in host or "clients6.google.com" in host:
        return "application/json", json.dumps({"upload_id": uid})

    if "duck.ai" in host:
        return "application/json", json.dumps({"role": "assistant", "message": "OK"})

    if "substrate.office.com" in host:
        return "application/json", json.dumps({"itemId": uid, "type": "message", "text": "OK"})

    if "oncprealp-my.sharepoint.com" in host:
        return "application/json", json.dumps({"id": uid, "name": "data.txt"})

    if "grok.com" in host:
        if "upload-file" in path:
            return "application/json", json.dumps({"fileId": uid})
        return "application/json", json.dumps(
            {"message": {"text": "OK", "role": "ASSISTANT"}, "conversationId": uid}
        )

    if "api.lovable.dev" in host:
        return "application/json", json.dumps({"id": uid, "message": "OK"})

    if "perplexity.ai" in host:
        return "application/json", json.dumps({"answer": "OK", "query_str": ""})

    if "ppl-ai-file-upload.s3.amazonaws.com" in host:
        return "application/json", json.dumps({"key": uid, "etag": "abc123"})

    if "copilot.microsoft.com" in host and "attachments" in path:
        return "application/json", json.dumps({"attachmentId": uid})

    if "files.oaiusercontent.com" in host:
        return "application/json", json.dumps({"upload_id": uid, "status": "success"})

    if "router.huggingface.co" in host:
        if "chat/completions" in path:
            return "application/json", json.dumps(
                {
                    "id": f"chatcmpl-{uid}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": "meta-llama/Llama-3-8b-instruct",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "OK"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11},
                }
            )
        return "application/json", json.dumps([{"generated_text": "OK"}])

    # Default: OpenAI-compatible (chatgpt, deepseek, etc.)
    return "application/json", json.dumps(
        {
            "id": f"chatcmpl-{uid}",
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
    )


class DLPAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if host not in CHATBOT_HOSTS:
            return

        # WebSocket upgrade for Copilot consumer: redirect to fake server so the WS
        # connection is established there; DLP inspection fires in websocket_message.
        if host in _WS_HOSTS and flow.request.headers.get("Upgrade", "").lower() == "websocket":
            flow.metadata["copilot_ws"] = True
            flow.request.host = FAKE_SERVER_HOST
            flow.request.port = FAKE_SERVER_PORT
            return

        # HTTP requests (including upload POSTs to copilot, grok, etc.): inspect then short-circuit.
        text = _extract_text(flow)
        path = flow.request.path

        for category, name, pattern in DLP_PATTERNS:
            if pattern.search(text):
                print(f"[DLP] BLOCK host={host} match={name} category={category}", flush=True)
                flow.response = http.Response.make(
                    403,
                    json.dumps({"error": "blocked_by_dlp", "match": name}),
                    {"Content-Type": "application/json"},
                )
                return

        print(f"[DLP] PASS host={host} bytes={len(flow.request.content)}", flush=True)
        ct, body = _fake_response_body(host, path)
        flow.response = http.Response.make(200, body, {"Content-Type": ct})

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if not flow.metadata.get("copilot_ws"):
            return

        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]
        if not msg.from_client:
            return

        # Frame body: {"event":"send","content":{"type":"text","text":"<prompt>"},...}
        # Extract text for DLP scanning.
        body_str = msg.text or ""
        try:
            frame = json.loads(body_str)
            # Prompt is in content.text for send events; fall back to full body scan.
            text = frame.get("content", {}).get("text") or body_str
        except Exception:
            text = body_str

        for category, name, pattern in DLP_PATTERNS:
            if pattern.search(text):
                print(
                    f"[DLP] WS BLOCK host=copilot.microsoft.com match={name} category={category}",
                    flush=True,
                )
                msg.drop()
                flow.kill()
                return

        print(
            f"[DLP] WS PASS host=copilot.microsoft.com bytes={len(msg.content)}", flush=True
        )


addons = [DLPAddon()]
