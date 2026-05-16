from __future__ import annotations

import asyncio
import hashlib
import json
import random
import ssl
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import aiohttp
import httpx

from genai_tester._version import CPCODE_HASH  # noqa: F401 — imported for traceability
from genai_tester.certs import load_ssl_context_client
from genai_tester.corpus import CorpusData, pick_prompt
from genai_tester.log import AsyncJSONLWriter
from genai_tester.models import Chatbot, FlowType, LogRecord, RunConfig

_EDGE_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/146.0.0.0"
)
_MSAPP_UA = "MSAppHost/3.0"

# HuggingFace model path segment used in URL templates.
_HF_MODEL = "meta-llama/Llama-3-8b-instruct"


@dataclass(frozen=True)
class ServiceSpec:
    key: str
    hostname: str
    # Path template: {org_id}, {conv_id}, {uuid}, {bucket} are substituted per-request.
    path_template: str
    method: str  # "POST" | "PUT" | "WS"
    flow_type: FlowType
    content_type: str = "application/json"
    extra_headers: dict[str, str] = field(default_factory=dict)


# All entries derived from publicly known API shapes; matched against nbnbnb.C parser names.
# CPcode reference hash in genai_tester/_version.py.
ALL_SPECS: list[ServiceSpec] = [
    # chatgpt_parser — chatgpt.com/backend-api/conversation
    ServiceSpec(
        key="chatgpt_chat",
        hostname="chatgpt.com",
        path_template="/backend-api/conversation",
        method="POST",
        flow_type="chat",
    ),
    # chatgpt file upload parser — files.oaiusercontent.com/<uuid>
    ServiceSpec(
        key="chatgpt_upload",
        hostname="files.oaiusercontent.com",
        path_template="/{uuid}",
        method="PUT",
        flow_type="file_upload",
        content_type="multipart/form-data",
    ),
    # claude file parser — claude.ai/api/organizations/.../completion
    ServiceSpec(
        key="claude_chat",
        hostname="claude.ai",
        path_template="/api/organizations/{org_id}/chat_conversations/{conv_id}/completion",
        method="POST",
        flow_type="chat",
    ),
    # claude file upload parser — claude.ai/api/organizations/.../upload-file
    ServiceSpec(
        key="claude_upload",
        hostname="claude.ai",
        path_template="/api/organizations/{org_id}/chat_conversations/{conv_id}/upload-file",
        method="POST",
        flow_type="file_upload",
        content_type="multipart/form-data",
    ),
    # copilot file parser — copilot.microsoft.com/c/api/chat (WebSocket)
    ServiceSpec(
        key="copilot_chat",
        hostname="copilot.microsoft.com",
        path_template="/c/api/chat",
        method="WS",
        flow_type="chat",
        extra_headers={"User-Agent": _EDGE_UA},
    ),
    # copilot file upload parser — copilot.microsoft.com/c/api/attachments
    ServiceSpec(
        key="copilot_upload",
        hostname="copilot.microsoft.com",
        path_template="/c/api/attachments",
        method="POST",
        flow_type="file_upload",
        content_type="multipart/form-data",
        extra_headers={"User-Agent": _EDGE_UA},
    ),
    # teams_copilot_parser — substrate.office.com/m365Copilot/Chathub
    ServiceSpec(
        key="teams_copilot_chat",
        hostname="substrate.office.com",
        path_template="/m365Copilot/Chathub",
        method="POST",
        flow_type="chat",
        extra_headers={"User-Agent": _MSAPP_UA},
    ),
    # teams_copilot_upload_parser — oncprealp-my.sharepoint.com/.../drive/items
    ServiceSpec(
        key="teams_copilot_upload",
        hostname="oncprealp-my.sharepoint.com",
        path_template="/personal/edge_oncprealp_onmicrosoft_com/drive/items",
        method="POST",
        flow_type="file_upload",
        content_type="multipart/form-data",
        extra_headers={"User-Agent": _MSAPP_UA},
    ),
    # deepseek file parser — chat.deepseek.com/api/v0/chat/completion
    ServiceSpec(
        key="deepseek_chat",
        hostname="chat.deepseek.com",
        path_template="/api/v0/chat/completion",
        method="POST",
        flow_type="chat",
    ),
    # deepseek file upload parser — chat.deepseek.com/api/v0/file/upload_file
    ServiceSpec(
        key="deepseek_upload",
        hostname="chat.deepseek.com",
        path_template="/api/v0/file/upload_file",
        method="POST",
        flow_type="file_upload",
        content_type="multipart/form-data",
    ),
    # duck file parser — duck.ai/duckchat/v1/chat
    ServiceSpec(
        key="duck_chat",
        hostname="duck.ai",
        path_template="/duckchat/v1/chat",
        method="POST",
        flow_type="chat",
    ),
    # gemini file parser — gemini.google.com/...BardFrontendService (CT text/plain)
    ServiceSpec(
        key="gemini_chat",
        hostname="gemini.google.com",
        path_template="/_/BardChatUi/data/assistant.lamda.BardFrontendService",
        method="POST",
        flow_type="chat",
        content_type="text/plain",
    ),
    # gemini file upload parser — push.clients6.google.com/upload/?upload_id=<id>
    ServiceSpec(
        key="gemini_upload",
        hostname="push.clients6.google.com",
        path_template="/upload/",
        method="POST",
        flow_type="file_upload",
        content_type="multipart/form-data",
    ),
    # grok file parser — grok.com/rest/app-chat/conversations/<uuid>
    ServiceSpec(
        key="grok_chat",
        hostname="grok.com",
        path_template="/rest/app-chat/conversations/{uuid}",
        method="POST",
        flow_type="chat",
    ),
    # grok file upload parser — grok.com/rest/app-chat/upload-file
    ServiceSpec(
        key="grok_upload",
        hostname="grok.com",
        path_template="/rest/app-chat/upload-file",
        method="POST",
        flow_type="file_upload",
        content_type="multipart/form-data",
    ),
    # huggingface chat completions parser — router.huggingface.co/<model>/v1/chat/completions
    ServiceSpec(
        key="hf_completions",
        hostname="router.huggingface.co",
        path_template=f"/{_HF_MODEL}/v1/chat/completions",
        method="POST",
        flow_type="chat",
    ),
    # huggingface prompt parser — router.huggingface.co/<model> with {"prompt":...} body
    ServiceSpec(
        key="hf_prompt",
        hostname="router.huggingface.co",
        path_template=f"/{_HF_MODEL}",
        method="POST",
        flow_type="chat",
    ),
    # huggingface inputs parser — router.huggingface.co/<model> with {"inputs":...} body
    ServiceSpec(
        key="hf_inputs",
        hostname="router.huggingface.co",
        path_template=f"/{_HF_MODEL}",
        method="POST",
        flow_type="chat",
    ),
    # lovable file parser — api.lovable.dev/projects/<uuid>/chat
    ServiceSpec(
        key="lovable_chat",
        hostname="api.lovable.dev",
        path_template="/projects/{uuid}/chat",
        method="POST",
        flow_type="chat",
    ),
    # perplexity file parser — perplexity.ai/rest/sse/perplexity_ask
    ServiceSpec(
        key="perplexity_chat",
        hostname="perplexity.ai",
        path_template="/rest/sse/perplexity_ask",
        method="POST",
        flow_type="chat",
    ),
    # perplexity file upload parser — ppl-ai-file-upload.s3.amazonaws.com/<bucket>/<uuid>
    ServiceSpec(
        key="perplexity_upload",
        hostname="ppl-ai-file-upload.s3.amazonaws.com",
        path_template="/uploads/{uuid}",
        method="POST",
        flow_type="file_upload",
        content_type="multipart/form-data",
    ),
]

CHATBOTS: list[Chatbot] = [s.key for s in ALL_SPECS]  # type: ignore[assignment]


def _fresh_uuid(rng: random.Random) -> str:
    return uuid.UUID(int=rng.getrandbits(128)).hex


def build_path_vars(spec: ServiceSpec, rng: random.Random) -> dict[str, str]:
    return {
        "org_id": _fresh_uuid(rng),
        "conv_id": _fresh_uuid(rng),
        "uuid": _fresh_uuid(rng),
        "bucket": "ppl-uploads",
    }


def build_url(spec: ServiceSpec, config: RunConfig, path_vars: dict[str, str]) -> str:
    path = spec.path_template.format(**path_vars)
    if spec.key == "gemini_upload":
        path = f"{path}?upload_id={path_vars['uuid']}"
    host = spec.hostname
    if config.insecure_local:
        host = f"{config.server_host}:{config.server_port}"
    scheme = "wss" if spec.method == "WS" else "https"
    url = f"{scheme}://{host}{path}"
    if spec.method == "WS" and not config.insecure_local:
        url += f"?api-version=2&clientSessionId={path_vars['uuid']}"
    return url


def build_request_body(
    spec: ServiceSpec,
    prompt: str,
    rng: random.Random,
    path_vars: dict[str, str],
) -> tuple[str, Any]:
    """Return (content_type, body). body may be str, dict, or httpx-compatible files dict."""
    if spec.flow_type == "file_upload":
        # All upload flows: single multipart POST with text/plain file content.
        return "multipart/form-data", {"file": ("data.txt", prompt, "text/plain")}

    match spec.key:
        case "chatgpt_chat":
            return "application/json", {
                "action": "next",
                "messages": [
                    {
                        "id": _fresh_uuid(rng),
                        "role": "user",
                        "content": [{"content_type": "text", "parts": [prompt]}],
                    }
                ],
                "model": "gpt-4o",
                "conversation_id": None,
            }

        case "claude_chat":
            return "application/json", {"prompt": prompt}

        case "teams_copilot_chat":
            return "application/json", {
                "arguments": [{"source": prompt, "type": "UserMessage"}]
            }

        case "deepseek_chat":
            return "application/json", {
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": prompt}],
            }

        case "duck_chat":
            return "application/json", {"model": "gpt-4o-mini", "query": prompt}

        case "gemini_chat":
            # CT: text/plain. Body is a JSON array; prompt at position [5][0][0].
            # Matches gemini file parser in nbnbnb.C.
            body_str = json.dumps([None, None, None, None, None, [[prompt, 1]], None, "en"])
            return "text/plain", body_str

        case "grok_chat":
            return "application/json", {"message": prompt, "imageAttachments": []}

        case "hf_completions":
            return "application/json", {
                "messages": [{"role": "user", "content": prompt}],
                "max_new_tokens": 16,
            }

        case "hf_prompt":
            return "application/json", {"prompt": prompt, "max_new_tokens": 16}

        case "hf_inputs":
            return "application/json", {"inputs": prompt}

        case "lovable_chat":
            return "application/json", {
                "id": _fresh_uuid(rng),
                "messages": [{"role": "user", "content": prompt}],
            }

        case "perplexity_chat":
            return "application/json", {"query": prompt}

        case _:
            raise ValueError(f"No body builder for spec key: {spec.key}")


async def send_copilot_ws(
    ws_session: aiohttp.ClientSession,
    url: str,
    prompt: str,
    conv_id: str,
    client_session_id: str,
    config: RunConfig,
) -> tuple[int | None, str, str]:
    ssl_param: bool | ssl.SSLContext
    if config.insecure_local:
        ssl_param = False
    elif config.proxy_ca:
        ssl_param = ssl.create_default_context(cafile=config.proxy_ca)
    else:
        ssl_param = load_ssl_context_client(config.ca_cert)

    # Frame body starts with {"event":"send"} — matches copilot file parser in nbnbnb.C.
    frame = json.dumps(
        {
            "event": "send",
            "conversationId": conv_id,
            "content": {"type": "text", "text": prompt},
            "clientSessionId": client_session_id,
        }
    )

    try:
        async with ws_session.ws_connect(
            url,
            ssl=ssl_param,
            proxy=config.proxy or None,
            headers={"User-Agent": _EDGE_UA},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as ws:
            await ws.send_str(frame)
            resp_msg = await asyncio.wait_for(ws.receive(), timeout=3)
            if resp_msg.type == aiohttp.WSMsgType.TEXT:
                return 101, "sent", resp_msg.data[:120]
            elif resp_msg.type in (
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSING,
                aiohttp.WSMsgType.ERROR,
            ):
                return None, "blocked-by-gw", f"ws closed: code={resp_msg.data}"
            else:
                return None, "network-error", f"unexpected ws type: {resp_msg.type}"
    except TimeoutError:
        return None, "blocked-by-gw", "ws receive timeout: frame blocked by gateway"
    except aiohttp.ClientError as exc:
        return None, "network-error", str(exc)[:120]
    except OSError as exc:
        return None, "network-error", str(exc)[:120]


async def send_http(
    spec: ServiceSpec,
    url: str,
    prompt: str,
    client: httpx.AsyncClient,
    rng: random.Random,
    path_vars: dict[str, str],
) -> tuple[int | None, str, str]:
    content_type, body = build_request_body(spec, prompt, rng, path_vars)
    headers: dict[str, str] = dict(spec.extra_headers)

    try:
        if content_type == "multipart/form-data":
            resp = await client.request(
                spec.method, url, files=body, headers=headers, timeout=15.0
            )
        elif content_type == "text/plain":
            headers["Content-Type"] = "text/plain"
            resp = await client.post(url, content=body.encode(), headers=headers, timeout=15.0)
        else:
            resp = await client.post(url, json=body, headers=headers, timeout=15.0)
        return resp.status_code, "sent", resp.text[:120]
    except httpx.TimeoutException as exc:
        return None, "timeout", str(exc)[:120]
    except httpx.ConnectError as exc:
        return None, "network-error", str(exc)[:120]
    except httpx.HTTPError as exc:
        return None, "network-error", str(exc)[:120]


async def employee_task(
    employee_id: str,
    department: str,
    config: RunConfig,
    corpus: CorpusData,
    client: httpx.AsyncClient,
    ws_session: aiohttp.ClientSession,
    writer: AsyncJSONLWriter,
    deadline: float,
    rng: random.Random,
) -> None:
    while True:
        interval = rng.expovariate(config.rate_per_employee)
        await asyncio.sleep(interval)
        if time.monotonic() >= deadline:
            break

        spec: ServiceSpec = rng.choice(ALL_SPECS)
        prompt, category = pick_prompt(corpus, department, config.violation_ratio, rng)
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        path_vars = build_path_vars(spec, rng)
        url = build_url(spec, config, path_vars)

        http_status: int | None = None

        if spec.method == "WS":
            conv_id = path_vars["uuid"]
            client_session_id = _fresh_uuid(rng)
            http_status, outcome, response_summary = await send_copilot_ws(
                ws_session, url, prompt, conv_id, client_session_id, config
            )
        else:
            http_status, outcome, response_summary = await send_http(
                spec, url, prompt, client, rng, path_vars
            )

        record = LogRecord(
            timestamp=datetime.now(tz=UTC).isoformat(),
            employee_id=employee_id,
            department=department,
            target_chatbot=spec.key,  # type: ignore[arg-type]
            flow_type=spec.flow_type,
            prompt_category=category,
            prompt_hash=prompt_hash,
            http_status=http_status,
            outcome=outcome,
            response_summary=response_summary,
        )
        await writer.write(record)


async def run_employees(
    config: RunConfig,
    corpus: CorpusData,
    writer: AsyncJSONLWriter,
) -> None:
    verify: bool | ssl.SSLContext | str
    if config.insecure_local:
        verify = False
    elif config.proxy_ca:
        verify = config.proxy_ca
    else:
        verify = load_ssl_context_client(config.ca_cert)

    client_kwargs: dict[str, Any] = {"verify": verify}
    if config.proxy:
        client_kwargs["proxy"] = config.proxy

    async with httpx.AsyncClient(**client_kwargs) as client, aiohttp.ClientSession() as ws_session:
        deadline = time.monotonic() + config.duration
        tasks: list[asyncio.Task[None]] = []

        for dept, count in config.departments.items():
            for i in range(count):
                employee_id = f"{dept}-{i + 1:02d}"
                rng = random.Random(random.randbytes(8))
                task = asyncio.create_task(
                    employee_task(
                        employee_id,
                        dept,
                        config,
                        corpus,
                        client,
                        ws_session,
                        writer,
                        deadline,
                        rng,
                    ),
                    name=employee_id,
                )
                tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for task, result in zip(tasks, results, strict=True):
            if isinstance(result, Exception):
                print(f"[warn] employee {task.get_name()} crashed: {result}", flush=True)
