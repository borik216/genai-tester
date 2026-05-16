from __future__ import annotations

import asyncio
import hashlib
import json
import random
import ssl
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import aiohttp
import httpx

from genai_tester.certs import load_ssl_context_client
from genai_tester.corpus import CorpusData, pick_prompt
from genai_tester.log import AsyncJSONLWriter
from genai_tester.models import Chatbot, LogRecord, RunConfig

# hostname, path — for HTTP chatbots these feed build_url(); copilot uses build_ws_url().
CHATBOT_URLS: dict[str, tuple[str, str]] = {
    "anthropic": ("api.anthropic.com", "/v1/messages"),
    "openai": ("api.openai.com", "/v1/chat/completions"),
    "google": (
        "generativelanguage.googleapis.com",
        "/v1beta/models/gemini-1.5-pro:generateContent",
    ),
    # Grok uses OpenAI-compatible /v1/chat/completions — source: https://docs.x.ai/docs/guides/chat-completions
    "xai": ("api.x.ai", "/v1/chat/completions"),
    # DeepSeek uses /chat/completions without /v1/ — source: https://api-docs.deepseek.com/
    "deepseek": ("api.deepseek.com", "/chat/completions"),
    # Perplexity uses /chat/completions without /v1/ — source: https://docs.perplexity.ai/
    "perplexity": ("api.perplexity.ai", "/chat/completions"),
    # Copilot consumer (WSS) — reverse-engineered from network capture; TODO revisit official docs
    "copilot": ("copilot.microsoft.com", "/c/api/chat"),
}

CHATBOTS: list[Chatbot] = [
    "anthropic",
    "openai",
    "google",
    "xai",
    "deepseek",
    "perplexity",
    "copilot",
]


def build_url(chatbot: str, config: RunConfig) -> str:
    host, path = CHATBOT_URLS[chatbot]
    if config.insecure_local:
        host = f"{config.server_host}:{config.server_port}"
    return f"https://{host}{path}"


def build_ws_url(config: RunConfig, client_session_id: str) -> str:
    host, path = CHATBOT_URLS["copilot"]
    if config.insecure_local:
        host = f"{config.server_host}:{config.server_port}"
    return f"wss://{host}{path}?api-version=2&clientSessionId={client_session_id}"


def build_request_body(chatbot: str, prompt: str) -> dict[str, Any]:
    match chatbot:
        case "anthropic":
            return {
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 16,
                "messages": [{"role": "user", "content": prompt}],
            }
        case "openai":
            return {
                "model": "gpt-4o",
                "max_tokens": 16,
                "messages": [{"role": "user", "content": prompt}],
            }
        case "google":
            return {
                "contents": [{"parts": [{"text": prompt}], "role": "user"}],
                "generationConfig": {"maxOutputTokens": 16},
            }
        case "xai":
            # OpenAI-compatible — source: https://docs.x.ai/docs/guides/chat-completions
            return {
                "model": "grok-3",
                "messages": [{"role": "user", "content": prompt}],
            }
        case "deepseek":
            # source: https://api-docs.deepseek.com/
            return {
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": prompt}],
            }
        case "perplexity":
            # source: https://docs.perplexity.ai/api-reference/chat-completions-post
            return {
                "model": "sonar-pro",
                "messages": [{"role": "user", "content": prompt}],
            }
        case _:
            raise ValueError(f"Unknown chatbot: {chatbot}")


async def send_copilot_ws(
    ws_session: aiohttp.ClientSession,
    url: str,
    prompt: str,
    config: RunConfig,
) -> tuple[int | None, str, str]:
    """Send a prompt via WebSocket to the Copilot fake server (or through a proxy)."""
    ssl_param: bool | ssl.SSLContext
    if config.insecure_local:
        ssl_param = False
    elif config.proxy_ca:
        ssl_param = ssl.create_default_context(cafile=config.proxy_ca)
    else:
        ssl_param = load_ssl_context_client(config.ca_cert)

    proxy_param = config.proxy or None
    client_session_id = url.split("clientSessionId=")[-1]
    msg_body = json.dumps({"message": prompt, "clientSessionId": client_session_id})

    try:
        async with ws_session.ws_connect(
            url,
            ssl=ssl_param,
            proxy=proxy_param,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as ws:
            await ws.send_str(msg_body)
            # 3-second timeout: if the gateway dropped the frame (msg.drop()) the fake server
            # never responds, so the connection hangs until we time out here.
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
        # Gateway dropped the frame (msg.drop()) — no server response arrives; we time out.
        return None, "blocked-by-gw", "ws receive timeout: frame blocked by gateway"
    except aiohttp.ClientError as exc:
        return None, "network-error", str(exc)[:120]
    except OSError as exc:
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

        chatbot: Chatbot = rng.choice(CHATBOTS)
        prompt, category = pick_prompt(corpus, department, config.violation_ratio, rng)
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()

        http_status: int | None = None
        outcome: str
        response_summary: str

        if chatbot == "copilot":
            client_session_id = uuid.uuid4().hex
            ws_url = build_ws_url(config, client_session_id)
            http_status, outcome, response_summary = await send_copilot_ws(
                ws_session, ws_url, prompt, config
            )
        else:
            url = build_url(chatbot, config)
            body = build_request_body(chatbot, prompt)
            try:
                resp = await client.post(url, json=body, timeout=15.0)
                http_status = resp.status_code
                outcome = "sent"
                response_summary = resp.text[:120]
            except httpx.TimeoutException as exc:
                outcome = "timeout"
                response_summary = str(exc)[:120]
            except httpx.ConnectError as exc:
                outcome = "network-error"
                response_summary = str(exc)[:120]
            except httpx.HTTPError as exc:
                outcome = "network-error"
                response_summary = str(exc)[:120]

        record = LogRecord(
            timestamp=datetime.now(tz=UTC).isoformat(),
            employee_id=employee_id,
            department=department,
            target_chatbot=chatbot,
            prompt_category=category,
            prompt_hash=prompt_hash,
            http_status=http_status,
            outcome=outcome,  # type: ignore[arg-type]
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
