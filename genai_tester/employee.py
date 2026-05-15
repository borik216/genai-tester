from __future__ import annotations

import asyncio
import hashlib
import random
import ssl
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from genai_tester.certs import load_ssl_context_client
from genai_tester.corpus import CorpusData, pick_prompt
from genai_tester.log import AsyncJSONLWriter
from genai_tester.models import Chatbot, LogRecord, RunConfig

CHATBOT_URLS: dict[str, tuple[str, str]] = {
    "anthropic": ("api.anthropic.com", "/v1/messages"),
    "openai": ("api.openai.com", "/v1/chat/completions"),
    "google": (
        "generativelanguage.googleapis.com",
        "/v1beta/models/gemini-1.5-pro:generateContent",
    ),
}

CHATBOTS: list[Chatbot] = ["anthropic", "openai", "google"]


def build_url(chatbot: str, config: RunConfig) -> str:
    host, path = CHATBOT_URLS[chatbot]
    if config.insecure_local:
        # Dev override: bypass gateway, connect directly to fake server on localhost
        host = f"{config.server_host}:{config.server_port}"
    return f"https://{host}{path}"


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
        case _:
            raise ValueError(f"Unknown chatbot: {chatbot}")


async def employee_task(
    employee_id: str,
    department: str,
    config: RunConfig,
    corpus: CorpusData,
    client: httpx.AsyncClient,
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
        url = build_url(chatbot, config)
        body = build_request_body(chatbot, prompt)

        http_status: int | None = None
        outcome: str
        response_summary: str

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

    async with httpx.AsyncClient(**client_kwargs) as client:
        deadline = time.monotonic() + config.duration
        tasks: list[asyncio.Task[None]] = []

        for dept, count in config.departments.items():
            for i in range(count):
                employee_id = f"{dept}-{i + 1:02d}"
                rng = random.Random(random.randbytes(8))
                task = asyncio.create_task(
                    employee_task(
                        employee_id, dept, config, corpus, client, writer, deadline, rng
                    ),
                    name=employee_id,
                )
                tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for task, result in zip(tasks, results):
            if isinstance(result, Exception):
                print(f"[warn] employee {task.get_name()} crashed: {result}", flush=True)
