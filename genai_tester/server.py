from __future__ import annotations

import json
import time
import uuid

from aiohttp import web

from genai_tester.certs import load_ssl_context_server
from genai_tester.models import ServerConfig


async def handle_anthropic(request: web.Request) -> web.Response:
    try:
        await request.json()
    except json.JSONDecodeError:
        return web.Response(status=400, text="Bad Request")

    body = {
        "id": f"msg_{uuid.uuid4().hex}",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "OK"}],
        "model": "claude-3-5-sonnet-20241022",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 1},
    }
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps(body),
    )


async def handle_openai(request: web.Request) -> web.Response:
    try:
        await request.json()
    except json.JSONDecodeError:
        return web.Response(status=400, text="Bad Request")

    body = {
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
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps(body),
    )


async def handle_google(request: web.Request) -> web.Response:
    try:
        await request.json()
    except json.JSONDecodeError:
        return web.Response(status=400, text="Bad Request")

    body = {
        "candidates": [
            {
                "content": {"parts": [{"text": "OK"}], "role": "model"},
                "finishReason": "STOP",
                "index": 0,
            }
        ],
        "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 1, "totalTokenCount": 11},
    }
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps(body),
    )


async def handle_health(request: web.Request) -> web.Response:
    return web.Response(status=200, text="ok")


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/v1/messages", handle_anthropic)
    app.router.add_post("/v1/chat/completions", handle_openai)
    app.router.add_post("/v1beta/{tail:.+}", handle_google)
    app.router.add_get("/healthz", handle_health)
    return app


def run_server(config: ServerConfig) -> None:
    ssl_ctx = load_ssl_context_server(config.cert_file, config.key_file)
    app = build_app()
    web.run_app(app, host=config.host, port=config.port, ssl_context=ssl_ctx)
