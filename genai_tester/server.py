from __future__ import annotations

import contextlib
import json
import time
import uuid

import aiohttp
from aiohttp import web

from genai_tester.certs import load_ssl_context_server
from genai_tester.models import ServerConfig


def _uuid() -> str:
    return uuid.uuid4().hex


def _openai_response(model: str = "gpt-4o") -> dict:
    return {
        "id": f"chatcmpl-{_uuid()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11},
    }


# matches chatgpt_parser in nbnbnb.C
async def handle_chatgpt(request: web.Request) -> web.Response:
    with contextlib.suppress(Exception):
        await request.json()
    return web.Response(
        status=200, content_type="application/json", body=json.dumps(_openai_response())
    )


# matches chatgpt file upload parser in nbnbnb.C
async def handle_chatgpt_upload(request: web.Request) -> web.Response:
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"upload_id": _uuid(), "status": "success"}),
    )


# matches claude file parser in nbnbnb.C
async def handle_claude_chat(request: web.Request) -> web.Response:
    with contextlib.suppress(Exception):
        await request.json()
    body = {
        "id": f"msg_{_uuid()}",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "OK"}],
        "model": "claude-3-5-sonnet-20241022",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 1},
    }
    return web.Response(status=200, content_type="application/json", body=json.dumps(body))


# matches claude file upload parser in nbnbnb.C
async def handle_claude_upload(request: web.Request) -> web.Response:
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"file_uuid": _uuid()}),
    )


# matches copilot file parser in nbnbnb.C (WebSocket)
async def handle_copilot_ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            resp = json.dumps({"type": "message", "author": "bot", "text": "OK"})
            await ws.send_str(resp)
            break
        elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
            break
    return ws


# matches copilot file upload parser in nbnbnb.C
async def handle_copilot_upload(request: web.Request) -> web.Response:
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"attachmentId": _uuid()}),
    )


# matches teams_copilot_parser in nbnbnb.C
async def handle_teams_copilot(request: web.Request) -> web.Response:
    with contextlib.suppress(Exception):
        await request.json()
    body = {"itemId": _uuid(), "type": "message", "text": "OK"}
    return web.Response(status=200, content_type="application/json", body=json.dumps(body))


# matches teams_copilot_upload_parser in nbnbnb.C
async def handle_teams_upload(request: web.Request) -> web.Response:
    body = {
        "id": _uuid(),
        "name": "data.txt",
        "@odata.type": "#microsoft.graph.driveItem",
    }
    return web.Response(status=201, content_type="application/json", body=json.dumps(body))


# matches deepseek file parser in nbnbnb.C
async def handle_deepseek_chat(request: web.Request) -> web.Response:
    with contextlib.suppress(Exception):
        await request.json()
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps(_openai_response("deepseek-chat")),
    )


# matches deepseek file upload parser in nbnbnb.C
async def handle_deepseek_upload(request: web.Request) -> web.Response:
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"file_id": _uuid(), "status": "success"}),
    )


# matches duck file parser in nbnbnb.C
async def handle_duck(request: web.Request) -> web.Response:
    with contextlib.suppress(Exception):
        await request.json()
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"role": "assistant", "message": "OK"}),
    )


# matches gemini file parser in nbnbnb.C (CT text/plain, body is JSON array)
async def handle_gemini(request: web.Request) -> web.Response:
    return web.Response(
        status=200,
        content_type="text/plain",
        body=json.dumps([None, None, "OK"]),
    )


# matches gemini file upload parser in nbnbnb.C
async def handle_gemini_upload(request: web.Request) -> web.Response:
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"upload_id": _uuid()}),
    )


# matches grok file parser in nbnbnb.C
async def handle_grok_chat(request: web.Request) -> web.Response:
    with contextlib.suppress(Exception):
        await request.json()
    body = {"message": {"text": "OK", "role": "ASSISTANT"}, "conversationId": _uuid()}
    return web.Response(status=200, content_type="application/json", body=json.dumps(body))


# matches grok file upload parser in nbnbnb.C
async def handle_grok_upload(request: web.Request) -> web.Response:
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"fileId": _uuid()}),
    )


# matches huggingface chat completions parser in nbnbnb.C
async def handle_hf_completions(request: web.Request) -> web.Response:
    with contextlib.suppress(Exception):
        await request.json()
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps(_openai_response("meta-llama/Llama-3-8b-instruct")),
    )


# matches huggingface prompt parser and huggingface inputs parser in nbnbnb.C
async def handle_hf_generic(request: web.Request) -> web.Response:
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps([{"generated_text": "OK"}]),
    )


# matches lovable file parser in nbnbnb.C
async def handle_lovable(request: web.Request) -> web.Response:
    with contextlib.suppress(Exception):
        await request.json()
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"id": _uuid(), "message": "OK"}),
    )


# matches perplexity file parser in nbnbnb.C
async def handle_perplexity_chat(request: web.Request) -> web.Response:
    with contextlib.suppress(Exception):
        await request.json()
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"answer": "OK", "query_str": ""}),
    )


# matches perplexity file upload parser in nbnbnb.C (S3 bucket path)
async def handle_perplexity_upload(request: web.Request) -> web.Response:
    return web.Response(
        status=200,
        content_type="application/json",
        body=json.dumps({"key": _uuid(), "etag": "abc123"}),
    )


async def handle_health(request: web.Request) -> web.Response:
    return web.Response(status=200, text="ok")


def build_app() -> web.Application:
    app = web.Application()

    # --- Exact paths (registered first to take priority) ---
    app.router.add_post("/backend-api/conversation", handle_chatgpt)
    app.router.add_post("/c/api/attachments", handle_copilot_upload)
    app.router.add_post("/m365Copilot/Chathub", handle_teams_copilot)
    app.router.add_post("/api/v0/chat/completion", handle_deepseek_chat)
    app.router.add_post("/api/v0/file/upload_file", handle_deepseek_upload)
    app.router.add_post("/duckchat/v1/chat", handle_duck)
    app.router.add_post("/rest/app-chat/upload-file", handle_grok_upload)
    app.router.add_post("/rest/sse/perplexity_ask", handle_perplexity_chat)
    app.router.add_get("/healthz", handle_health)

    # --- WebSocket ---
    app.router.add_get("/c/api/chat", handle_copilot_ws)

    # --- Parameterised paths (specific → general) ---

    # Gemini: /_/BardChatUi/data/<tail>
    app.router.add_post("/_/BardChatUi/data/{tail:.+}", handle_gemini)

    # Gemini upload: /upload/?upload_id=<id>
    app.router.add_post("/upload/", handle_gemini_upload)

    # Claude chat: /api/organizations/{org}/chat_conversations/{conv}/completion
    app.router.add_post(
        "/api/organizations/{org}/chat_conversations/{conv}/completion",
        handle_claude_chat,
    )
    # Claude upload: /api/organizations/{org}/chat_conversations/{conv}/upload-file
    app.router.add_post(
        "/api/organizations/{org}/chat_conversations/{conv}/upload-file",
        handle_claude_upload,
    )

    # Teams upload: /personal/<tail>/drive/items
    app.router.add_post("/personal/{tail:.+}/drive/items", handle_teams_upload)

    # Lovable: /projects/{uuid}/chat
    app.router.add_post("/projects/{uuid}/chat", handle_lovable)

    # Grok chat: /rest/app-chat/conversations/{id}
    app.router.add_post("/rest/app-chat/conversations/{id}", handle_grok_chat)

    # HuggingFace completions: /<tail>/chat/completions — before generic catch-all
    app.router.add_post("/{tail:.+}/chat/completions", handle_hf_completions)

    # ChatGPT upload: PUT /{uuid} — PUT method avoids collision with POST catch-all
    app.router.add_put("/{uuid}", handle_chatgpt_upload)

    # HuggingFace generic (prompt/inputs) + perplexity upload + teams upload fallback: last
    app.router.add_post("/{tail:.+}", handle_hf_generic)

    return app


def run_server(config: ServerConfig) -> None:
    ssl_ctx = load_ssl_context_server(config.cert_file, config.key_file)
    app = build_app()
    web.run_app(app, host=config.host, port=config.port, ssl_context=ssl_ctx)
