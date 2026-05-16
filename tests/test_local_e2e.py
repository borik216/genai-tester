"""
Local end-to-end test: harness → mitmproxy (DLP addon) → fake server (HTTP + WSS).

Flow:
  employees → mitmdump:8080 → DLP addon inspects:
    HTTP chatbots: short-circuited with fake 200/403, no upstream needed.
    Copilot (WSS): redirected to fake_server:8444, frames inspected in websocket_message.

Requires:
  - mitmproxy installed:  pip install mitmproxy
  - CA generated once:    run `mitmproxy`, press q to quit
  - pytest installed:     pip install pytest

Run:
    pytest tests/test_local_e2e.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path

import pytest

PROXY_PORT = 8080
FAKE_SERVER_PORT = 8444
PROXY_URL = f"http://127.0.0.1:{PROXY_PORT}"
MITMPROXY_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
PROJECT_ROOT = Path(__file__).parent.parent
ADDON = PROJECT_ROOT / "tools" / "dlp_addon.py"
CORPUS = PROJECT_ROOT / "corpus" / "prompts.yaml"
CERTS_DIR = PROJECT_ROOT / "certs"


@pytest.fixture(scope="session")
def mitmproxy_ca() -> Path:
    if not MITMPROXY_CA.exists():
        pytest.skip(
            f"mitmproxy CA not found at {MITMPROXY_CA}. "
            "Run 'mitmproxy' once (then press q) to generate it, then re-run the test."
        )
    return MITMPROXY_CA


@pytest.fixture(scope="session")
def fake_server_proc() -> Generator[subprocess.Popen[bytes], None, None]:
    # Ensure certs exist; gen-certs is idempotent but we need them for TLS.
    if not (CERTS_DIR / "server.pem").exists():
        subprocess.run(
            [sys.executable, "-m", "genai_tester", "gen-certs"],
            cwd=str(PROJECT_ROOT),
            check=True,
        )

    proc = subprocess.Popen(
        [
            sys.executable, "-m", "genai_tester", "serve",
            "--host", "127.0.0.1",
            "--port", str(FAKE_SERVER_PORT),
            "--cert-file", str(CERTS_DIR / "server.pem"),
            "--key-file", str(CERTS_DIR / "server.key"),
        ],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", FAKE_SERVER_PORT), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        proc.terminate()
        pytest.fail(f"fake server did not start within 10 seconds on port {FAKE_SERVER_PORT}")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def mitmdump_proc(
    mitmproxy_ca: Path,
    fake_server_proc: subprocess.Popen[bytes],
) -> Generator[subprocess.Popen[bytes], None, None]:
    if shutil.which("mitmdump") is None:
        pytest.skip("mitmdump not found in PATH. Install with: pip install mitmproxy")

    env = os.environ.copy()
    env["FAKE_SERVER_PORT"] = str(FAKE_SERVER_PORT)

    proc = subprocess.Popen(
        [
            "mitmdump",
            "-s", str(ADDON),
            "--listen-port", str(PROXY_PORT),
            "--ssl-insecure",   # allows mitmproxy to connect to our self-signed fake server
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        proc.terminate()
        pytest.fail("mitmdump did not start within 15 seconds")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_local_e2e(
    mitmdump_proc: subprocess.Popen[bytes],
    mitmproxy_ca: Path,
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "e2e.jsonl"
    duration = 5
    employees = 14    # 14 employees × 2 req/s × 5s ≈ 140 requests → ~20 per chatbot
    rate = 2.0

    result = subprocess.run(
        [
            sys.executable, "-m", "genai_tester", "run",
            "--employees", str(employees),
            "--duration", str(duration),
            "--rate-per-employee", str(rate),
            "--violation-ratio", "0.5",
            "--proxy", PROXY_URL,
            "--proxy-ca", str(mitmproxy_ca),
            "--corpus", str(CORPUS),
            "--log-file", str(log_file),
        ],
        capture_output=True,
        text=True,
        timeout=duration + 20,
        cwd=str(PROJECT_ROOT),
    )

    assert result.returncode == 0, (
        f"harness exited with code {result.returncode}:\n"
        f"stdout: {result.stdout[:500]}\n"
        f"stderr: {result.stderr[:500]}"
    )

    assert log_file.exists(), "harness wrote no JSONL file"
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert lines, "JSONL file is empty"

    records = [json.loads(line) for line in lines]

    for rec in records:
        cat = rec["prompt_category"]
        status = rec["http_status"]
        chatbot = rec["target_chatbot"]
        eid = rec["employee_id"]

        if chatbot == "copilot":
            # Copilot uses WSS: violations are signalled by connection kill (no HTTP status).
            if cat != "clean":
                assert rec["outcome"] in ("blocked-by-gw", "network-error"), (
                    f"Copilot violation prompt ({cat}) expected block, "
                    f"got outcome={rec['outcome']} [employee={eid}]"
                )
            else:
                assert rec["outcome"] == "sent", (
                    f"Copilot clean prompt expected sent, "
                    f"got outcome={rec['outcome']} [employee={eid}]"
                )
        else:
            # HTTP chatbots: DLP addon returns 403 / 200 directly.
            if cat != "clean":
                assert status == 403, (
                    f"violation prompt ({cat}) expected 403, got {status} "
                    f"[chatbot={chatbot} employee={eid} outcome={rec['outcome']}]"
                )
            else:
                assert status == 200, (
                    f"clean prompt expected 200, got {status} "
                    f"[chatbot={chatbot} employee={eid} outcome={rec['outcome']}]"
                )

    # Every chatbot must appear in the log at least once.
    expected_chatbots = {"anthropic", "openai", "google", "xai", "deepseek", "perplexity", "copilot"}
    seen_chatbots = {rec["target_chatbot"] for rec in records}
    missing = expected_chatbots - seen_chatbots
    assert not missing, (
        f"chatbots not seen in run: {missing}. "
        f"Increase employees or duration if this flakes."
    )

    # Loose lower-bound: at least 30% of the theoretical maximum
    expected = duration * rate * employees  # ~140
    assert len(records) >= expected * 0.3, (
        f"too few records: {len(records)} (expected ≥ {int(expected * 0.3)} "
        f"from {employees} employees × {rate}/s × {duration}s)"
    )
