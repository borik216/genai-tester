# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies (prefer uv)
uv sync
# or: pip install -e ".[test]"

# Run CLI directly (three subcommands)
python -m genai_tester gen-certs
python -m genai_tester serve --host 127.0.0.1 --port 8443
python -m genai_tester run --employees 5 --duration 10 --insecure-local

# Run tests
pytest tests/
pytest tests/test_local_e2e.py -v   # single test file

# Lint
ruff check genai_tester/ tools/
ruff format genai_tester/ tools/
```

## Architecture

The harness simulates N employees sending prompts through a DLP gateway to fake AI chatbot APIs, then logs each request outcome as JSONL.

**Three-command CLI** (`genai_tester/cli.py`):
- `gen-certs` — generates CA + server TLS certs into `certs/` (idempotent)
- `serve` — starts the fake upstream chatbot server (`server.py`, aiohttp)
- `run` — launches the employee simulation (`employee.py`, httpx async)

**Deployment topologies** (controlled by CLI flags):
1. `--insecure-local` — smoke test, client talks directly to fake server, TLS verification off
2. `--proxy <url>` — client routes through mitmproxy/DLP gateway
3. Full lab — /etc/hosts + `--ca-cert` to route through a real gateway that TLS-bumps traffic

**Employee simulation** (`employee.py`):
- Each employee is an async task. Inter-request intervals are Poisson-distributed (`expovariate(rate_per_employee)`).
- `violation_ratio` controls how often DLP-triggering prompts are chosen. Department-specific weights skew which *category* of violation each department is likely to produce (e.g., engineering → `source_with_secret`, HR → `pii`).
- Randomly targets one of three chatbot APIs: Anthropic `/v1/messages`, OpenAI `/v1/chat/completions`, Google `/v1beta/...`.

**Fake server** (`server.py`): Returns shape-correct mock responses for all three chatbot APIs over TLS. No real AI calls are made.

**Corpus** (`corpus/prompts.yaml`): Six categories — `clean`, `pii`, `credential`, `source_with_secret`, `internal_codename`, `customer_data`. Loaded and validated by `corpus.py`.

**JSONL logging** (`log.py` → `models.py`): One record per request. Key fields: `employee_id`, `department`, `target_chatbot`, `prompt_category`, `prompt_hash`, `http_status`, `outcome` (`sent` | `blocked-by-gw` | `network-error` | `timeout`), `response_summary`.

**Local E2E test** (`tests/test_local_e2e.py`): Spawns `mitmdump` with `tools/dlp_addon.py` (a regex-based DLP engine with 16 pattern rules). Runs the harness for 5 seconds and asserts clean prompts → 200, violation prompts → 403.

## Key Constraints

- Python 3.12+ required.
- `certs/` is gitignored — always run `gen-certs` before `serve` or `run`.
- `*.jsonl` log files are gitignored.
- Ruff config: 100-char line limit, selects E, F, I, UP, B, SIM.
- The fake server and the mitmproxy addon both mimic real API response shapes so gateway inspection logic sees realistic traffic.
