# genai-tester

DLP test harness for Check Point gateway inspection of GenAI chatbot traffic.

Simulates N employees sending prompts to AI chatbot APIs through a gateway that performs HTTPS
inspection and DLP policy enforcement. The harness generates correctly-classified traffic with
controlled DLP-violating content and self-logs every attempt as JSONL.

---

## Supported chatbots

| Chatbot | Hostname(s) | Path | Protocol | Mode | Source |
|---------|-------------|------|----------|------|--------|
| Claude (Anthropic) | `api.anthropic.com` | `/v1/messages` | HTTPS | API | [docs.anthropic.com](https://docs.anthropic.com/en/api/messages) |
| ChatGPT (OpenAI) | `api.openai.com` | `/v1/chat/completions` | HTTPS | API | [platform.openai.com](https://platform.openai.com/docs/api-reference/chat) |
| Gemini (Google) | `generativelanguage.googleapis.com` | `/v1beta/models/gemini-1.5-pro:generateContent` | HTTPS | API | [ai.google.dev](https://ai.google.dev/api/generate-content) |
| Grok (xAI) | `api.x.ai` | `/v1/chat/completions` | HTTPS | API | [docs.x.ai](https://docs.x.ai/docs/guides/chat-completions) |
| DeepSeek | `api.deepseek.com` | `/chat/completions` | HTTPS | API | [api-docs.deepseek.com](https://api-docs.deepseek.com/) |
| Copilot (consumer) | `copilot.microsoft.com` | `/c/api/chat` | **WSS** | Web UI ⚠ | Network capture (reverse-engineered) |
| Perplexity | `api.perplexity.ai` | `/chat/completions` | HTTPS | API | [docs.perplexity.ai](https://docs.perplexity.ai/api-reference/chat-completions-post) |

> ⚠ **Copilot**: Microsoft publishes no API documentation for the consumer chatbot at
> `copilot.microsoft.com`. The endpoint was determined by network-tab inspection and may change
> without notice. TODO: revisit when/if Microsoft publishes consumer API docs.
> Enterprise M365 Copilot (`graph.microsoft.com`) is a separate product and is out of scope.

---

## Architecture / Topology

```
  Internal subnet                                      External subnet
  ┌──────────────────────────┐                        ┌───────────────────────────┐
  │  Employee Simulator       │                        │  Fake Upstream Server      │
  │  (genai-tester run)       │──── HTTPS ────────────►│  (genai-tester serve)      │
  │                           │                        │  :443  server.pem/key      │
  │  /etc/hosts:              │                        └───────────────────────────┘
  │  api.anthropic.com   → GW │                                     ▲
  │  api.openai.com      → GW │        ┌─────────────────────┐      │ HTTPS (trusts our CA)
  │  generative*.googleapis.* → GW │   │  Check Point Gateway │──────┘
  │  chatgpt.com         → GW │   └──►│  HTTPS Inspection    │
  │  claude.ai           → GW │        │  DLP Policy          │
  │                           │        │  Trusts our CA       │
  └──────────────────────────┘        └─────────────────────┘
```

**TLS flow:**

- Client → Gateway: gateway presents a certificate bumped with our CA. Client trusts it because
  `certs/ca.pem` is installed in the OS trust store (or passed via `--ca-cert`).
- Gateway → Server: server presents `certs/server.pem` signed by our CA. Gateway trusts it because
  we imported `certs/ca.pem` into SmartConsole as a trusted CA.

**Deployment variants** — the harness is topology-agnostic:

| Deployment | Client side | Server side | Gateway |
|---|---|---|---|
| Two VMs | VM-A (internal NIC) | VM-B (external NIC) | Gateway VM routing between |
| Network namespaces | netns-client | netns-server | veth pair + ip route |
| Docker bridge | client container | server container | gateway container / host routing |

`/etc/hosts` on the client side maps all chatbot hostnames to the gateway's IP. No code changes
needed across deployments.

---

## Prerequisites

- Python 3.12+
- Port 443 requires root or `CAP_NET_BIND_SERVICE` on Linux (see [Troubleshooting](#troubleshooting))

---

## Installation

```bash
pip install -e .          # runtime only
pip install -e ".[test]"  # include pytest for running tests
```

After installation the `genai-tester` entry point is available as an alternative to
`python -m genai_tester`:

```bash
genai-tester gen-certs
genai-tester serve --host 127.0.0.1 --port 8443
genai-tester run --employees 5 --duration 10 --insecure-local
```

---

## Step 1 — Generate certificates

```bash
python -m genai_tester gen-certs
# Writes: certs/ca.pem  certs/ca.key  certs/server.pem  certs/server.key
# Idempotent: safe to re-run; does nothing if all four files already exist.
```

---

## Step 2 — Install the CA certificate

### On the gateway (SmartConsole)

1. Open SmartConsole → **Manage & Settings → Blades → HTTPS Inspection → Trusted CAs**.
2. Import `certs/ca.pem`.
3. Install policy.

### On the client (Linux)

```bash
sudo cp certs/ca.pem /usr/local/share/ca-certificates/genai-tester.crt
sudo update-ca-certificates
```

### On the client (macOS)

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain certs/ca.pem
```

### On the client (Windows)

```powershell
Import-Certificate -FilePath certs\ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

---

## Step 3 — Configure /etc/hosts (client side, full-lab runs only)

Add the following to `/etc/hosts` on the client host, replacing `<gateway-ip>` with the gateway's
internal-subnet IP address:

```
<gateway-ip>  api.anthropic.com
<gateway-ip>  api.openai.com
<gateway-ip>  generativelanguage.googleapis.com
<gateway-ip>  chatgpt.com
<gateway-ip>  claude.ai
<gateway-ip>  api.x.ai
<gateway-ip>  api.deepseek.com
<gateway-ip>  api.perplexity.ai
<gateway-ip>  copilot.microsoft.com
```

---

## Smoke test (no gateway needed)

Run everything on localhost with TLS verification disabled — good for verifying the harness itself.

```bash
# Terminal 1 — start fake server on a non-privileged port
python -m genai_tester serve --host 127.0.0.1 --port 8443

# Terminal 2 — run 3 employees for 20 seconds at 1 req/2 sec each
python -m genai_tester run \
  --insecure-local \
  --server-host 127.0.0.1 \
  --server-port 8443 \
  --employees 3 \
  --duration 20 \
  --rate-per-employee 0.5 \
  --violation-ratio 0.5 \
  --log-file smoke.jsonl
```

Verify the output:

```bash
python -c "
import json
lines = [json.loads(l) for l in open('smoke.jsonl')]
print(f'Records: {len(lines)}')
outcomes = {r['outcome'] for r in lines}
print(f'Outcomes: {outcomes}')
assert outcomes == {'sent'}, 'Expected only sent in smoke test'
assert all(r['http_status'] == 200 for r in lines)
print('PASS')
"
```

In smoke test mode all outcomes should be `sent` with `http_status: 200` — no gateway means no
blocks.

---

## Full lab run (gateway in path)

```bash
# On the server host (external subnet)
python -m genai_tester serve --host 0.0.0.0 --port 443

# On the client host (internal subnet, after Steps 2-3 above)
python -m genai_tester run \
  --employees 10 \
  --departments "engineering:3,hr:3,finance:2,legal:2" \
  --rate-per-employee 0.016 \
  --duration 600 \
  --violation-ratio 0.4 \
  --ca-cert certs/ca.pem \
  --log-file "run-$(date +%s).jsonl"
```

---

## JSONL log schema

Each line is a JSON object:

| Field | Type | Example |
|---|---|---|
| `timestamp` | ISO 8601 string | `"2025-05-15T09:23:11.042+00:00"` |
| `employee_id` | string | `"engineering-02"` |
| `department` | string | `"engineering"` |
| `target_chatbot` | `"anthropic"` \| `"openai"` \| `"google"` \| `"xai"` \| `"deepseek"` \| `"perplexity"` \| `"copilot"` | `"xai"` |
| `prompt_category` | see below | `"credential"` |
| `prompt_hash` | SHA-256 hex | `"a3f1..."` |
| `http_status` | integer or `null` | `200`, `403`, `null` |
| `outcome` | `"sent"` \| `"blocked-by-gw"` \| `"network-error"` \| `"timeout"` | `"sent"` |
| `response_summary` | first 120 chars of response body or error message | `'{"id":"msg_..."}'` |

**Prompt categories:** `clean`, `pii`, `credential`, `source_with_secret`, `internal_codename`,
`customer_data`.

**Outcome semantics:**

| Outcome | Meaning |
|---|---|
| `sent` | HTTP response received from the fake server (clean prompt passed through) |
| `blocked-by-gw` | Gateway returned HTTP 403 (DLP policy triggered) |
| `network-error` | TCP connection failed — gateway dropped the connection outright |
| `timeout` | No response within 15 seconds |

Cross-reference `prompt_hash` against Check Point SmartLog to correlate harness records with
gateway log entries.

---

## Local end-to-end test on your laptop (no lab needed)

Proxy mode routes the harness through mitmproxy acting as a stand-in DLP engine. It exercises
the same TLS-MITM + content-inspection code path the real gateway uses. Fully offline — the
`dlp_addon.py` short-circuits every request with a fake response.

> **Note:** `tools/dlp_addon.py` is a stand-in DLP engine, not the real Check Point inspector.
> It exercises the same TLS-bump and content-inspection code path but uses regex patterns instead
> of the gateway's policy engine.

### One-time setup

```bash
# Install mitmproxy
pip install mitmproxy

# Generate the mitmproxy CA (stored in ~/.mitmproxy/mitmproxy-ca-cert.pem)
mitmproxy   # press q immediately to quit — you only need the CA generated
```

### Manual run

```bash
# Terminal 1 — start the DLP stand-in
mitmdump -s tools/dlp_addon.py --listen-port 8080

# Terminal 2 — run the harness through it
python -m genai_tester run \
  --employees 5 \
  --duration 30 \
  --rate-per-employee 0.5 \
  --violation-ratio 0.5 \
  --proxy http://127.0.0.1:8080 \
  --proxy-ca ~/.mitmproxy/mitmproxy-ca-cert.pem \
  --log-file proxy_run.jsonl
```

Terminal 1 will print lines like:
```
[DLP] BLOCK host=api.anthropic.com match=us_ssn category=pii
[DLP] PASS  host=api.openai.com bytes=142
```

Terminal 2 JSONL will show `outcome: "blocked-by-gw"` / `http_status: 403` for violations and
`outcome: "sent"` / `http_status: 200` for clean prompts.

### Automated run

```bash
pytest tests/test_local_e2e.py -v
```

The test spawns `mitmdump` automatically, runs the harness for 5 seconds with 10 employees at
2 req/s (≈100 requests), and asserts: every violation prompt → 403, every clean prompt → 200.

---

## CLI reference

```
python -m genai_tester gen-certs [--out-dir DIR]

python -m genai_tester serve
  [--host HOST]        # default: 0.0.0.0
  [--port PORT]        # default: 443
  [--cert-file PATH]   # default: certs/server.pem
  [--key-file PATH]    # default: certs/server.key

python -m genai_tester run
  --employees N
  [--departments "dept:count,..."]  # must sum to --employees; default: single "default" dept
  [--rate-per-employee RATE]        # mean req/sec per employee (default: 0.0167 = 1/60)
  [--duration SECS]                 # default: 300
  [--violation-ratio RATIO]         # 0.0–1.0, default: 0.3
  [--insecure-local]                # dev mode: bypass gateway, skip TLS verification
  [--server-host HOST]              # for --insecure-local (default: localhost)
  [--server-port PORT]              # for --insecure-local (default: 443)
  [--proxy URL]                     # e.g. http://127.0.0.1:8080 (mutually exclusive with --insecure-local)
  [--proxy-ca PATH]                 # CA cert for proxy TLS (required with --proxy)
  [--ca-cert PATH]                  # default: certs/ca.pem
  [--log-file PATH]                 # default: stdout
  [--corpus PATH]                   # default: corpus/prompts.yaml
```

`--insecure-local` and `--proxy` / `--proxy-ca` are mutually exclusive. `--proxy` and `--proxy-ca`
must always be specified together.

---

## Troubleshooting

**`Permission denied` binding port 443 (Linux)**

```bash
# Option A — run as root in lab (simplest)
sudo python -m genai_tester serve

# Option B — grant capability to the interpreter
sudo setcap cap_net_bind_service+ep $(which python3.12)
python -m genai_tester serve

# Option C — use a non-privileged port and add a redirect
python -m genai_tester serve --port 8443
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
```

**TLS handshake errors on the client**

- Verify `certs/ca.pem` is installed in the OS trust store (`update-ca-certificates` on Debian/Ubuntu).
- Or pass `--ca-cert certs/ca.pem` to `genai-tester run` and confirm the path exists.
- For quick debugging, check with: `curl --cacert certs/ca.pem https://api.anthropic.com/healthz`
  (after `/etc/hosts` redirect is in place).

**/etc/hosts not taking effect**

- Flush the DNS cache: `sudo systemd-resolve --flush-caches` (Linux) or `sudo dscacheutil -flushcache` (macOS).
- Confirm the entry with: `getent hosts api.anthropic.com`.

**Cert expired**

Re-run `python -m genai_tester gen-certs --out-dir certs` after deleting the old `certs/` directory.
Remember to re-import `ca.pem` into SmartConsole and reinstall the policy.
