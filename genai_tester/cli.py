from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import yaml

from genai_tester import certs as certs_mod
from genai_tester import corpus as corpus_mod
from genai_tester import employee as employee_mod
from genai_tester import server as server_mod
from genai_tester.log import AsyncJSONLWriter
from genai_tester.models import RunConfig, ServerConfig

_DEFAULTS = {
    "employees": 5,
    "rate_per_employee": 1 / 60,
    "duration": 300.0,
    "total_requests": None,
    "violation_ratio": 0.3,
    "violation_categories": None,
    "insecure_local": False,
    "server_host": "localhost",
    "server_port": 443,
    "ca_cert": "certs/ca.pem",
    "log_file": None,
    "corpus": "corpus/prompts.yaml",
    "proxy": None,
    "proxy_ca": None,
}


def load_config_file(path: str) -> dict:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        print("error: config file must be a YAML mapping", file=sys.stderr)
        sys.exit(1)
    return raw


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="genai-tester",
        description="DLP test harness — simulates employees sending prompts through a gateway.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # gen-certs
    gc = sub.add_parser("gen-certs", help="Generate CA and server TLS certificates")
    gc.add_argument(
        "--out-dir",
        default="certs",
        metavar="DIR",
        help="Directory to write certs into (default: certs/)",
    )

    # serve
    sv = sub.add_parser("serve", help="Run the fake upstream chatbot server")
    sv.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    sv.add_argument("--port", type=int, default=443, help="Bind port (default: 443)")
    sv.add_argument("--cert-file", default="certs/server.pem", metavar="PATH")
    sv.add_argument("--key-file", default="certs/server.key", metavar="PATH")

    # run
    rp = sub.add_parser("run", help="Simulate employees sending prompts")
    rp.add_argument(
        "--config",
        default=None,
        metavar="PATH",
        help="YAML config file; CLI flags override values from the file",
    )
    rp.add_argument("--employees", type=int, default=None, metavar="N")
    rate_group = rp.add_mutually_exclusive_group()
    rate_group.add_argument(
        "--rate",
        type=float,
        default=None,
        metavar="RATE",
        help="Total aggregate requests/sec across all employees",
    )
    rate_group.add_argument(
        "--rate-per-employee",
        type=float,
        default=None,
        metavar="RATE",
        help="Mean requests/sec per employee (default: 1/60)",
    )
    rp.add_argument(
        "--duration", type=float, default=None, metavar="SECS", help="Run duration in seconds"
    )
    rp.add_argument(
        "--total-requests",
        type=int,
        default=None,
        metavar="N",
        help="Stop after N total requests (can be combined with --duration; whichever fires first wins)",
    )
    rp.add_argument(
        "--violation-ratio",
        type=float,
        default=None,
        metavar="RATIO",
        help="Fraction of prompts that contain DLP violations (default: 0.3)",
    )
    rp.add_argument(
        "--insecure-local",
        action="store_true",
        default=None,
        help="Bypass gateway: connect directly to fake server, skip TLS verification",
    )
    rp.add_argument(
        "--server-host",
        default=None,
        metavar="HOST",
        help="Fake server host for --insecure-local (default: localhost)",
    )
    rp.add_argument(
        "--server-port",
        type=int,
        default=None,
        metavar="PORT",
        help="Fake server port for --insecure-local (default: 443)",
    )
    rp.add_argument(
        "--ca-cert",
        default=None,
        metavar="PATH",
        help="CA cert to trust for gateway TLS (default: certs/ca.pem)",
    )
    rp.add_argument(
        "--log-file", default=None, metavar="PATH", help="JSONL output file (default: stdout)"
    )
    rp.add_argument(
        "--corpus",
        default=None,
        metavar="PATH",
        help="Prompt corpus YAML (default: corpus/prompts.yaml)",
    )
    rp.add_argument(
        "--proxy",
        default=None,
        metavar="URL",
        help="HTTP proxy URL (e.g. http://127.0.0.1:8080). Requires --proxy-ca. "
        "Mutually exclusive with --insecure-local.",
    )
    rp.add_argument(
        "--proxy-ca",
        default=None,
        metavar="PATH",
        help="CA cert PEM for proxy TLS verification. Required with --proxy.",
    )

    return parser


def _merge(cli_val, file_val, default):
    """Return CLI value if explicitly set, else config file value, else default."""
    if cli_val is not None:
        return cli_val
    if file_val is not None:
        return file_val
    return default


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    match args.command:
        case "gen-certs":
            out_dir = Path(args.out_dir)
            certs_mod.write_certs(out_dir)
            print(f"Certs written to {out_dir}/")

        case "serve":
            cfg = ServerConfig(
                host=args.host,
                port=args.port,
                cert_file=args.cert_file,
                key_file=args.key_file,
            )
            server_mod.run_server(cfg)

        case "run":
            file_cfg: dict = {}
            if args.config:
                file_cfg = load_config_file(args.config)

            def _f(key):
                return file_cfg.get(key)

            # Resolve all parameters (CLI beats file beats default)
            employees: int = _merge(args.employees, _f("employees"), _DEFAULTS["employees"])

            # Rate: --rate (aggregate) or --rate-per-employee (per-employee); mutually exclusive
            if args.rate is not None:
                rate_per_employee = args.rate / employees
            elif args.rate_per_employee is not None:
                rate_per_employee = args.rate_per_employee
            elif _f("rate") is not None:
                rate_per_employee = _f("rate") / employees
            elif _f("rate_per_employee") is not None:
                rate_per_employee = _f("rate_per_employee")
            else:
                rate_per_employee = _DEFAULTS["rate_per_employee"]

            duration: float = _merge(args.duration, _f("duration"), _DEFAULTS["duration"])
            total_requests: int | None = _merge(
                args.total_requests, _f("total_requests"), _DEFAULTS["total_requests"]
            )
            violation_ratio: float = _merge(
                args.violation_ratio, _f("violation_ratio"), _DEFAULTS["violation_ratio"]
            )
            violation_weights: dict[str, float] | None = _f("violation_categories")
            insecure_local: bool = args.insecure_local or _f("insecure_local") or False
            server_host: str = _merge(args.server_host, _f("server_host"), _DEFAULTS["server_host"])
            server_port: int = _merge(args.server_port, _f("server_port"), _DEFAULTS["server_port"])
            ca_cert: str = _merge(args.ca_cert, _f("ca_cert"), _DEFAULTS["ca_cert"])
            log_file: str | None = _merge(args.log_file, _f("log_file"), _DEFAULTS["log_file"])
            corpus_path: str = _merge(args.corpus, _f("corpus"), _DEFAULTS["corpus"])
            proxy: str | None = _merge(args.proxy, _f("proxy"), _DEFAULTS["proxy"])
            proxy_ca: str | None = _merge(args.proxy_ca, _f("proxy_ca"), _DEFAULTS["proxy_ca"])

            if insecure_local and (proxy or proxy_ca):
                parser.error("--insecure-local is mutually exclusive with --proxy / --proxy-ca")
            if bool(proxy) != bool(proxy_ca):
                parser.error("--proxy and --proxy-ca must both be specified together")

            cfg = RunConfig(
                employees=employees,
                rate_per_employee=rate_per_employee,
                duration=duration,
                total_requests=total_requests,
                violation_ratio=violation_ratio,
                violation_weights=violation_weights,
                insecure_local=insecure_local,
                server_host=server_host,
                server_port=server_port,
                ca_cert=ca_cert,
                log_file=log_file,
                corpus_path=corpus_path,
                proxy=proxy,
                proxy_ca=proxy_ca,
            )
            data = corpus_mod.load_corpus(cfg.corpus_path)

            async def _run() -> None:
                async with AsyncJSONLWriter(cfg.log_file) as writer:
                    await employee_mod.run_employees(cfg, data, writer)

            asyncio.run(_run())
