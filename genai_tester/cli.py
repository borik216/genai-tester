from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from genai_tester import certs as certs_mod
from genai_tester import corpus as corpus_mod
from genai_tester import employee as employee_mod
from genai_tester import server as server_mod
from genai_tester.log import AsyncJSONLWriter
from genai_tester.models import RunConfig, ServerConfig


def parse_departments(raw: str, total_employees: int) -> dict[str, int]:
    if not raw:
        return {"default": total_employees}
    result: dict[str, int] = {}
    for part in raw.split(","):
        part = part.strip()
        if ":" not in part:
            print(f"error: department entry '{part}' must be in name:count format", file=sys.stderr)
            sys.exit(1)
        name, _, count_str = part.partition(":")
        try:
            count = int(count_str)
        except ValueError:
            print(f"error: count for department '{name}' is not an integer", file=sys.stderr)
            sys.exit(1)
        if count < 1:
            print(f"error: count for department '{name}' must be >= 1", file=sys.stderr)
            sys.exit(1)
        result[name.strip()] = count
    total = sum(result.values())
    if total != total_employees:
        print(
            f"error: department counts sum to {total} but --employees is {total_employees}",
            file=sys.stderr,
        )
        sys.exit(1)
    return result


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
    rp.add_argument("--employees", type=int, default=5, metavar="N")
    rp.add_argument(
        "--departments",
        default="",
        metavar="SPEC",
        help='Department spec, e.g. "engineering:3,hr:2" (must sum to --employees)',
    )
    rp.add_argument(
        "--rate-per-employee",
        type=float,
        default=1 / 60,
        metavar="RATE",
        help="Mean requests/sec per employee (default: 1/60)",
    )
    rp.add_argument(
        "--duration", type=float, default=300.0, metavar="SECS", help="Run duration (default: 300)"
    )
    rp.add_argument(
        "--violation-ratio",
        type=float,
        default=0.3,
        metavar="RATIO",
        help="Fraction of prompts that contain DLP violations (default: 0.3)",
    )
    rp.add_argument(
        "--insecure-local",
        action="store_true",
        help="Bypass gateway: connect directly to fake server, skip TLS verification",
    )
    rp.add_argument(
        "--server-host",
        default="localhost",
        metavar="HOST",
        help="Fake server host for --insecure-local (default: localhost)",
    )
    rp.add_argument(
        "--server-port",
        type=int,
        default=443,
        metavar="PORT",
        help="Fake server port for --insecure-local (default: 443)",
    )
    rp.add_argument(
        "--ca-cert",
        default="certs/ca.pem",
        metavar="PATH",
        help="CA cert to trust for gateway TLS (default: certs/ca.pem)",
    )
    rp.add_argument(
        "--log-file", default=None, metavar="PATH", help="JSONL output file (default: stdout)"
    )
    rp.add_argument(
        "--corpus",
        default="corpus/prompts.yaml",
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
            if args.insecure_local and (args.proxy or args.proxy_ca):
                parser.error("--insecure-local is mutually exclusive with --proxy / --proxy-ca")
            if bool(args.proxy) != bool(args.proxy_ca):
                parser.error("--proxy and --proxy-ca must both be specified together")
            depts = parse_departments(args.departments, args.employees)
            cfg = RunConfig(
                employees=args.employees,
                departments=depts,
                rate_per_employee=args.rate_per_employee,
                duration=args.duration,
                violation_ratio=args.violation_ratio,
                insecure_local=args.insecure_local,
                server_host=args.server_host,
                server_port=args.server_port,
                ca_cert=args.ca_cert,
                log_file=args.log_file,
                corpus_path=args.corpus,
                proxy=args.proxy,
                proxy_ca=args.proxy_ca,
            )
            data = corpus_mod.load_corpus(cfg.corpus_path)

            async def _run() -> None:
                async with AsyncJSONLWriter(cfg.log_file) as writer:
                    await employee_mod.run_employees(cfg, data, writer)

            asyncio.run(_run())
