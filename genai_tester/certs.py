from __future__ import annotations

import contextlib
import ipaddress
import os
import ssl
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_DIR = Path("certs")

SANS_DNS: list[str] = [
    # Web-interface targets matched by nbnbnb.C parsers (cpcode version 5)
    "chatgpt.com",
    "files.oaiusercontent.com",             # chatgpt file upload parser
    "claude.ai",
    "copilot.microsoft.com",
    "copilot.com",
    "www.copilot.com",
    "substrate.office.com",                 # teams_copilot_parser
    "oncprealp-my.sharepoint.com",          # teams_copilot_upload_parser
    "chat.deepseek.com",                    # deepseek file parser
    "duck.ai",                              # duck file parser
    "gemini.google.com",                    # gemini file parser
    "push.clients6.google.com",             # gemini file upload parser
    "clients6.google.com",
    "grok.com",                             # grok file parser
    "router.huggingface.co",               # huggingface parsers
    "api.lovable.dev",                      # lovable file parser
    "perplexity.ai",                        # perplexity file parser
    "ppl-ai-file-upload.s3.amazonaws.com",  # perplexity file upload parser
    "m365.cloud.microsoft",
    "teams.cloud.microsoft",
    "outlook.office.com",
    "localhost",
]
SANS_IP: list[str] = ["127.0.0.1"]

_CA_SUBJECT = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "GenAI-Tester-CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lab"),
    ]
)
_SERVER_SUBJECT = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "GenAI-Tester-Server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lab"),
    ]
)


def generate_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.now(tz=UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_CA_SUBJECT)
        .issuer_name(_CA_SUBJECT)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def generate_server_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=UTC)
    san = x509.SubjectAlternativeName(
        [x509.DNSName(h) for h in SANS_DNS]
        + [x509.IPAddress(ipaddress.IPv4Address(ip)) for ip in SANS_IP]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(_SERVER_SUBJECT)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san, critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def write_certs(cert_dir: Path = CERT_DIR) -> None:
    files = [
        cert_dir / "ca.pem",
        cert_dir / "ca.key",
        cert_dir / "server.pem",
        cert_dir / "server.key",
    ]
    if all(f.exists() for f in files):
        return

    cert_dir.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = generate_ca()
    server_key, server_cert = generate_server_cert(ca_key, ca_cert)

    _write_pem(cert_dir / "ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(cert_dir / "ca.key", ca_key)
    _write_pem(cert_dir / "server.pem", server_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(cert_dir / "server.key", server_key)


def _write_pem(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    with contextlib.suppress(NotImplementedError):  # Windows doesn't support chmod
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def load_ca(cert_dir: Path = CERT_DIR) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Load the CA key and cert from disk for dynamic cert issuance."""
    ca_key: rsa.RSAPrivateKey = serialization.load_pem_private_key(  # type: ignore[assignment]
        (cert_dir / "ca.key").read_bytes(), password=None
    )
    ca_cert = x509.load_pem_x509_certificate((cert_dir / "ca.pem").read_bytes())
    return ca_key, ca_cert


def generate_hostname_cert(
    hostname: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Issue a certificate valid for exactly one hostname, signed by the lab CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    san = x509.SubjectAlternativeName([x509.DNSName(hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san, critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def load_ssl_context_server(cert_file: str, key_file: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


def load_ssl_context_client(ca_cert_path: str) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_cert_path)
