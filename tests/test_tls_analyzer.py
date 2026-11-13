"""TLS analyzer: certificate parsing and a live handshake against a local TLS server."""

import asyncio
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, ScanConfig
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer
from argus.modules.infrastructure.tls_analyzer import TlsAnalyzerModule, parse_certificate

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def make_cert(cn="localhost", sans=("www.localhost", "api.localhost"), days=(-30, 60)):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Argus Test CA")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0xA1B2C3)
        .not_valid_before(NOW + timedelta(days=days[0]))
        .not_valid_after(NOW + timedelta(days=days[1]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def test_parse_certificate_extracts_investigator_facts():
    cert, _ = make_cert()
    info = parse_certificate(cert.public_bytes(serialization.Encoding.DER), now=NOW)
    assert info["subject_cn"] == "localhost"
    assert info["issuer"] == "Argus Test CA"
    assert info["sans"] == ["www.localhost", "api.localhost"]
    assert info["self_signed"] is True
    assert info["expired"] is False and info["days_remaining"] == 60
    assert info["public_key"] == "EC-secp256r1" and info["signature_hash"] == "sha256"
    assert info["serial"] == "a1b2c3" and len(info["sha256_fingerprint"]) == 64


def test_expired_certificate_detected():
    cert, _ = make_cert(days=(-400, -5))
    info = parse_certificate(cert.public_bytes(serialization.Encoding.DER), now=NOW)
    assert info["expired"] is True and info["days_remaining"] < 0


@pytest.fixture
async def tls_server(tmp_path):
    """A real TLS listener on 127.0.0.1 presenting a self-signed certificate."""
    cert, key = make_cert(days=(-1, 365 * 20))  # valid relative to "now" in the module
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")

    async def handle(reader, writer):
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    yield server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()


async def test_live_handshake_yields_certificate_and_san_subdomains(tls_server):
    module = TlsAnalyzerModule()
    module.port = tls_server
    config = ScanConfig(target="localhost", target_type=EntityType.DOMAIN, max_depth=1, allow_private_targets=True)
    engine = ArgusEngine(config, bus=EventBus(), modules={"tls_analyzer": module})
    graph = await engine.start()

    certs = [e for e in graph.get_all_entities() if e.type == EntityType.CERTIFICATE]
    subs = sorted(e.value for e in graph.get_all_entities() if e.type == EntityType.SUBDOMAIN)
    assert len(certs) == 1, engine.investigation.errors
    assert certs[0].metadata["issuer"] == "Argus Test CA"
    assert certs[0].metadata["self_signed"] is True
    assert certs[0].metadata["tls_version"].startswith("TLS")
    assert subs == ["api.localhost", "www.localhost"]


def test_analyzer_flags_bad_certificates():
    graph = IntelligenceGraph("t")
    graph.add_entity(Entity.create(EntityType.DOMAIN, "example.com"), is_seed=True)
    graph.add_entity(
        Entity.create(EntityType.CERTIFICATE, "c1", metadata={"expired": True, "observed_on": "a.example.com"})
    )
    graph.add_entity(
        Entity.create(EntityType.CERTIFICATE, "c2", metadata={"self_signed": True, "observed_on": "b.example.com"})
    )
    flags = GraphIntelligenceAnalyzer.analyze(graph)["risk_flags"]
    assert "Expired TLS certificate served on a.example.com" in flags
    assert "Self-signed TLS certificate served on b.example.com" in flags
