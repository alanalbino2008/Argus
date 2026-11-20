"""Phase 62: JARM, HASSH-server and certificate pivot searches."""

from __future__ import annotations

import asyncio
import hashlib
import os
import ssl
import struct

import pytest

from argus.core.models import Entity, EntityType, RelationType, ScanConfig
from argus.intel import jarm, ssh_fingerprint
from argus.modules import get_module_catalog
from argus.modules.infrastructure import server_fingerprints
from argus.modules.infrastructure.server_fingerprints import JarmModule, SshFingerprintModule
from argus.security.network import BlockedDestinationError

LOCAL = ScanConfig(target="x", target_type=EntityType.DOMAIN, allow_private_targets=True, timeout_seconds=5)
PUBLIC = ScanConfig(target="x", target_type=EntityType.DOMAIN, timeout_seconds=5)

# Ten parsed answers and their JARM, as computed by the independent pyjarm hasher.
ANSWERS = [
    "c02f|0303|h2|ff01-0000-0001-000b-0023-0010-0017", "c030|0303|http/1.1|ff01-0000-0001-0023-0010-0017", "|||",
    "1301|0303||002b-0033", "0035|0302||ff01-0000", "|||", "1302|0303||002b-0033", "|||", "c02c|0303||0000-ff01",
    "cca8|0303|h2|0017-0010",
]  # fmt: skip
ANSWERS_JARM = "29d2ad00041d08c00042d00028d3fd5dd001f7b765d0c5525a0c12d31f7a8f"


# ----------------------------------------------------------------------------- JARM
def test_jarm_hash_matches_reference_vector():
    assert jarm.jarm_hash(ANSWERS) == ANSWERS_JARM
    assert jarm.jarm_hash([jarm.FAILED] * 10) == jarm.ZERO_JARM
    assert len(ANSWERS_JARM) == 62


def test_probe_order_and_cipher_munging():
    assert len(jarm.PROBES) == 10
    items = [bytes([i]) for i in range(1, 6)]  # odd length
    assert jarm._mung(items, "MIDDLE_OUT") == [bytes([i]) for i in (3, 4, 2, 5, 1)]
    assert jarm._mung(items, "BOTTOM_HALF") == [bytes([i]) for i in (4, 5)]
    assert jarm._mung(items, "TOP_HALF") == [bytes([i]) for i in (3, 2, 1)]
    even = [bytes([i]) for i in range(1, 5)]
    assert jarm._mung(even, "MIDDLE_OUT") == [bytes([i]) for i in (3, 2, 4, 1)]


@pytest.mark.parametrize("probe", jarm.PROBES)
def test_client_hello_is_well_formed(probe):
    hello = jarm.client_hello("example.com", probe)
    assert hello[0] == 0x16 and struct.unpack(">H", hello[3:5])[0] == len(hello) - 5  # one TLS record
    assert hello[5] == 1 and int.from_bytes(hello[6:9], "big") == len(hello) - 9  # a ClientHello
    assert b"example.com" in hello  # SNI
    assert (b"\x00\x2b" in hello[-40:]) == (probe.version == "TLS_1.3" or probe.support == "1.2_SUPPORT")


def test_server_hello_parsing():
    session = os.urandom(32)
    extensions = b"\xff\x01\x00\x01\x00" + b"\x00\x10\x00\x05\x00\x03\x02h2" + b"\x00\x17\x00\x00"
    body = b"\x03\x03" + os.urandom(32) + bytes([len(session)]) + session + b"\xc0\x2f\x00"
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    assert jarm.parse_server_hello(record) == "c02f|0303|h2|ff01-0010-0017"
    assert jarm.parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x28") == jarm.FAILED  # an alert
    assert jarm.parse_server_hello(None) == jarm.FAILED
    assert jarm.parse_server_hello(b"HTTP/1.1 400 Bad Request\r\n") == jarm.FAILED


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    """A throwaway self-signed certificate for local TLS servers."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256())
    )  # fmt: skip
    folder = tmp_path_factory.mktemp("tls")
    crt, pem = folder / "crt.pem", folder / "key.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))  # fmt: skip
    return str(crt), str(pem)


async def _tls_server(certificate, *, maximum=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*certificate)
    if maximum is not None:
        context.maximum_version = maximum

    async def handle(reader, writer):
        try:
            await reader.read(1)
        except (ssl.SSLError, OSError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    return server, server.sockets[0].getsockname()[1]


async def test_jarm_of_live_servers_is_stable_and_discriminating(certificate):
    modern, modern_port = await _tls_server(certificate)
    legacy, legacy_port = await _tls_server(certificate, maximum=ssl.TLSVersion.TLSv1_2)
    async with modern, legacy:
        first = await jarm.fingerprint("127.0.0.1", modern_port, "localhost", timeout=5)
        again = await jarm.fingerprint("127.0.0.1", modern_port, "localhost", timeout=5)
        older = await jarm.fingerprint("127.0.0.1", legacy_port, "localhost", timeout=5)
    assert first["jarm"] == again["jarm"] != jarm.ZERO_JARM and first["answered"] > 0
    assert older["jarm"] not in (first["jarm"], jarm.ZERO_JARM)  # a different configuration, a different JARM


async def test_jarm_of_a_closed_port_is_zero():
    sock_server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = sock_server.sockets[0].getsockname()[1]
    sock_server.close()
    await sock_server.wait_closed()
    assert (await jarm.fingerprint("127.0.0.1", port, "x", timeout=2)) == {"jarm": jarm.ZERO_JARM, "answered": 0}


async def test_jarm_module_links_a_shared_hub(certificate):
    server, port = await _tls_server(certificate)
    module = JarmModule()
    port_entity = Entity.create(EntityType.PORT, f"127.0.0.1:{port}", metadata={"port_number": port, "ip": "127.0.0.1"})
    async with server:
        server_fingerprints.TLS_PORTS = server_fingerprints.TLS_PORTS | {port}
        try:
            assert module.can_handle(port_entity)
            items = [i async for i in module.run(port_entity, None, LOCAL)]
        finally:
            server_fingerprints.TLS_PORTS = server_fingerprints.TLS_PORTS - {port}
    hub, relation = items
    assert hub.value.startswith("jarm:") and hub.metadata["category"] == "jarm" and hub.metadata["pivot_hub"]
    digest = hub.metadata["jarm"]
    assert hub.metadata["search_queries"] == {
        "shodan": f"ssl.jarm:{digest}",
        "censys": f"services.jarm.fingerprint: {digest}",
    }
    assert relation.type == RelationType.USES_TECH and relation.confidence == 0.5


def test_jarm_module_scope():
    module = JarmModule()
    assert module.can_handle(Entity.create(EntityType.DOMAIN, "example.com"))
    assert module.can_handle(Entity.create(EntityType.PORT, "192.0.2.1:8443", metadata={"port_number": 8443}))
    assert not module.can_handle(Entity.create(EntityType.PORT, "192.0.2.1:80", metadata={"port_number": 80}))
    assert not module.can_handle(Entity.create(EntityType.DOMAIN, "impostor.example", metadata={"out_of_scope": True}))


async def test_private_addresses_are_never_contacted(monkeypatch):
    async def refuse(host, port):
        raise BlockedDestinationError("private")

    async def never(*args, **kwargs):
        raise AssertionError("connected to a private address")

    monkeypatch.setattr(server_fingerprints, "resolve_public", refuse)
    monkeypatch.setattr(jarm, "fingerprint", never)
    monkeypatch.setattr(ssh_fingerprint, "fingerprint", never)
    domain = Entity.create(EntityType.DOMAIN, "internal.example")
    ssh_port = Entity.create(EntityType.PORT, "10.0.0.5:22", metadata={"port_number": 22, "ip": "10.0.0.5"})
    assert [i async for i in JarmModule().run(domain, None, PUBLIC)] == []
    assert [i async for i in SshFingerprintModule().run(ssh_port, None, PUBLIC)] == []


# ----------------------------------------------------------------------------- SSH
KEX = ["curve25519-sha256", "diffie-hellman-group14-sha256"]
LISTS = [KEX, ["ssh-ed25519", "rsa-sha2-512"], ["aes128-ctr"], ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
         ["hmac-sha2-256"], ["umac-128-etm@openssh.com", "hmac-sha2-512"], ["none"], ["none", "zlib@openssh.com"], [], []]  # fmt: skip
EXPECTED_ALGORITHMS = (
    "curve25519-sha256,diffie-hellman-group14-sha256;chacha20-poly1305@openssh.com,aes256-gcm@openssh.com;"
    "umac-128-etm@openssh.com,hmac-sha2-512;none,zlib@openssh.com"
)


def _kexinit_packet() -> bytes:
    payload = b"\x14" + os.urandom(16)
    for names in LISTS:
        raw = ",".join(names).encode()
        payload += struct.pack(">I", len(raw)) + raw
    payload += b"\x00" + b"\x00\x00\x00\x00"
    padding = 8 - (len(payload) + 5) % 8 + 8
    body = bytes([padding]) + payload + b"\x00" * padding
    return struct.pack(">I", len(body)) + body


def test_kexinit_parsing_and_hassh():
    lists = ssh_fingerprint.parse_kexinit(_kexinit_packet()[5:])
    assert lists["kex_algorithms"] == KEX and lists["languages_server_to_client"] == []
    digest, algorithms = ssh_fingerprint.hassh_server(lists)
    assert algorithms == EXPECTED_ALGORITHMS
    assert digest == hashlib.md5(EXPECTED_ALGORITHMS.encode(), usedforsecurity=False).hexdigest()
    with pytest.raises(ssh_fingerprint.SshProtocolError):
        ssh_fingerprint.parse_kexinit(b"\x15rest")


def test_banner_parsing():
    info = ssh_fingerprint.parse_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    assert info == {"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "protocol": "2.0",
                    "software": "OpenSSH_8.9p1", "comments": "Ubuntu-3ubuntu0.6"}  # fmt: skip


async def _ssh_server(script):
    async def handle(reader, writer):
        try:
            await script(reader, writer)
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _good_ssh(reader, writer):
    writer.write(b"A friendly pre-banner line\r\nSSH-2.0-OpenSSH_9.6 FreeBSD-20240104\r\n")
    client = await reader.readline()
    assert client.startswith(b"SSH-2.0-")
    writer.write(_kexinit_packet())
    await writer.drain()
    await reader.read(1)


async def test_ssh_fingerprint_of_a_live_server():
    server, port = await _ssh_server(_good_ssh)
    async with server:
        info = await ssh_fingerprint.fingerprint("127.0.0.1", port, timeout=5)
    assert info["software"] == "OpenSSH_9.6" and info["hassh_server_algorithms"] == EXPECTED_ALGORITHMS
    assert info["host_key_algorithms"] == ["ssh-ed25519", "rsa-sha2-512"]


async def test_non_ssh_services_are_rejected():
    async def http(reader, writer):
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()

    server, port = await _ssh_server(http)
    async with server:
        with pytest.raises(ssh_fingerprint.SshProtocolError):
            await ssh_fingerprint.fingerprint("127.0.0.1", port, timeout=3)


async def test_ssh_module_yields_hub_and_software():
    server, port = await _ssh_server(_good_ssh)
    entity = Entity.create(EntityType.PORT, f"127.0.0.1:{port}", metadata={"port_number": port, "ip": "127.0.0.1",
                                                                         "service_guess": "SSH"})  # fmt: skip
    module = SshFingerprintModule()
    assert module.can_handle(entity)
    async with server:
        items = [i async for i in module.run(entity, None, LOCAL)]
    hub, link, software, runs = items
    digest = hashlib.md5(EXPECTED_ALGORITHMS.encode(), usedforsecurity=False).hexdigest()
    assert hub.value == f"hassh:{digest}" and hub.metadata["search_queries"] == {"shodan": f"ssh.hassh:{digest}"}
    assert link.metadata["banner"] == "SSH-2.0-OpenSSH_9.6 FreeBSD-20240104"
    assert software.type == EntityType.TECHNOLOGY and software.value == "OpenSSH 9.6"
    assert runs.target_id == software.id


def test_ssh_module_scope():
    module = SshFingerprintModule()
    assert module.can_handle(Entity.create(EntityType.PORT, "192.0.2.1:22", metadata={"port_number": 22}))
    assert module.can_handle(Entity.create(EntityType.PORT, "192.0.2.1:2200", metadata={"port_number": 2200,
                                                                                       "service_guess": "SSH"}))  # fmt: skip
    assert not module.can_handle(Entity.create(EntityType.PORT, "192.0.2.1:443", metadata={"port_number": 443}))
    assert not module.can_handle(Entity.create(EntityType.DOMAIN, "example.com"))


def test_registered_as_active_direct_modules():
    catalog = get_module_catalog()
    for name in ("jarm", "ssh_fingerprint"):
        assert catalog[name].active and catalog[name].direct_connections


def test_certificates_carry_pivot_searches():
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from argus.modules.infrastructure.tls_analyzer import parse_certificate

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256())
    )  # fmt: skip
    info = parse_certificate(cert.public_bytes(serialization.Encoding.DER))
    assert info["sha1_fingerprint"] == cert.fingerprint(hashes.SHA1()).hex()  # noqa: S303 - an identifier
