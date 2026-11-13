"""Tests for the resilient HTTP client against a local aiohttp test server."""

import time

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from argus.core.http import HttpClient, _parse_retry_after


async def make_server(handler):
    app = web.Application()
    app.router.add_get("/{tail:.*}", handler)
    server = TestServer(app)
    await server.start_server()
    return server


async def test_retries_transient_5xx_then_succeeds():
    hits = {"n": 0}

    async def handler(request):
        hits["n"] += 1
        return web.Response(status=503 if hits["n"] < 3 else 200, text="ok")

    server = await make_server(handler)
    try:
        async with aiohttp.ClientSession() as s:
            client = HttpClient(s, allow_private=True, max_retries=3, backoff_base=0.01, min_host_interval=0)
            async with client.get(str(server.make_url("/x"))) as resp:
                assert resp.status == 200
                assert await resp.text() == "ok"
        assert hits["n"] == 3
        assert client.stats.retries == 2 and client.stats.requests == 3
    finally:
        await server.close()


async def test_gives_up_and_returns_last_response():
    async def handler(request):
        return web.Response(status=502)

    server = await make_server(handler)
    try:
        async with aiohttp.ClientSession() as s:
            client = HttpClient(s, allow_private=True, max_retries=2, backoff_base=0.01, min_host_interval=0)
            async with client.get(str(server.make_url("/"))) as resp:
                assert resp.status == 502
        assert client.stats.requests == 3
    finally:
        await server.close()


async def test_does_not_retry_client_errors():
    async def handler(request):
        return web.Response(status=404)

    server = await make_server(handler)
    try:
        async with aiohttp.ClientSession() as s:
            client = HttpClient(s, allow_private=True, max_retries=3, min_host_interval=0)
            async with client.get(str(server.make_url("/"))) as resp:
                assert resp.status == 404
        assert client.stats.requests == 1 and client.stats.retries == 0
    finally:
        await server.close()


async def test_honours_retry_after_on_429():
    hits = {"n": 0}

    async def handler(request):
        hits["n"] += 1
        if hits["n"] == 1:
            return web.Response(status=429, headers={"Retry-After": "1"})
        return web.Response(status=200)

    server = await make_server(handler)
    try:
        async with aiohttp.ClientSession() as s:
            client = HttpClient(s, allow_private=True, max_retries=2, min_host_interval=0)
            t0 = time.monotonic()
            async with client.get(str(server.make_url("/"))) as resp:
                assert resp.status == 200
            assert time.monotonic() - t0 >= 0.9
        assert client.stats.throttled == 1
    finally:
        await server.close()


async def test_per_host_rate_limit_spaces_requests():
    async def handler(request):
        return web.Response(status=200)

    server = await make_server(handler)
    try:
        async with aiohttp.ClientSession() as s:
            client = HttpClient(s, allow_private=True, min_host_interval=0.1)
            t0 = time.monotonic()
            for _ in range(5):
                async with client.get(str(server.make_url("/"))) as resp:
                    assert resp.status == 200
            assert time.monotonic() - t0 >= 0.39
    finally:
        await server.close()


async def test_connection_errors_are_retried_then_raised():
    async with aiohttp.ClientSession() as s:
        client = HttpClient(s, allow_private=True, max_retries=1, backoff_base=0.01, min_host_interval=0)
        with pytest.raises(aiohttp.ClientConnectionError):
            async with client.get("http://127.0.0.1:1/"):
                pass
    assert client.stats.retries == 1 and client.stats.failures == 1


def test_parse_retry_after():
    assert _parse_retry_after("5") == 5.0
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("garbage") is None
    assert _parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0


async def test_non_retryable_errors_are_counted():
    async with aiohttp.ClientSession() as s:
        client = HttpClient(s, allow_private=True, max_retries=3, min_host_interval=0)
        with pytest.raises(aiohttp.InvalidURL):
            async with client.get("http://"):
                pass
    assert client.stats.failures == 1 and client.stats.retries == 0
