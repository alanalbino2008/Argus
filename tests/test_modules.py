"""Unit tests for modules, heuristics, and engine behavior."""

from argus.cli.console import detect_target_type
from argus.core.events import Event, EventBus, EventType
from argus.core.models import EntityType
from argus.modules.infrastructure.http_fingerprint import HttpFingerprintModule


def test_detect_target_type():
    assert detect_target_type("8.8.8.8") == EntityType.IP_ADDRESS
    assert detect_target_type("2001:4860:4860::8888") == EntityType.IP_ADDRESS
    assert detect_target_type("admin@example.com") == EntityType.EMAIL
    assert detect_target_type("sub.domain.co.uk") == EntityType.DOMAIN
    assert detect_target_type("cool_hacker99") == EntityType.USERNAME


def test_http_fingerprint_security_headers_grading():
    mod = HttpFingerprintModule()
    # Check that security headers are correctly listed
    assert "strict-transport-security" in mod.SECURITY_HEADERS
    assert "content-security-policy" in mod.SECURITY_HEADERS


def test_event_bus_dispatch():
    bus = EventBus()
    received_events = []

    def sample_sync_handler(event: Event):
        received_events.append(event)

    bus.subscribe(EventType.SCAN_STARTED, sample_sync_handler)

    event = Event(
        type=EventType.SCAN_STARTED,
        investigation_id="inv_123",
        data={"target": "test.com"},
    )

    assert event.type in bus._subscribers
    assert sample_sync_handler in bus._subscribers[event.type]

    # Test safe invocation
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(bus._safe_invoke(sample_sync_handler, event))
    finally:
        loop.close()

    assert len(received_events) == 1
    assert received_events[0].investigation_id == "inv_123"
