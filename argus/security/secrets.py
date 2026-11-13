"""Keep API keys out of everything Argus records or displays.

Error messages from HTTP libraries often embed the full request URL - and some
APIs (Shodan) take the key as a query parameter. Those errors are stored on the
investigation and shown in the UI, so every secret a module uses is registered
here and scrubbed from recorded text.
"""

from __future__ import annotations

REDACTED = "[REDACTED]"
MIN_SECRET_LENGTH = 8  # never redact trivially short strings (would mangle normal text)

_secrets: set[str] = set()


def register_secret(value: str | None) -> None:
    if value and len(value) >= MIN_SECRET_LENGTH:
        _secrets.add(value)


def redact(text: str) -> str:
    for secret in _secrets:
        if secret in text:
            text = text.replace(secret, REDACTED)
    return text
