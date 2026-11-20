"""Censys Platform searches (CenQL) for the fingerprints Argus records, in one place.

Censys retired its Search 2.0 query syntax (``services.jarm.fingerprint: ...``) for the Platform's
Censys Query Language. These are exact-match host searches (``field = "value"``, which CenQL
documents as a case-sensitive exact match):

* certificate SHA-256 ``host.services.cert.fingerprint_sha256`` and favicon SHA-256
  ``host.services.endpoints.http.favicons.hash_sha256`` are listed verbatim in Censys's CenQL
  documentation (its ``sha256`` alias table);
* ``host.services.jarm.fingerprint`` and ``host.services.ssh.hassh_fingerprint`` follow the Platform
  API's published data schema (``Service.jarm.fingerprint``, ``Service.ssh.hassh_fingerprint``).

If Censys renames a field, this is the only file to change.
"""

from __future__ import annotations


def _exact(field: str, value: str) -> str:
    return f'{field} = "{value}"'


def favicon(sha256: str) -> str:
    return _exact("host.services.endpoints.http.favicons.hash_sha256", sha256)


def certificate(sha256: str) -> str:
    return _exact("host.services.cert.fingerprint_sha256", sha256)


def jarm(fingerprint: str) -> str:
    return _exact("host.services.jarm.fingerprint", fingerprint)


def hassh(fingerprint: str) -> str:
    return _exact("host.services.ssh.hassh_fingerprint", fingerprint)
