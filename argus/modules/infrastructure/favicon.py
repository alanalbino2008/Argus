"""Favicon pivoting: fingerprint a site's icon and link every host that serves the same one.

For each domain or sub-domain the module fetches ``/favicon.ico``, or the icon the homepage
declares with ``<link rel="icon">``. It checks that the bytes really are an image (not an HTML
"soft 404"), and records a **favicon node** keyed by its Shodan hash:

* every host serving the same icon links to the **same node**, so shared icons show up in the
  graph as a hub. That is an operator's whole estate, or every instance of one product;
* the node carries ready-made searches for Shodan, FOFA, ZoomEye and Censys, to find the
  *rest* of the internet serving that icon (analyst-driven: Argus does not run them).

A shared favicon is a lead, not proof: default framework and appliance icons are shared by
unrelated sites. The relation's confidence reflects that.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlsplit

import aiohttp

from argus.core.http import HttpClient, read_limited
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.intel.favicon import MAX_ICON_BYTES, Fingerprint, fingerprint, icon_links
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.favicon")

MAX_HOMEPAGE_BYTES = 512 * 1024
MAX_DECLARED_ICONS = 3
SHARED_ICON_CONFIDENCE = 0.6  # the same icon suggests, but does not prove, the same operator


class FaviconPivotModule(BaseModule):
    name = "favicon_pivot"
    description = "Favicon fingerprinting (Shodan/FOFA/ZoomEye/Censys hashes) linking hosts that share an icon"
    supported_entity_types = [EntityType.DOMAIN, EntityType.SUBDOMAIN]
    attack_techniques = ("T1594", "T1596.005")  # search victim-owned websites; scan databases
    active = True  # requests the icon from the target's own web server

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        host = entity.value.strip().lower().rstrip(".")
        if not host or entity.metadata.get("out_of_scope"):
            return
        found = await self._find_icon(session, host, config)
        if found is None:
            return
        url, print_ = found
        icon = Entity.create(
            EntityType.GENERIC,
            f"favicon:{print_.mmh3}",
            label=f"Favicon {print_.mmh3}",
            source_module=self.name,
            depth=entity.depth + 1,
            metadata={**print_.as_metadata(), "pivot_hub": True},
        )
        yield icon
        yield Relation.create(
            entity.id,
            icon.id,
            RelationType.USES_TECH,
            label="serves favicon",
            metadata={"url": url},
            confidence=SHARED_ICON_CONFIDENCE,
        )

    async def _find_icon(self, session: HttpClient, host: str, config: ScanConfig) -> tuple[str, Fingerprint] | None:
        timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
        for scheme in ("https", "http"):
            base = f"{scheme}://{host}/"
            reached, result = await self._fetch_icon(session, urljoin(base, "/favicon.ico"), timeout)
            if result:
                return result
            homepage = await self._fetch_text(session, base, timeout)
            if homepage is not None:
                reached = True
                final_base, html = homepage
                for href in icon_links(html)[:MAX_DECLARED_ICONS]:
                    target = urljoin(final_base, href)
                    if urlsplit(target).scheme not in ("http", "https"):
                        continue
                    _, result = await self._fetch_icon(session, target, timeout)
                    if result:
                        return result
            if reached:
                return None  # the site answered over HTTPS; plain HTTP would not add anything
        return None

    async def _fetch_icon(
        self, session: HttpClient, url: str, timeout: aiohttp.ClientTimeout
    ) -> tuple[bool, tuple[str, Fingerprint] | None]:
        """(the server answered at all, the icon's fingerprint if it is a real image)."""
        try:
            async with session.get(url, timeout=timeout, allow_redirects=True, ssl=False) as resp:
                if resp.status != 200:
                    return True, None
                data = await read_limited(resp, MAX_ICON_BYTES)
                if not data:
                    return True, None
                print_ = fingerprint(data)
                return True, (str(resp.url), print_) if print_ else None
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:  # OSError: blocked private address
            logger.debug("favicon fetch failed for %s: %r", url, exc)
            return False, None

    async def _fetch_text(
        self, session: HttpClient, url: str, timeout: aiohttp.ClientTimeout
    ) -> tuple[str, str] | None:
        try:
            async with session.get(url, timeout=timeout, allow_redirects=True, ssl=False) as resp:
                if resp.status >= 400 or "html" not in resp.headers.get("Content-Type", "").lower():
                    return None
                body = await read_limited(resp, MAX_HOMEPAGE_BYTES)
                if body is None:
                    return None
                return str(resp.url), body.decode("utf-8", errors="replace")
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:  # OSError: blocked private address
            logger.debug("homepage fetch failed for %s: %r", url, exc)
            return None
