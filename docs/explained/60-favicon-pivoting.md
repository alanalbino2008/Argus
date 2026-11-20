# 60 — Favicon pivoting

## The idea

A favicon is a small file most people never think about, which is exactly why it is a good
fingerprint. Organisations reuse the same icon across their sites. Appliances and web
applications ship a default one, such as a VPN login page or a CI server. Phishing kits copy the
brand's icon byte for byte. So two hosts serving the *same* icon usually have something in common.

Internet-scan engines index favicons by hash, so one icon can be searched across the whole internet:

| Engine | Search | Hash |
|---|---|---|
| Shodan | `http.favicon.hash:-568180311` | MurmurHash3 of the base64 text |
| FOFA | `icon_hash="-568180311"` | same |
| ZoomEye | `iconhash:"-568180311"` | same |
| Censys | `services.http.response.favicons.md5_hash:<md5>` | MD5 of the bytes |

## What Argus does

`argus/modules/infrastructure/favicon.py` runs on every domain and sub-domain in scope:

1. `GET https://host/favicon.ico`.
2. If that isn't an image, read the homepage and try up to three icons it declares with
   `<link rel="icon">`, `"shortcut icon"` or `"apple-touch-icon"` (relative links resolved, `data:`
   links ignored).
3. Plain HTTP is tried only if HTTPS could not be reached at all.
4. The bytes must *be* an image (ICO, PNG, GIF, JPEG, BMP, WebP or SVG, checked by their first
   bytes, not the `Content-Type` header). Many sites answer `/favicon.ico` with a 200 HTML
   "not found" page, which would otherwise give every such site the same bogus hash.
5. The icon becomes a node with value `favicon:<shodan hash>`. Entity IDs are derived from the
   value, so **every host serving the same icon links to the same node**, in this scan and in
   later ones.

The node holds the hashes (Shodan, MD5, SHA-256), the type and size, and the four searches. The
graph panel shows how many hosts here serve it and offers each search with a Copy button.

## The Shodan hash

Shodan computes `mmh3.hash(base64.encodebytes(icon))`: MurmurHash3 x86 32-bit, seed 0, as a
**signed** integer, over the base64 text **with a newline every 76 characters and at the end**.
Get either detail wrong and the hash matches nothing. `argus/intel/favicon.py` implements
MurmurHash3 in pure Python, and `tests/test_favicon.py` checks it against the published reference
vectors.

## Finding shared icons

```text
category:favicon degree>=2 <-[USES_TECH]- *        hosts that share an icon
category:favicon | sort degree desc                 the most widely shared icons
```

## Limits and safety

- **A lead, not proof.** Default icons (a framework's, a hosting panel's) are shared by unrelated
  sites, so the relation's confidence is 0.6. Check the hosts before treating them as one operator.
- **Active**: the module requests the icon from the target, so *passive only* scans skip it.
  Routed scans (Tor, VPN) send it through the route like every other request.
- **No outside searches**: Argus never queries Shodan, FOFA, ZoomEye or Censys with the hash. The
  analyst pastes the search in, so the engine sees the analyst's query, never the target's
  infrastructure.
- **SSRF-safe**: icon links are fetched through the shared client, so a page declaring
  `http://10.0.0.5/icon.png` is refused by the egress guard and the module carries on.
- Icons are capped at 256 KB and homepages at 512 KB. Third parties' assets (`out_of_scope`) are
  never contacted.

Tests: `tests/test_favicon.py`.
