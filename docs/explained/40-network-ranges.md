# 40 — Network Ranges (Plain-English Guide)

> Purpose: explain how Argus finds who owns the internet addresses behind a target, and the other
> addresses they run. Useful for questions like:
> * "this company's server is at one address: what else do they run?"
> * "does this website really belong to the company, or to a hosting firm?"
> * "does Argus probe whole blocks of addresses?"

## 1. Why this matters

Every computer on the internet has an address, and addresses are handed out in **blocks**.

* **Companies with their own network.** A company that runs its own network holds whole blocks,
  announced to the rest of the internet under its own network number (an *autonomous system*,
  or ASN). Finding those blocks maps everything the company runs online: offices, data centres,
  forgotten servers.
* **Sites on a provider.** Most websites live on a cloud or hosting provider's addresses instead,
  shared with thousands of strangers. It matters to know which is which: a provider's block says
  nothing about the company, and treating it as the company's would point at innocent
  neighbours.

## 2. Where the information comes from

Only from the official internet registries, which record who holds which addresses:

* **RDAP**: the modern registry lookup, run by the five regional registries (Europe, the
  Americas, Asia-Pacific, Africa, Latin America);
* **RIPEstat**: the routing information published by RIPE NCC, showing which network announces
  each block.

Both are free and public. **The target is never contacted.**

## 3. What it finds

| Starting from | What Argus records |
|---|---|
| **An address** | the block it belongs to, who it is registered to, the country, the registry, the abuse contact, and the network announcing it |
| **A network (ASN)** | who holds it, and every block it announces (IPv4 and IPv6), with the number of addresses |
| **A company name** | networks registered in the company's name, found by comparing names word by word with legal forms such as "Ltd" ignored. Each match is marked *likely, to be confirmed*, because two companies can have similar names |

**Cloud and hosting providers** (Amazon, Cloudflare, Google, Microsoft, OVH, Hetzner and
dozens more) are recognised:

* their addresses are marked **shared hosting**;
* their networks' blocks are **not listed**: they belong to the providers' many customers.

## 4. Listed, never scanned

Argus lists the blocks but doesn't probe them. Probing a whole block would touch every computer
on it, including ones that have nothing to do with the investigation, and could be unlawful
without permission. Investigators with permission to test a company's systems can choose
addresses from the list and scan those deliberately.

## 5. In the playbooks

* **Company due diligence** looks for networks registered in the company's name, and lists
  their blocks.
* **Website background** shows who owns each address the website uses. On a provider, it says so
  plainly; on a company's own block, it says whose block it is.

## 6. In the graph

* Clicking an address shows an **"Address block"** panel: the block, who it is registered to,
  the network announcing it, the country, the registry and the abuse contact.
* Clicking a network shows a **"Network"** panel: its holder, how many blocks and addresses it
  has, and the full list. A network found by matching the company's name carries a reminder to
  confirm it.

## 7. What a reviewer can check

* `argus/modules/infrastructure/network_ranges.py`:
  * reading registry answers (`rdap_network`);
  * recognising providers (`is_provider`);
  * the lookups for addresses, networks and companies.
* `argus/intel/playbooks.py`: the playbooks and their findings.
* `argus/web/js/views/graphview.js`: the "Address block" and "Network" panels.
* `tests/test_networks.py`:
  * reading registry answers;
  * providers recognised;
  * an address's block and owner, with only the registries asked;
  * private addresses never looked up;
  * a company's ranges listed but a provider's not;
  * a company name matching only its own networks;
  * the playbook findings.
