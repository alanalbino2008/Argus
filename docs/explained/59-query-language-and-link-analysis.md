# 59 — The Argus Query Language and link analysis

## Why

A large investigation has thousands of entities. Clicking through them answers "what is this?"
but not the questions investigators actually ask:

- *Which remote-access hosts resolve to infrastructure outside the EU?*
- *How does this person's email connect to that server?*
- *Which entity, if it went away, would split this network in two?*

The Argus Query Language (AQL) answers these in milliseconds, against the graph already in memory.

## The language

### Filters
A selector is one or more terms. Terms next to each other must all hold (AND is implied).

| Form | Meaning | Example |
|---|---|---|
| `field:value` | equals, ignoring case; `*` and `?` are wildcards | `label:*acme*` |
| `field:*` | the field is present and not empty | `intel.kev:*` |
| `field=value`, `field!=value` | exact match / not equal | `http_status!=200` |
| `field~"regex"` | regular-expression search | `value~"^(vpn\|sso)"` |
| `field>n` `>=` `<` `<=` | numeric comparison | `confidence<0.8` |
| `word`, `"two words"` | text in the value or label | `"acme corp"` |
| `domain`, `ip`, `sub`… | a bare type name matches the type | `ip` |
| `AND` `OR` `NOT` `-term` `( )` | combine | `(email OR username) -sources:seed` |

**Fields**: `type value label id confidence depth degree seed source`, any metadata key
(dotted for nested ones: `geo.country`, `intel.kev`), and the link-analysis scores below.
A list matches when any element matches, so `sources:passive_dns` finds anything that source saw.

### Relation patterns
Join selectors with edges. Every step must hold, so only complete chains match:

```text
type:domain -[RESOLVES_TO]-> type:ip_address          a domain that resolves to an IP
ip <-[RESOLVES_TO]- sub                                IPs that subdomains resolve to
type:person -- type:organization                       any relation, either direction
sub -[RESOLVES_TO|SUBDOMAIN_OF]-> *                    either relation type
type:email -> domain <- sub -> ip                      four steps
```

The rows are the entities matched by the **last** step. The graph highlights every entity and
relation on a complete chain. The first 25 chains are listed so each one can be shown alone.

How it's evaluated: each step's candidates are found once. A backward pass keeps only the
candidates that can complete the rest of the pattern, and a forward pass keeps only the ones
reachable from a valid start. That is linear in the size of the graph for each step, so a pattern
never explodes into an enumeration of every possible chain.

### Shortest routes
```text
path from type:email to type:ip_address max 6
```
A breadth-first search from **all** sources at once (ignoring direction) finds the nearest
targets. Up to 25 routes, each the shortest to its target. `max` caps the hops (default 6, at most 12).

### Shaping results
```text
| sort pagerank desc     | sort confidence asc
| limit 20               | count             | group type
```

## Link analysis

`argus/intel/link_analysis.py` scores every entity. It is pure Python with no SciPy, and the
result is cached per graph version, so repeated queries cost nothing.

| Score | What it means | Investigative use |
|---|---|---|
| `pagerank` | influence: pointed at by important entities | the IP that actually hosts the key domains |
| `betweenness` | brokerage: on many shortest routes between others | the one email tying a company to a person |
| `community` | Louvain cluster number (largest first) | one estate, persona or shell network per cluster |
| `articulation` | removing it disconnects the graph | single points of failure, critical pivots |
| `key_score` | 0.4 × PageRank + 0.4 × betweenness + 0.2 × degree, each scaled to this graph | "who matters most here" |

Betweenness is exact up to 600 entities and estimated from 256 sampled sources above that
(`betweenness_sampled: true`). Seeds are fixed, so results are repeatable.

## In the interface

- **Search box** (`/` to focus): a plain name jumps to that entity. Anything with an operator,
  an arrow, `path from` or `*` runs as a query. **Esc** clears it.
- **Query tab**: the count, timing, routes or matched chains, and results. Click a row to select
  it, or a route to light up just that route. Before you type, it shows examples and the syntax.
- **Intelligence tab → Link analysis**: key entities, brokers, single points of failure and
  clusters. **Colour by cluster** recolours the graph, and clicking a cluster highlights it.

## API and CLI

```bash
curl -X POST "$ARGUS/api/investigation/$ID/query" -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' -d '{"query": "path from type:email to ip"}'
curl "$ARGUS/api/investigation/$ID/links" -H "Authorization: Bearer $KEY"
argus --query "type:vulnerability intel.kev:* | sort pagerank" --on inv_1a2b3c4d
argus --query "* | group type" --on graph-export.json --query-json
```

## Safety

Queries are read-only and bounded:

- at most 2,000 characters, 64 filters and 8 pattern steps;
- regular expressions are limited to 200 characters, with no nested repetition such as
  `(a+)+`, and test at most 2,000 characters of a value;
- at most 5,000 rows, 25 paths and 12 hops.

Stored graphs are analysed in a worker thread, so a heavy query never stalls the server. A
running scan's graph is read on the event loop, where the engine cannot change it mid-query.
Queries are scoped to the workspace like every other investigation endpoint (viewer role).

Tests: `tests/test_query.py`.
