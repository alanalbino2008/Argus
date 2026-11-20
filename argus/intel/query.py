"""Argus Query Language (AQL): ask the investigation graph questions.

Filters (one selector, terms joined by AND unless OR is written)::

    type:ip_address country:RU
    type:subdomain AND NOT http_status:200
    (type:email OR type:username) confidence>=0.8
    value~"^vpn|^remote"            regex
    label:*acme*                    glob
    sources:passive_dns             any element of a list
    intel.kev:*                     the field exists (dotted metadata paths)
    pagerank>0.01 community:2       link-analysis scores

Patterns (selectors joined by edges; every step must hold)::

    type:domain -[RESOLVES_TO]-> type:ip_address country:US
    type:email <-[HAS_ACCOUNT|BELONGS_TO]- *
    type:person -- type:organization          any relation, either direction

Paths::

    path from type:email to type:ip_address max 6

Commands after ``|``::

    | sort pagerank desc | limit 20 | count | group type

Every query is read-only, bounded (terms, regex size, rows, paths, time) and runs in
memory on the graph already loaded for the investigation.
"""

from __future__ import annotations

import fnmatch
import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, RelationType
from argus.intel.link_analysis import analyze_links

MAX_QUERY_LENGTH = 2000
MAX_TERMS = 64
MAX_REGEX_LENGTH = 200
MAX_MATCH_TEXT = 2000  # regex and glob tests see at most this much of a value
DEFAULT_LIMIT = 500
MAX_LIMIT = 5000
MAX_PATHS = 25
DEFAULT_PATH_HOPS = 6
MAX_PATH_HOPS = 12
MAX_CHAIN_SEGMENTS = 8

TYPE_ALIASES = {
    "ip": "ip_address",
    "ipv4": "ip_address",
    "ipv6": "ip_address",
    "sub": "subdomain",
    "host": "subdomain",
    "user": "username",
    "handle": "username",
    "profile": "social_profile",
    "account": "social_profile",
    "org": "organization",
    "company": "organization",
    "cert": "certificate",
    "tech": "technology",
    "cve": "vulnerability",
    "vuln": "vulnerability",
    "wallet": "crypto_wallet",
    "dns": "dns_record",
}
ANALYTIC_FIELDS = {"pagerank", "betweenness", "community", "key_score", "articulation"}
CORE_FIELDS = {"type", "value", "label", "id", "confidence", "depth", "source", "module", "degree", "seed"}
KEYWORDS = {"AND", "OR", "NOT"}
COMMANDS = {"limit", "sort", "count", "group"}


class QueryError(ValueError):
    """A query that cannot be parsed or run; ``position`` points into the query text."""

    def __init__(self, message: str, position: int | None = None):
        super().__init__(message)
        self.position = position


# ----------------------------------------------------------------------------- tokens
@dataclass(frozen=True)
class Token:
    kind: str  # WORD STRING OP LPAREN RPAREN PIPE LBRACKET_OUT ... EOF
    text: str
    pos: int


_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<STRING>"(?:[^"\\]|\\.)*")
  | (?P<EDGE_IN_OPEN><-\[)          # <-[
  | (?P<EDGE_OUT_CLOSE>\]->)        # ]->
  | (?P<EDGE_CLOSE>\]-)             # ]-
  | (?P<EDGE_OPEN>-\[)              # -[
  | (?P<ARROW_OUT>->)
  | (?P<ARROW_IN><-)
  | (?P<ARROW_ANY>--)
  | (?P<OP>>=|<=|!=|[:=<>~])
  | (?P<LPAREN>\()
  | (?P<RPAREN>\))
  | (?P<PIPE>\|)
  | (?P<COMMA>,)
  | (?P<WORD>(?:(?!->|<-|--)[^\s()|:"=<>!~\[\],])+)
    """,
    re.VERBOSE,
)


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise QueryError(f"unexpected character {text[pos]!r}", pos)
        kind = m.lastgroup or ""
        value = m.group()
        if kind != "ws":
            if kind == "WORD" and value.startswith("-") and len(value) > 1 and (not tokens or tokens[-1].kind != "OP"):
                tokens.append(Token("WORD", "NOT", pos))  # -term is shorthand for NOT term
                tokens.append(Token("WORD", value[1:], pos + 1))
            elif kind == "STRING":
                tokens.append(Token("STRING", bytes(value[1:-1], "utf-8").decode("unicode_escape"), pos))
            else:
                tokens.append(Token(kind, value, pos))
        pos = m.end()
    tokens.append(Token("EOF", "", len(text)))
    return tokens


# ----------------------------------------------------------------------------- AST
Predicate = Callable[[Entity], bool]


@dataclass
class EdgeSpec:
    direction: str  # "out", "in" or "any"
    types: frozenset[str] = frozenset()  # empty: any relation type

    def describe(self) -> str:
        rel = "|".join(sorted(self.types)) if self.types else "*"
        return {"out": f"-[{rel}]->", "in": f"<-[{rel}]-", "any": f"-[{rel}]-"}[self.direction]


@dataclass
class Command:
    name: str
    args: list[str] = field(default_factory=list)


@dataclass
class ParsedQuery:
    kind: str  # "chain" or "path"
    selectors: list[Predicate]
    edges: list[EdgeSpec]
    commands: list[Command]
    max_hops: int = DEFAULT_PATH_HOPS
    uses_analytics: bool = False


# ----------------------------------------------------------------------------- parser
class _Parser:
    def __init__(self, text: str, context: _Context):
        self.tokens = tokenize(text)
        self.i = 0
        self.terms = 0
        self.ctx = context

    # helpers
    def peek(self, offset: int = 0) -> Token:
        return self.tokens[min(self.i + offset, len(self.tokens) - 1)]

    def advance(self) -> Token:
        tok = self.tokens[self.i]
        self.i = min(self.i + 1, len(self.tokens) - 1)
        return tok

    def expect(self, kind: str, what: str) -> Token:
        tok = self.peek()
        if tok.kind != kind:
            raise QueryError(f"expected {what}, found {tok.text or 'end of query'!r}", tok.pos)
        return self.advance()

    def is_word(self, *words: str) -> bool:
        tok = self.peek()
        return tok.kind == "WORD" and tok.text.lower() in {w.lower() for w in words}

    # grammar
    def parse(self) -> ParsedQuery:
        if self.is_word("path") and self.peek(1).kind == "WORD" and self.peek(1).text.lower() == "from":
            query = self.parse_path()
        else:
            query = self.parse_chain()
        query.commands = self.parse_commands()
        tok = self.peek()
        if tok.kind != "EOF":
            raise QueryError(f"unexpected {tok.text!r}", tok.pos)
        query.uses_analytics = self.ctx.uses_analytics
        return query

    def parse_path(self) -> ParsedQuery:
        self.advance()
        self.advance()  # path from
        source = self.parse_or(stop_words={"to"})
        if not self.is_word("to"):
            tok = self.peek()
            raise QueryError("a path query needs 'to': path from <selector> to <selector>", tok.pos)
        self.advance()
        target = self.parse_or(stop_words={"max"})
        hops = DEFAULT_PATH_HOPS
        if self.is_word("max"):
            self.advance()
            tok = self.expect("WORD", "a number of hops")
            if not tok.text.isdigit() or not 1 <= int(tok.text) <= MAX_PATH_HOPS:
                raise QueryError(f"max hops must be 1-{MAX_PATH_HOPS}", tok.pos)
            hops = int(tok.text)
        return ParsedQuery("path", [source, target], [], [], max_hops=hops)

    def parse_chain(self) -> ParsedQuery:
        selectors = [self.parse_or()]
        edges: list[EdgeSpec] = []
        while self.peek().kind in {"ARROW_OUT", "ARROW_IN", "ARROW_ANY", "EDGE_OPEN", "EDGE_IN_OPEN"}:
            if len(selectors) >= MAX_CHAIN_SEGMENTS:
                raise QueryError(f"a pattern can have at most {MAX_CHAIN_SEGMENTS} steps", self.peek().pos)
            edges.append(self.parse_edge())
            selectors.append(self.parse_or())
        return ParsedQuery("chain", selectors, edges, [])

    def parse_edge(self) -> EdgeSpec:
        tok = self.advance()
        if tok.kind == "ARROW_OUT":
            return EdgeSpec("out")
        if tok.kind == "ARROW_IN":
            return EdgeSpec("in")
        if tok.kind == "ARROW_ANY":
            return EdgeSpec("any")
        types = self.parse_relation_types()
        close = self.advance()
        if tok.kind == "EDGE_OPEN" and close.kind == "EDGE_OUT_CLOSE":
            return EdgeSpec("out", types)
        if tok.kind == "EDGE_OPEN" and close.kind == "EDGE_CLOSE":
            return EdgeSpec("any", types)
        if tok.kind == "EDGE_IN_OPEN" and close.kind == "EDGE_CLOSE":
            return EdgeSpec("in", types)
        raise QueryError("relation brackets must read -[TYPE]->, <-[TYPE]- or -[TYPE]-", close.pos)

    def parse_relation_types(self) -> frozenset[str]:
        known = {r.value for r in RelationType}
        types: set[str] = set()
        while True:
            tok = self.peek()
            if tok.kind == "WORD" and tok.text == "*":
                self.advance()
            elif tok.kind == "WORD":
                name = tok.text.upper()
                if name not in known:
                    raise QueryError(f"unknown relation {tok.text!r}; known: {', '.join(sorted(known))}", tok.pos)
                types.add(name)
                self.advance()
            else:
                raise QueryError("expected a relation type", tok.pos)
            if self.peek().kind in {"PIPE", "COMMA"}:
                self.advance()
                continue
            return frozenset(types)

    def at_selector_end(self, stop_words: set[str]) -> bool:
        tok = self.peek()
        if tok.kind in {"EOF", "PIPE", "RPAREN", "ARROW_OUT", "ARROW_IN", "ARROW_ANY", "EDGE_OPEN", "EDGE_IN_OPEN"}:
            return True
        return tok.kind == "WORD" and tok.text.lower() in stop_words

    def parse_or(self, stop_words: set[str] | None = None) -> Predicate:
        stop = stop_words or set()
        parts = [self.parse_and(stop)]
        while self.is_word("OR"):
            self.advance()
            parts.append(self.parse_and(stop))
        if len(parts) == 1:
            return parts[0]
        return lambda e: any(p(e) for p in parts)

    def parse_and(self, stop: set[str]) -> Predicate:
        if self.at_selector_end(stop):
            tok = self.peek()
            raise QueryError("expected a filter (for example type:domain, or * for anything)", tok.pos)
        parts = [self.parse_unary(stop)]
        while not self.at_selector_end(stop) and not self.is_word("OR"):
            if self.is_word("AND"):
                self.advance()
            parts.append(self.parse_unary(stop))
        if len(parts) == 1:
            return parts[0]
        return lambda e: all(p(e) for p in parts)

    def parse_unary(self, stop: set[str]) -> Predicate:
        if self.is_word("NOT"):
            self.advance()
            inner = self.parse_unary(stop)
            return lambda e: not inner(e)
        if self.peek().kind == "LPAREN":
            self.advance()
            inner = self.parse_or()
            self.expect("RPAREN", "')'")
            return inner
        return self.parse_term()

    def parse_term(self) -> Predicate:
        tok = self.advance()
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise QueryError(f"a query can have at most {MAX_TERMS} filters", tok.pos)
        if tok.kind not in {"WORD", "STRING"}:
            raise QueryError(f"unexpected {tok.text or 'end of query'!r}", tok.pos)
        if tok.kind == "WORD" and tok.text == "*":
            return lambda _e: True
        if self.peek().kind == "OP" and tok.kind == "WORD":
            op = self.advance()
            value_tok = self.advance()
            if value_tok.kind not in {"WORD", "STRING"}:
                raise QueryError(f"expected a value after {tok.text}{op.text}", value_tok.pos)
            return self.ctx.field_predicate(tok.text, op.text, value_tok.text, value_tok.pos)
        needle = tok.text.lower()
        if tok.kind == "WORD" and needle in TYPE_ALIASES.keys() | {t.value for t in EntityType}:
            entity_type = TYPE_ALIASES.get(needle, needle)  # a bare type name: "domain -> ip"
            return lambda e: e.type.value == entity_type
        return lambda e: needle in e.value.lower() or needle in e.label.lower()

    def parse_commands(self) -> list[Command]:
        commands: list[Command] = []
        while self.peek().kind == "PIPE":
            self.advance()
            tok = self.expect("WORD", "a command (limit, sort, count, group)")
            name = tok.text.lower()
            if name not in COMMANDS:
                raise QueryError(f"unknown command {tok.text!r}; use limit, sort, count or group", tok.pos)
            args: list[str] = []
            while self.peek().kind in {"WORD", "STRING"}:
                args.append(self.advance().text)
            commands.append(self.validate_command(Command(name, args), tok.pos))
        return commands

    def validate_command(self, cmd: Command, pos: int) -> Command:
        if cmd.name == "limit" and (len(cmd.args) != 1 or not cmd.args[0].isdigit() or int(cmd.args[0]) < 1):
            raise QueryError("limit needs a positive number: | limit 50", pos)
        if cmd.name in {"sort", "group"} and not 1 <= len(cmd.args) <= 2:
            raise QueryError(f"{cmd.name} needs a field: | {cmd.name} type", pos)
        if cmd.name == "sort" and len(cmd.args) == 2 and cmd.args[1].lower() not in {"asc", "desc"}:
            raise QueryError("sort order is asc or desc", pos)
        if cmd.name == "count" and cmd.args:
            raise QueryError("count takes no arguments", pos)
        if cmd.name in {"sort", "group"} and cmd.args[0].lower() in ANALYTIC_FIELDS:
            self.ctx.uses_analytics = True
        return cmd


# ----------------------------------------------------------------------------- field access
_MISSING = object()


class _Context:
    """Field lookup and comparison for one graph (link-analysis scores computed on first use)."""

    def __init__(self, graph: IntelligenceGraph):
        self.graph = graph
        self.uses_analytics = False
        self._scores: dict[str, dict[str, Any]] | None = None

    def scores(self) -> dict[str, dict[str, Any]]:
        if self._scores is None:
            self._scores = analyze_links(self.graph)["scores"]
        return self._scores

    def get(self, entity: Entity, name: str) -> Any:
        key = name.lower()
        if key == "type":
            return entity.type.value
        if key in {"value", "label", "id", "confidence", "depth"}:
            return getattr(entity, key)
        if key in {"source", "module"}:
            return entity.metadata.get("sources") or [entity.source_module]
        if key == "degree":
            g = self.graph._graph
            return g.degree(entity.id) if entity.id in g else 0
        if key == "seed":
            return entity.id in self.graph._seed_ids
        if key in ANALYTIC_FIELDS:
            return self.scores().get(entity.id, {}).get(key, _MISSING)
        node: Any = entity.metadata
        for part in name.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return _MISSING
        return node

    def field_predicate(self, name: str, op: str, raw: str, pos: int) -> Predicate:
        key = name.lower()
        if key in ANALYTIC_FIELDS:
            self.uses_analytics = True
        if key == "type" and op in {":", "=", "!="}:
            wanted = TYPE_ALIASES.get(raw.lower(), raw.lower())
            if wanted not in {t.value for t in EntityType} and not _has_wildcard(raw):
                types = ", ".join(sorted(t.value for t in EntityType))
                raise QueryError(f"unknown entity type {raw!r}; known: {types}", pos)
            raw = wanted
        if op == "~":
            if len(raw) > MAX_REGEX_LENGTH:
                raise QueryError(f"regular expressions are limited to {MAX_REGEX_LENGTH} characters", pos)
            if re.search(r"\([^)]*[+*][^)]*\)[+*{]", raw):
                raise QueryError("nested repetition is not allowed in a regular expression", pos)
            try:
                pattern = re.compile(raw, re.IGNORECASE)
            except re.error as exc:
                raise QueryError(f"invalid regular expression: {exc}", pos) from exc
            return lambda e: _any_value(self.get(e, name), lambda v: bool(pattern.search(str(v)[:MAX_MATCH_TEXT])))
        if op in {">", ">=", "<", "<="}:
            try:
                limit = float(raw)
            except ValueError as exc:
                raise QueryError(f"{name}{op} needs a number", pos) from exc
            compare = {
                ">": lambda a: a > limit,
                ">=": lambda a: a >= limit,
                "<": lambda a: a < limit,
                "<=": lambda a: a <= limit,
            }[op]
            return lambda e: _any_value(self.get(e, name), lambda v: _number(v) is not None and compare(_number(v)))
        if op == ":" and raw == "*":
            return lambda e: _present(self.get(e, name))
        matcher = _text_matcher(raw, glob=op == ":")
        if op == "!=":
            return lambda e: not _any_value(self.get(e, name), matcher)
        return lambda e: _any_value(self.get(e, name), matcher)


def _has_wildcard(text: str) -> bool:
    return any(c in text for c in "*?")


def _text_matcher(raw: str, glob: bool) -> Callable[[Any], bool]:
    wanted = raw.lower()
    if wanted in {"true", "false"}:
        flag = wanted == "true"
        return lambda v: (v is flag) if isinstance(v, bool) else str(v).lower() == wanted
    number = _number(raw)
    if glob and _has_wildcard(raw):
        pattern = re.compile(fnmatch.translate(wanted), re.IGNORECASE)
        return lambda v: bool(pattern.match(str(v)[:MAX_MATCH_TEXT].lower()))

    def equal(v: Any) -> bool:
        if number is not None and isinstance(v, (int, float)) and not isinstance(v, bool):
            return float(v) == number
        return str(v).lower() == wanted

    return equal


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except ValueError:
        return None


def _present(value: Any) -> bool:
    return value is not _MISSING and value not in (None, "", [], {}, False)


def _any_value(value: Any, test: Callable[[Any], bool]) -> bool:
    if value is _MISSING or value is None:
        return False
    if isinstance(value, (list, tuple, set)):
        return any(_any_value(v, test) for v in value)
    if isinstance(value, dict):
        return any(_any_value(v, test) for v in value.values()) or any(test(k) for k in value)
    return test(value)


# ----------------------------------------------------------------------------- evaluation
def run_query(graph: IntelligenceGraph, text: str) -> dict[str, Any]:
    """Parse and run ``text`` against ``graph``; raises :class:`QueryError` on bad input."""
    started = time.perf_counter()
    text = (text or "").strip()
    if not text:
        raise QueryError("empty query", 0)
    if len(text) > MAX_QUERY_LENGTH:
        raise QueryError(f"queries are limited to {MAX_QUERY_LENGTH} characters", MAX_QUERY_LENGTH)
    context = _Context(graph)
    parsed = _Parser(text, context).parse()

    result = _run_paths(graph, parsed) if parsed.kind == "path" else _run_chain(graph, parsed)
    result = _apply_commands(result, parsed.commands, context)
    result["query"] = text
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def _neighbours(graph: IntelligenceGraph, node: str, spec: EdgeSpec) -> list[tuple[str, str]]:
    """(neighbour, relation id) pairs reachable from ``node`` along ``spec``."""
    g = graph._graph
    found: list[tuple[str, str]] = []
    if spec.direction in {"out", "any"}:
        for _, target, key, data in g.out_edges(node, keys=True, data=True):
            if not spec.types or data.get("relation_type") in spec.types:
                found.append((target, key))
    if spec.direction in {"in", "any"}:
        for source, _, key, data in g.in_edges(node, keys=True, data=True):
            if not spec.types or data.get("relation_type") in spec.types:
                found.append((source, key))
    return found


def _run_chain(graph: IntelligenceGraph, query: ParsedQuery) -> dict[str, Any]:
    entities = graph.get_all_entities()
    candidates = [{e.id for e in entities if pred(e)} for pred in query.selectors]
    if not query.edges:
        return {"kind": "nodes", "_rows": candidates[0], "_nodes": set(candidates[0]), "_edges": set(), "paths": []}

    # Backward pass: keep only nodes that can complete the rest of the pattern.
    valid: list[set[str]] = [set() for _ in candidates]
    valid[-1] = candidates[-1]
    for i in range(len(query.edges) - 1, -1, -1):
        valid[i] = {
            n for n in candidates[i] if any(m in valid[i + 1] for m, _ in _neighbours(graph, n, query.edges[i]))
        }
    # Forward pass: keep only nodes reachable from a valid start, and the edges used.
    reached: list[set[str]] = [set() for _ in candidates]
    reached[0] = valid[0]
    edges: set[str] = set()
    for i, spec in enumerate(query.edges):
        for n in reached[i]:
            for m, rel_id in _neighbours(graph, n, spec):
                if m in valid[i + 1]:
                    reached[i + 1].add(m)
                    edges.add(rel_id)

    paths = _enumerate_chain_paths(graph, query, reached)
    nodes = set().union(*reached)
    return {"kind": "nodes", "_rows": reached[-1], "_nodes": nodes, "_edges": edges, "paths": paths}


def _enumerate_chain_paths(graph: IntelligenceGraph, query: ParsedQuery, reached: list[set[str]]) -> list[dict]:
    paths: list[dict] = []

    def walk(step: int, nodes: list[str], rels: list[str]) -> None:
        if len(paths) >= MAX_PATHS:
            return
        if step == len(query.edges):
            paths.append({"nodes": list(nodes), "edges": list(rels)})
            return
        for m, rel_id in _neighbours(graph, nodes[-1], query.edges[step]):
            if m in reached[step + 1] and m not in nodes:
                walk(step + 1, [*nodes, m], [*rels, rel_id])

    for start in sorted(reached[0]):
        walk(0, [start], [])
        if len(paths) >= MAX_PATHS:
            break
    return paths


def _run_paths(graph: IntelligenceGraph, query: ParsedQuery) -> dict[str, Any]:
    """Shortest routes (ignoring direction) from any source match to the nearest target matches."""
    entities = graph.get_all_entities()
    sources = {e.id for e in entities if query.selectors[0](e)}
    targets = {e.id for e in entities if query.selectors[1](e)}
    spec = EdgeSpec("any")
    parent: dict[str, tuple[str, str] | None] = dict.fromkeys(sources)
    depth = dict.fromkeys(sources, 0)
    queue = deque(sorted(sources))
    found: list[str] = []
    while queue and len(found) < MAX_PATHS:
        node = queue.popleft()
        if node in targets and parent[node] is not None:  # a source that is also a target is not a route
            found.append(node)
        if depth[node] >= query.max_hops:
            continue
        for neighbour, rel_id in _neighbours(graph, node, spec):
            if neighbour not in parent:
                parent[neighbour] = (node, rel_id)
                depth[neighbour] = depth[node] + 1
                queue.append(neighbour)

    paths: list[dict] = []
    nodes: set[str] = set()
    edges: set[str] = set()
    for end in found:
        chain_nodes, chain_edges = [end], []
        step = parent[end]
        while step is not None:
            prev, rel_id = step
            chain_nodes.append(prev)
            chain_edges.append(rel_id)
            step = parent[prev]
        chain_nodes.reverse()
        chain_edges.reverse()
        paths.append({"nodes": chain_nodes, "edges": chain_edges, "hops": len(chain_edges)})
        nodes.update(chain_nodes)
        edges.update(chain_edges)
    return {"kind": "paths", "_rows": set(found), "_nodes": nodes, "_edges": edges, "paths": paths}


def _row(entity: Entity, context: _Context, extra: list[str]) -> dict[str, Any]:
    g = context.graph._graph
    row: dict[str, Any] = {
        "id": entity.id,
        "type": entity.type.value,
        "label": entity.label,
        "value": entity.value,
        "confidence": entity.confidence,
        "depth": entity.depth,
        "degree": g.degree(entity.id) if entity.id in g else 0,
    }
    if context.uses_analytics:
        score = context.scores().get(entity.id, {})
        for key in ("key_score", "pagerank", "betweenness", "community"):
            row[key] = score.get(key)
    for name in extra:
        if name not in row:
            value = context.get(entity, name)
            row[name] = None if value is _MISSING else value
    return row


def _sort_key(value: Any) -> tuple[int, Any]:
    if value is None or value is _MISSING:
        return (2, 0)
    number = _number(value)
    if number is not None:
        return (0, number)
    return (1, str(value).lower())


def _apply_commands(result: dict[str, Any], commands: list[Command], context: _Context) -> dict[str, Any]:
    graph = context.graph
    rows_ids: set[str] = result.pop("_rows")
    node_ids: set[str] = result.pop("_nodes")
    edge_ids: set[str] = result.pop("_edges")
    extra = [c.args[0] for c in commands if c.name in {"sort", "group"}]
    entities = [e for e in (graph.get_entity(i) for i in rows_ids) if e is not None]
    rows = [_row(e, context, extra) for e in entities]
    rows.sort(key=lambda r: (-r.get("degree", 0), r["label"].lower()))
    limit = DEFAULT_LIMIT
    groups: list[dict[str, Any]] | None = None
    count_only = False
    for cmd in commands:
        if cmd.name == "sort":
            descending = len(cmd.args) < 2 or cmd.args[1].lower() == "desc"
            name = cmd.args[0]
            present = [r for r in rows if r.get(name) is not None]
            absent = [r for r in rows if r.get(name) is None]
            present.sort(key=lambda r: _sort_key(r.get(name)), reverse=descending)
            rows = present + absent
        elif cmd.name == "limit":
            limit = min(int(cmd.args[0]), MAX_LIMIT)
            rows = rows[:limit]
        elif cmd.name == "count":
            count_only = True
        elif cmd.name == "group":
            name = cmd.args[0]
            tally: dict[str, int] = {}
            for r in rows:
                value = r.get(name)
                values = value if isinstance(value, list) else [value]
                for v in values:
                    label = "(none)" if v is None else str(v)
                    tally[label] = tally.get(label, 0) + 1
            groups = [{"key": k, "count": n} for k, n in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))]

    total = len(rows_ids)
    truncated = len(rows) > MAX_LIMIT or (len(rows) > limit)
    rows = rows[: min(limit, MAX_LIMIT)]
    shown = {r["id"] for r in rows}
    if result["kind"] == "nodes" and not result["paths"]:
        node_ids = shown  # a plain filter highlights only the rows actually returned
    return {
        "kind": "count" if count_only else "groups" if groups is not None else result["kind"],
        "count": total,
        "rows": [] if count_only else rows,
        "groups": groups or [],
        "node_ids": sorted(node_ids | shown),
        "edge_ids": sorted(edge_ids),
        "paths": result["paths"],
        "truncated": truncated or total > len(rows),
    }


EXAMPLES = [
    {"query": "type:ip_address", "explains": "Every IP address"},
    {"query": 'type:subdomain value~"^(vpn|remote|sso|admin)"', "explains": "Remote-access and admin hosts"},
    {"query": "type:domain -[RESOLVES_TO]-> type:ip_address", "explains": "Domains and the IPs they resolve to"},
    {"query": "type:vulnerability intel.kev:*", "explains": "CVEs exploited in the wild (CISA KEV)"},
    {"query": "type:email -- type:social_profile", "explains": "Emails linked to social accounts"},
    {"query": "path from type:email to type:ip_address", "explains": "How people connect to infrastructure"},
    {"query": "* | sort key_score | limit 10", "explains": "The ten most important entities"},
    {"query": "* | group type", "explains": "How many of each kind of entity"},
    {"query": "articulation:true", "explains": "Single points of failure"},
    {
        "query": "category:favicon degree>=2 <-[USES_TECH]- *",
        "explains": "Hosts sharing a favicon (same operator or product?)",
    },
]


def syntax() -> list[dict[str, str]]:
    """A compact reference for the help endpoint and the UI."""
    return [
        {"form": "field:value", "means": "equals (case-insensitive); * and ? are wildcards; field:* means present"},
        {"form": "field=value  field!=value", "means": "exact match / not equal"},
        {"form": 'field~"regex"', "means": "regular expression search"},
        {"form": "field>n  >=  <  <=", "means": "numeric comparison"},
        {
            "form": 'word  "two words"',
            "means": "text in the value or label; a bare type name (domain, ip) matches the type",
        },
        {"form": "AND  OR  NOT  -term  ( )", "means": "combine filters (AND is implied between terms)"},
        {"form": "A -> B   A <- B   A -- B", "means": "A has a relation to / from / with B"},
        {"form": "A -[RESOLVES_TO|HOSTED_ON]-> B", "means": "only those relation types"},
        {"form": "path from A to B max 6", "means": "shortest routes between any A and the nearest Bs"},
        {"form": "| sort field [asc|desc]  | limit n  | count  | group field", "means": "shape the results"},
        {
            "form": "fields",
            "means": "type value label id confidence depth degree seed source, any metadata key (dotted: "
            "intel.kev), and pagerank betweenness community key_score articulation",
        },
    ]
