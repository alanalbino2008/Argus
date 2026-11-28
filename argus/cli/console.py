"""Command-line interface (CLI) for Argus OSINT Platform with Rich styling."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import re
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from argus.core.engine import ArgusEngine
from argus.core.events import Event, EventType, event_bus
from argus.core.models import EntityType, ScanConfig

console = Console()

BANNER = r"""[bold cyan]
    ___     ____     ______  __  __   _____
   /   |   / __ \   / ____/ / / / /  / ___/
  / /| |  / /_/ /  / / __  / / / /   \__ \
 / ___ | / _, _/  / /_/ / / /_/ /   ___/ /
/_/  |_|/_/ |_|   \____/  \____/   /____/
[/bold cyan]
[dim cyan]» Next-Generation OSINT & Graph Link Analysis Platform «[/dim cyan]
"""


def detect_target_type(target: str) -> EntityType:
    """Smart heuristic to auto-detect entity type from user string input."""
    target_clean = target.strip()

    # 1. IP Address
    try:
        ipaddress.ip_address(target_clean)
        return EntityType.IP_ADDRESS
    except ValueError:
        pass

    # 2. Cryptocurrency wallet (checksum verified, so a random string is never mistaken for one)
    from argus.intel.crypto import classify

    if classify(target_clean) is not None:
        return EntityType.CRYPTO_WALLET

    # 2. Email Address
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", target_clean):
        return EntityType.EMAIL

    # 3. Domain or Subdomain
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target_clean) and not target_clean.startswith("@"):
        return EntityType.DOMAIN

    # 4. Phone Number
    if re.match(r"^\+?[0-9\s().-]{7,20}$", target_clean) and sum(c.isdigit() for c in target_clean) >= 7:
        return EntityType.PHONE

    # 5. A company name ("Acme Holdings Ltd") or a person's full name ("Jane Roe")
    from argus.intel.names import LEGAL_FORMS

    words = target_clean.split()
    if len(words) >= 2 and all(re.fullmatch(r"[^\W\d_][\w.'&,-]*", w) for w in words):
        if words[-1].lower().strip(".,") in LEGAL_FORMS - {"the", "and", "group"}:
            return EntityType.ORGANIZATION
        return EntityType.PERSON

    # 5. Default to Username
    return EntityType.USERNAME


async def run_cli_scan(
    target: str,
    entity_type_str: str | None = None,
    max_depth: int = 2,
    enabled_modules: list | None = None,
    export_json: str | None = None,
    export_csv: str | None = None,
    allow_private: bool = False,
    passive_only: bool = False,
):
    """Run an investigation directly from the terminal with real-time Rich UI."""
    console.print(BANNER)

    # Detect entity type if not explicitly supplied
    entity_type = EntityType(entity_type_str.lower()) if entity_type_str else detect_target_type(target)

    if not allow_private:
        from argus.security.network import validate_scan_target

        try:
            validate_scan_target(target, entity_type)
        except ValueError as exc:
            console.print(
                f"[bold red]✗ {exc}[/bold red]\n[dim]Use --allow-private only for authorised internal assessments.[/dim]"
            )
            sys.exit(2)

    console.print(
        Panel(
            f"[bold white]Target:[/bold white] [green]{target}[/green]   "
            f"[bold white]Detected Type:[/bold white] [yellow]{entity_type.value.upper()}[/yellow]   "
            f"[bold white]Max Recursion Depth:[/bold white] [magenta]{max_depth}[/magenta]",
            title="[bold cyan]Investigation Parameters[/bold cyan]",
            border_style="cyan",
        )
    )

    config = ScanConfig(
        target=target,
        target_type=entity_type,
        max_depth=max_depth,
        enabled_modules=enabled_modules,
        concurrency_limit=15,
        timeout_seconds=10.0,
        allow_private_targets=allow_private,
        passive_only=passive_only,
    )

    engine = ArgusEngine(config)

    # Real-time event listener for CLI output
    async def cli_event_listener(event: Event):
        if event.type == EventType.ENTITY_DISCOVERED:
            data = event.data.get("entity", {})
            etype = data.get("type", "entity").upper()
            label = data.get("label", "")
            mod = event.data.get("source_module", "")
            console.print(
                f"[dim]{event.timestamp.strftime('%H:%M:%S')}[/dim] [bold green]+[/bold green] [{etype}] [white]{label}[/white] [dim](via {mod})[/dim]"
            )

    event_bus.subscribe_all(cli_event_listener)

    console.print("\n[bold yellow]⚡ Launching recursive reconnaissance pipeline...[/bold yellow]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Investigating attack surface...", total=None)
        graph = await engine.start()
        progress.update(task, completed=100, description="[bold green]✓ Investigation Complete[/bold green]")

    # Print summary results table
    table = Table(title=f"Discovered Intelligence Topology: {target}", border_style="cyan")
    table.add_column("Category", style="cyan", justify="left")
    table.add_column("Count", style="green", justify="right")
    table.add_column("Sample Entities", style="white", justify="left")

    analytics = graph.compute_analytics()
    for category, count in analytics.get("entities_by_type", {}).items():
        sample_nodes = [e.label for e in graph.get_all_entities() if e.type.value == category][:3]
        samples_str = ", ".join(sample_nodes)
        if count > 3:
            samples_str += f", +{count - 3} more"
        table.add_row(category.upper(), str(count), samples_str)

    console.print("\n", table)

    # Top Pivots / Hubs
    hubs = analytics.get("top_hubs", [])
    if hubs:
        hubs_table = Table(title="Top Graph Pivots & High-Degree Hubs", border_style="magenta")
        hubs_table.add_column("Entity Label", style="white")
        hubs_table.add_column("Type", style="yellow")
        hubs_table.add_column("Connections", style="green", justify="right")
        for hub in hubs[:5]:
            hubs_table.add_row(hub["label"], hub["type"].upper(), str(hub["degree"]))
        console.print(hubs_table)

    # Exports
    if export_json:
        import json

        # Write off the event loop: file I/O blocks.
        await asyncio.to_thread(Path(export_json).write_text, json.dumps(graph.to_dict(), indent=2), "utf-8")
        console.print(f"\n[green]✓ Graph exported to JSON:[/green] {export_json}")

    if export_csv:
        await asyncio.to_thread(Path(export_csv).write_text, graph.to_maltego_csv(), "utf-8")
        console.print(f"[green]✓ Maltego CSV exported to:[/green] {export_csv}")

    console.print(
        f"\n[bold green]Done.[/bold green] Discovered [bold]{graph.node_count}[/bold] entities and [bold]{graph.edge_count}[/bold] relationships."
    )


async def load_demo_cli() -> None:
    from argus.core.settings import get_settings
    from argus.demo import DEMO_TARGET, load_demo
    from argus.storage.db import Database
    from argus.storage.migrate import upgrade_database
    from argus.storage.repository import InvestigationRepository

    db = Database(get_settings().database_url)
    try:
        await upgrade_database(db)
        inv_id = await load_demo(InvestigationRepository(db))
    finally:
        await db.dispose()
    console.print(f"[bold green]✓ Demo investigation loaded:[/bold green] {DEMO_TARGET} ({inv_id})")
    console.print(f"[dim]Open the web UI → History, or visit /?inv={inv_id}[/dim]")


async def create_api_key_cli(name: str, role: str) -> None:
    """Out-of-band key creation (first setup, or recovery if every admin key is lost)."""
    from argus.core.settings import get_settings
    from argus.security.auth import SYSTEM, Role
    from argus.storage.db import Database
    from argus.storage.migrate import upgrade_database
    from argus.storage.security_repo import ApiKeyRepository, AuditLog

    db = Database(get_settings().database_url)
    try:
        await upgrade_database(db)
        record, key = await ApiKeyRepository(db).create(name, Role(role), created_by="cli")
        await AuditLog(db).record(
            SYSTEM, "key.create", record["id"], details={"name": name, "role": role, "via": "cli"}
        )
    finally:
        await db.dispose()
    console.print(
        Panel(
            f"[bold white]{key}[/bold white]\n\n[dim]id {record['id']} · role {role} · shown once, store it securely[/dim]",
            title=f"[bold green]API key created: {name}[/bold green]",
            border_style="green",
        )
    )


async def migrate_cli(wait_seconds: float = 90.0) -> str | None:
    """Apply database migrations and exit (run before the API starts, e.g. as an init container).

    Waits for the database to accept connections - in a fresh deployment PostgreSQL may still be
    starting - instead of failing and being restarted with an ever-growing back-off.
    """
    import time

    from argus.core.settings import get_settings
    from argus.storage import Database
    from argus.storage.migrate import upgrade_database

    deadline = time.monotonic() + wait_seconds
    while True:
        db = Database(get_settings().database_url)
        try:
            return await upgrade_database(db)
        except (OSError, ConnectionError) as exc:  # refused / DNS not ready / reset
            if time.monotonic() >= deadline:
                raise
            console.print(f"[yellow]Database not reachable yet ({type(exc).__name__}); retrying...[/yellow]")
            await asyncio.sleep(2)
        finally:
            await db.dispose()


async def check_platforms_cli() -> dict:
    """Verify every username-platform signature against live sites (needs internet access)."""
    import aiohttp

    from argus.core.http import HttpClient
    from argus.modules.identity.username_hunter import get_platforms, verify_platforms
    from argus.security.network import GuardedResolver, configured_proxy_hosts

    config = ScanConfig(target="platform-check", target_type=EntityType.USERNAME, timeout_seconds=15.0)
    connector = aiohttp.TCPConnector(limit=40, resolver=GuardedResolver(trusted_hosts=configured_proxy_hosts()))
    async with aiohttp.ClientSession(connector=connector, trust_env=True) as raw:
        rows = await verify_platforms(get_platforms(), HttpClient(raw, max_retries=1), config)
    table = Table(title="Username platform signatures", show_lines=False)
    for column in ("Platform", "Category", "Known account", "Status"):
        table.add_column(column)
    colours = {"ok": "green", "false_negative": "yellow", "false_positive": "red", "error": "magenta"}
    for r in rows:
        table.add_row(
            r["name"], r["category"], r.get("known") or "-", f"[{colours.get(r['status'], 'white')}]{r['status']}"
        )
    console.print(table)
    counts = {
        s: sum(r["status"] == s for r in rows) for s in ("ok", "false_negative", "false_positive", "error", "untested")
    }
    console.print(" · ".join(f"{k}: {v}" for k, v in counts.items()))
    return {"summary": counts, "platforms": rows}


def personal_data_dir() -> Path:
    """Where Argus Personal keeps its database: the platform's usual place for application data."""
    if os.environ.get("ARGUS_HOME"):
        return Path(os.environ["ARGUS_HOME"])
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "Argus"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Argus"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "argus"


SERVER: Any = None  # the running Argus Personal server, so Quit can stop it
RESTART = False  # set to start again straight after stopping (after preparing a restore)


def run_personal(port: int) -> None:
    """Argus Personal: only this computer can reach it (127.0.0.1), data in the user's own folder."""
    import threading
    import webbrowser

    import uvicorn

    home = personal_data_dir()
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.environ.setdefault("ARGUS_EDITION", "personal")
    os.environ.setdefault("ARGUS_DATABASE_URL", f"sqlite+aiosqlite:///{home / 'argus.db'}")
    os.environ.setdefault("ARGUS_PUBLIC_URL", f"http://127.0.0.1:{port}")
    # this computer's own encryption key (created on first start): protects saved API keys
    os.environ.setdefault("ARGUS_ENCRYPTION_KEY_FILE", str(home / "secret.key"))
    url = os.environ["ARGUS_PUBLIC_URL"]
    console.print(BANNER)
    console.print(f"[bold cyan]Argus Personal[/bold cyan] at {url}  ·  data in {home}")
    if not os.environ.get("ARGUS_NO_BROWSER"):
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    # 127.0.0.1 only: nobody else on the network (café wifi, a shared office) can reach it.
    global SERVER, RESTART
    while True:  # once, or again straight away when asked to restart (to finish restoring a backup)
        RESTART = False
        SERVER = uvicorn.Server(uvicorn.Config("argus.api.server:app", host="127.0.0.1", port=port, reload=False,
                                               access_log=False, log_config=None if os.environ.get("ARGUS_DESKTOP")
                                               else uvicorn.config.LOGGING_CONFIG))  # fmt: skip
        SERVER.run()
        if not RESTART:
            return
        console.print("[cyan]Restarting Argus…[/cyan]")


def _backup_password(confirm: bool) -> str:
    import getpass

    password = os.environ.get("ARGUS_BACKUP_PASSWORD") or getpass.getpass("Backup password: ")
    if confirm and not os.environ.get("ARGUS_BACKUP_PASSWORD") and getpass.getpass("Again: ") != password:
        raise SystemExit("The passwords don't match")
    return password


def backup_cli(args: argparse.Namespace) -> int:
    """argus --backup-to / --backup-check / --backup-restore (password: ARGUS_BACKUP_PASSWORD, or asked)."""
    from argus.core.settings import get_settings
    from argus.storage import backup

    settings = get_settings()
    try:
        if args.backup_to:
            result = backup.create(settings, Path(args.backup_to), backup.new_key(_backup_password(confirm=True)))
            console.print(f"[green]Backup written:[/green] {result['file']} ({result['size'] / 1e6:.1f} MB)")
        elif args.backup_check:
            info = backup.check(Path(args.backup_check), _backup_password(confirm=False), work_dir=Path.cwd(),
                                known_revisions=backup.known_revisions())  # fmt: skip
            console.print(f"[green]The backup is complete and readable.[/green] Made {info['created_at']} by Argus "
                          f"{info['argus_version']} on {info['computer']}: {info['counts']}")  # fmt: skip
        else:
            info = backup.stage_restore(settings, Path(args.backup_restore), _backup_password(confirm=False),
                                        backup.known_revisions())  # fmt: skip
            console.print(f"[green]Ready to restore the backup made {info['created_at']}.[/green] It takes over the "
                          "next time Argus starts; the current data is kept in a before-restore folder.")  # fmt: skip
    except backup.BackupError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1
    return 0


async def query_cli(text: str, source: str, as_json: bool) -> int:
    """Run an AQL query against a stored investigation or an exported graph; prints a table."""
    import json
    from pathlib import Path

    from argus.core.graph import IntelligenceGraph
    from argus.intel.query import QueryError, run_query

    path = Path(source)
    if path.suffix.lower() == ".json" and await asyncio.to_thread(path.is_file):
        graph: IntelligenceGraph | None = IntelligenceGraph.from_dict(
            json.loads(await asyncio.to_thread(path.read_text, "utf-8"))
        )
    else:
        from argus.core.settings import get_settings
        from argus.storage.db import Database
        from argus.storage.repository import InvestigationRepository

        db = Database(get_settings().database_url)
        try:
            graph = await InvestigationRepository(db).load_graph(source)
        finally:
            await db.dispose()
    if graph is None:
        console.print(f"[red]No investigation or graph file named {source}[/red]")
        return 2
    try:
        result = run_query(graph, text)
    except QueryError as exc:
        console.print(f"[red]Query error:[/red] {exc}")
        if exc.position is not None:
            console.print(f"  {text}\n  {' ' * exc.position}[red]^[/red]")
        return 1
    if as_json:
        print(json.dumps(result, indent=2, default=str))
        return 0
    if result["kind"] == "count":
        console.print(f"[bold]{result['count']}[/bold] matching entities")
        return 0
    if result["kind"] == "groups":
        table = Table(title=f"{result['count']} entities by group")
        table.add_column("Group")
        table.add_column("Count", justify="right")
        for group in result["groups"]:
            table.add_row(group["key"], str(group["count"]))
        console.print(table)
        return 0
    if result["kind"] == "paths":
        labels = {r["id"]: r["label"] for r in result["rows"]}
        for e in graph.get_all_entities():
            labels.setdefault(e.id, e.label)
        for route in result["paths"]:
            console.print(f"[cyan]{route['hops']} hops:[/cyan] " + "  →  ".join(labels[n] for n in route["nodes"]))
    table = Table(title=f"{result['count']} matches ({result['elapsed_ms']} ms)")
    columns = [c for c in ("type", "label", "degree", "confidence", "key_score") if any(c in r for r in result["rows"])]
    for column in columns:
        table.add_column(column)
    for row in result["rows"]:
        table.add_row(*(str(row.get(c, "")) for c in columns))
    console.print(table)
    return 0


def verify_report_cli(path: str, trusted_key: str | None) -> int:
    """0: genuine and unaltered (and signed by the given key, if one was given); 1 otherwise."""
    from pathlib import Path

    from argus.reports.signing import verify

    result = verify(Path(path).read_bytes(), trusted_key)
    if not result["valid"]:
        console.print(f"[red]NOT VALID[/red]: {result['problem']}")
        return 1
    console.print(f"[green]Valid[/green]: unaltered since it was signed by key {result['key_id']}")
    if result["trusted"] is False:
        console.print(f"[red]But not by the key you trust[/red] ({trusted_key})")
        return 1
    if result["trusted"] is None:
        console.print("Compare the key id with the one published by the organisation that issued the report.")
    else:
        console.print("[green]Signed by the key you trust.[/green]")
    console.print(f"SHA-256 of the file: {result['sha256']}")
    return 0


async def integrity_cli() -> int:
    """0: everything is whole; 1: problems found (each listed)."""
    from types import SimpleNamespace

    from argus.core.settings import get_settings
    from argus.storage import integrity
    from argus.storage.case_repo import CaseRepository
    from argus.storage.db import Database
    from argus.storage.security_repo import AuditLog
    from argus.storage.subscriber_repo import AppStateRepository
    from argus.storage.vault_store import VaultService

    db = Database(get_settings().database_url)
    try:
        state = AppStateRepository(db)
        await VaultService(db, state).load()  # so a locked vault is known, not misread as damage
        result = await integrity.run(SimpleNamespace(db=db, audit=AuditLog(db), cases=CaseRepository(db)))
    finally:
        await db.dispose()
    for check in result["checks"]:
        mark = (
            "[yellow]skipped[/yellow]"
            if check.get("skipped")
            else "[green]ok[/green]"
            if check["ok"]
            else "[red]PROBLEMS[/red]"
        )
        console.print(f"{check['name']:<12} {mark}  {check['detail']} ({check['seconds']} s)")
        for problem in check["problems"]:
            console.print(f"    - {problem}")
        if check["count"] > len(check["problems"]):
            console.print(f"    … and {check['count'] - len(check['problems'])} more")
    console.print(
        "[green]Everything is whole.[/green]" if result["ok"] else f"[red]{result['problems']} problem(s) found.[/red]"
    )
    return 0 if result["ok"] else 1


def verify_audit_cli(path: str, trusted_key: str | None) -> int:
    """0: the audit export is intact and signed (by the given public key, if one was given); 1 otherwise."""
    from pathlib import Path

    from argus.security.audit_export import VerificationError, verify

    try:
        result = verify(Path(path).read_bytes(), trusted_key)
    except (VerificationError, ValueError, KeyError) as exc:
        console.print(f"[red]NOT VALID[/red]: {exc}")
        return 1
    console.print(f"[green]Valid[/green]: {result['entries']} entries (ids {result['first_id']} to "
                  f"{result['last_id']}), unaltered since exported by {result['exported_by']} at {result['exported_at']}")  # fmt: skip
    console.print(f"Signed by key {result['key_id']}" + (" (the key you trust)" if result["trusted_key_checked"]
                  else ": compare it with the key published at /api/report-signing-key"))  # fmt: skip
    if result["complete_chain"]:
        console.print("The entries form an unbroken part of the chain.")
    else:
        console.print(f"{result['gaps']} gap(s) between entries: entries of other workspaces or outside the filters.")
    head = result.get("head") or {}
    console.print(f"Chain head at export: entry {head.get('id')}, hash {head.get('hash')}")
    return 0


def preflight_cli() -> int:
    """Print every production finding for the current configuration; 1 if any is an error."""
    from argus.core import preflight
    from argus.core.settings import get_settings

    findings = preflight.check(get_settings())
    errors = [f for f in findings if f.level == "error"]
    for f in findings:
        mark = "[red]ERROR  [/red]" if f.level == "error" else "[yellow]WARNING[/yellow]"
        console.print(f"{mark} {f.code}: {f.message}\n         fix: {f.fix}")
    if not findings:
        console.print("[green]Ready for production: no findings.[/green]")
    elif not errors:
        console.print(f"[green]No errors[/green] ({len(findings)} warning(s)): safe to start in production.")
    else:
        console.print(
            f"[red]{len(errors)} error(s):[/red] with ARGUS_ENVIRONMENT=production the server will not start."
        )
    return 1 if errors else 0


def cli_entrypoint():
    """Command line parser."""
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus - Advanced OSINT Platform & Relationship Graphing Engine",
    )
    parser.add_argument("target", nargs="?", help="Target seed (Domain, Username, Email, or IP)")
    parser.add_argument("-t", "--type", choices=[t.value for t in EntityType], help="Target entity type")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Max recursive enrichment depth (default: 2)")
    parser.add_argument("-m", "--modules", help="Comma-separated module names to execute")
    parser.add_argument("--export-json", help="Export investigation graph as JSON file")
    parser.add_argument("--export-csv", help="Export relationships as Maltego CSV format")
    parser.add_argument("--serve", action="store_true", help="Launch the interactive Web Dashboard & API server")
    parser.add_argument("--port", type=int, default=8000, help="Web server port (default: 8000)")
    parser.add_argument("--host", default="127.0.0.1", help="Web server host (default: 127.0.0.1)")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Permit private/internal targets (authorised internal assessments only)",
    )
    parser.add_argument(
        "--create-api-key", metavar="NAME", help="Create an API key in the configured database and print it once"
    )
    parser.add_argument(
        "--load-demo",
        action="store_true",
        help="Load the built-in fictional demo investigation into the database",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Skip modules that contact the target's own systems (bug bounty programmes that forbid active testing)",
    )
    parser.add_argument(
        "--personal",
        action="store_true",
        help="Start Argus Personal on this computer (signs in with an Argus account; data stays here)",
    )
    parser.add_argument(
        "--generate-licence-keys",
        action="store_true",
        help="Account service operators: print a new licence signing key pair, then exit",
    )
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="Apply database migrations to ARGUS_DATABASE_URL, then exit (for deployment jobs)",
    )
    parser.add_argument(
        "--check-platforms",
        action="store_true",
        help="Verify every username-platform signature against live sites, then exit",
    )
    parser.add_argument(
        "--query",
        metavar="AQL",
        help='Run an Argus Query Language query (with --on), e.g. "type:domain -> type:ip_address | limit 20"',
    )
    parser.add_argument("--on", metavar="ID_OR_FILE", help="With --query: an investigation id or a --export-json file")
    parser.add_argument("--query-json", action="store_true", help="With --query: print the raw JSON result")
    parser.add_argument("--platforms-report", metavar="FILE", help="With --check-platforms: write a JSON report")
    parser.add_argument("--backup-to", metavar="FOLDER", help="Make an encrypted backup into FOLDER, then exit")
    parser.add_argument(
        "--backup-check", metavar="FILE", help="Open a backup with its password and check it, then exit"
    )
    parser.add_argument(
        "--backup-restore", metavar="FILE", help="Prepare a restore from a backup (it takes over at the next start)"
    )
    parser.add_argument("--verify-report", metavar="FILE", help="Check a signed case report, then exit")
    parser.add_argument("--verify-audit", metavar="FILE", help="Check an audit log export (JSON Lines), then exit")
    parser.add_argument("--preflight", action="store_true",
                        help="Check this configuration is safe for production (exit 1 on errors), then exit")  # fmt: skip
    parser.add_argument("--check", action="store_true",
                        help="Check the database, its references, the audit chain and all evidence, then exit")  # fmt: skip
    parser.add_argument(
        "--report-key", metavar="KEY",
        help="With --verify-report: the issuer's public key or key id; with --verify-audit: its public key",
    )  # fmt: skip
    parser.add_argument(
        "--role",
        choices=["viewer", "analyst", "admin"],
        default="analyst",
        help="Role for --create-api-key (default: analyst)",
    )

    args = parser.parse_args()

    if args.verify_report:
        raise SystemExit(verify_report_cli(args.verify_report, args.report_key))
    if args.verify_audit:
        raise SystemExit(verify_audit_cli(args.verify_audit, args.report_key))
    if args.preflight:
        raise SystemExit(preflight_cli())
    if args.check:
        raise SystemExit(asyncio.run(integrity_cli()))

    if args.migrate:
        revision = asyncio.run(migrate_cli(float(os.environ.get("ARGUS_MIGRATE_WAIT_SECONDS", "90"))))
        console.print(f"[green]Database schema at revision {revision}[/green]")
        return

    if args.backup_to or args.backup_check or args.backup_restore:
        raise SystemExit(backup_cli(args))

    if args.check_platforms:
        report = asyncio.run(check_platforms_cli())
        if args.platforms_report:
            import json
            from pathlib import Path

            Path(args.platforms_report).write_text(json.dumps(report, indent=2), encoding="utf-8")
        return

    if args.load_demo:
        asyncio.run(load_demo_cli())
        return

    if args.query:
        if not args.on:
            parser.error("--query needs --on <investigation id or exported JSON file>")
        raise SystemExit(asyncio.run(query_cli(args.query, args.on, args.query_json)))

    if args.create_api_key:
        asyncio.run(create_api_key_cli(args.create_api_key, args.role))
        return

    if args.generate_licence_keys:
        from argus.accounts.licence import generate_keypair

        private, public = generate_keypair()
        console.print("[bold]Account service[/bold] (keep secret): ARGUS_LICENCE_SIGNING_KEY=" + private)
        console.print("[bold]Argus Personal[/bold] (safe to publish): ARGUS_LICENCE_PUBLIC_KEY=" + public)
        return

    if args.personal:
        run_personal(args.port)
        return

    if args.serve or (not args.target and "--serve" in sys.argv):
        import uvicorn

        console.print(BANNER)
        console.print(
            f"[bold cyan]Starting Argus Web Interface & Graph Server on http://{args.host}:{args.port}[/bold cyan]"
        )
        # Argus writes its own access log (route templates, request ids, no query strings).
        uvicorn.run("argus.api.server:app", host=args.host, port=args.port, reload=False, access_log=False)
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    mods = [m.strip() for m in args.modules.split(",")] if args.modules else None
    asyncio.run(
        run_cli_scan(
            target=args.target,
            entity_type_str=args.type,
            max_depth=args.depth,
            enabled_modules=mods,
            export_json=args.export_json,
            export_csv=args.export_csv,
            allow_private=args.allow_private,
            passive_only=args.passive_only,
        )
    )


if __name__ == "__main__":
    cli_entrypoint()
