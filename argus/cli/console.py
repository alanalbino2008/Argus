"""Command-line interface (CLI) for Argus OSINT Platform with Rich styling."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import re
import sys
from pathlib import Path

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

    # 2. Email Address
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", target_clean):
        return EntityType.EMAIL

    # 3. Domain or Subdomain
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target_clean) and not target_clean.startswith("@"):
        return EntityType.DOMAIN

    # 4. Phone Number
    if re.match(r"^\+?[0-9\s().-]{7,20}$", target_clean) and sum(c.isdigit() for c in target_clean) >= 7:
        return EntityType.PHONE

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
        "--role",
        choices=["viewer", "analyst", "admin"],
        default="analyst",
        help="Role for --create-api-key (default: analyst)",
    )

    args = parser.parse_args()

    if args.create_api_key:
        asyncio.run(create_api_key_cli(args.create_api_key, args.role))
        return

    if args.serve or (not args.target and "--serve" in sys.argv):
        import uvicorn

        console.print(BANNER)
        console.print(
            f"[bold cyan]Starting Argus Web Interface & Graph Server on http://{args.host}:{args.port}[/bold cyan]"
        )
        uvicorn.run("argus.api.server:app", host=args.host, port=args.port, reload=False)
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
        )
    )


if __name__ == "__main__":
    cli_entrypoint()
