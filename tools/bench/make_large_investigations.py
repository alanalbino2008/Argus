"""Store synthetic, realistically shaped investigations for the large-graph benchmark.

Shape: one domain with N/2 sub-domains (each resolving to one of N/6 IPs, every seventh using one of
30 shared technologies) and the rest as ports on those IPs. Some IPs are resolved by no sub-domain,
leaving small islands, as in real scans.

    python tools/bench/make_large_investigations.py ./bench.db 5000 20000 50000
    ARGUS_DATABASE_URL=sqlite+aiosqlite:///./bench.db ARGUS_BOOTSTRAP_ADMIN_KEY=<key> argus --serve --port 8811
    ARGUS_BENCH_KEY=<key> node tools/bench/large_graph_benchmark.js inv_big5k inv_big20k inv_big50k
"""

from __future__ import annotations

import asyncio
import random
import sys
from datetime import datetime, timezone

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, Investigation, InvestigationStatus, Relation, ScanConfig
from argus.core.models import EntityType as E
from argus.core.models import RelationType as R
from argus.storage import Database, InvestigationRepository
from argus.storage.migrate import upgrade_database

TECHNOLOGIES = 30


def build(investigation_id: str, size: int) -> IntelligenceGraph:
    rng = random.Random(size)  # the same graph every time for a given size
    graph = IntelligenceGraph(investigation_id)
    seed = Entity.create(E.DOMAIN, "big.example", source_module="seed")
    graph.add_entity(seed, is_seed=True)
    techs = [Entity.create(E.TECHNOLOGY, f"tech-{i} 1.{i}", depth=2) for i in range(TECHNOLOGIES)]
    n_ip, n_sub = size // 6, size // 2
    n_port = size - n_ip - n_sub - TECHNOLOGIES - 1
    ips = [Entity.create(E.IP_ADDRESS, f"10.{i // 62500}.{(i // 250) % 250}.{i % 250}", depth=2) for i in range(n_ip)]
    for entity in techs + ips:
        graph.add_entity(entity)
    for i in range(n_sub):
        sub = Entity.create(E.SUBDOMAIN, f"host{i}.zone{i % 40}.big.example", depth=1)
        graph.add_entity(sub)
        graph.add_relation(Relation.create(sub.id, seed.id, R.SUBDOMAIN_OF))
        graph.add_relation(Relation.create(sub.id, rng.choice(ips).id, R.RESOLVES_TO))
        if i % 7 == 0:
            graph.add_relation(Relation.create(sub.id, rng.choice(techs).id, R.USES_TECH))
    for i in range(n_port):
        ip = rng.choice(ips)
        port = Entity.create(
            E.PORT, f"{ip.value}:{1000 + i}", label=f"Port {1000 + i}", depth=3, metadata={"port_number": 1000 + i}
        )
        graph.add_entity(port)
        graph.add_relation(Relation.create(ip.id, port.id, R.EXPOSES))
    return graph


async def main(path: str, sizes: list[int]) -> None:
    db = Database(f"sqlite+aiosqlite:///{path}")
    await upgrade_database(db)
    repo = InvestigationRepository(db)
    for size in sizes:
        investigation_id = f"inv_big{size // 1000}k"
        await repo.delete_investigation(investigation_id)
        graph = build(investigation_id, size)
        investigation = Investigation(
            id=investigation_id,
            name=f"Benchmark {size}",
            config=ScanConfig(target="big.example", target_type=E.DOMAIN),
            status=InvestigationStatus.COMPLETED,
            completed_at=datetime.now(timezone.utc),
            node_count=graph.node_count,
            edge_count=graph.edge_count,
        )
        await repo.save_investigation(investigation)
        await repo.save_graph(graph)
        print(investigation_id, graph.node_count, "entities", graph.edge_count, "relations")
    await db.dispose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], [int(x) for x in sys.argv[2:]]))
