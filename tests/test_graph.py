"""Unit tests for Argus Intelligence Graph and exports."""

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Relation, RelationType


def test_graph_add_entity_and_deduplication():
    graph = IntelligenceGraph("test_inv")

    e1 = Entity.create(EntityType.DOMAIN, "example.com", metadata={"ip": "1.1.1.1"})
    assert graph.add_entity(e1, is_seed=True) is True
    assert graph.node_count == 1

    # Adding again with updated metadata should merge, not duplicate
    e2 = Entity.create(EntityType.DOMAIN, "example.com", metadata={"server": "nginx"})
    assert graph.add_entity(e2) is False
    assert graph.node_count == 1

    retrieved = graph.get_entity(e1.id)
    assert retrieved is not None
    assert retrieved.metadata["ip"] == "1.1.1.1"
    assert retrieved.metadata["server"] == "nginx"


def test_graph_relations_and_neighbors():
    graph = IntelligenceGraph("test_inv")

    dom = Entity.create(EntityType.DOMAIN, "target.com")
    ip = Entity.create(EntityType.IP_ADDRESS, "192.0.2.1")
    graph.add_entity(dom)
    graph.add_entity(ip)

    rel = Relation.create(dom.id, ip.id, RelationType.RESOLVES_TO)
    assert graph.add_relation(rel) is True
    assert graph.edge_count == 1

    neighbors = graph.get_neighbors(dom.id)
    assert len(neighbors) == 1
    assert neighbors[0].id == ip.id


def test_cytoscape_elements_serialization():
    graph = IntelligenceGraph("test_inv")
    dom = Entity.create(EntityType.DOMAIN, "target.com")
    graph.add_entity(dom, is_seed=True)

    elements = graph.to_cytoscape_elements()
    assert len(elements) == 1
    assert elements[0]["group"] == "nodes"
    assert elements[0]["data"]["label"] == "target.com"
    assert elements[0]["data"]["is_seed"] is True


def test_maltego_csv_export():
    graph = IntelligenceGraph("test_inv")
    dom = Entity.create(EntityType.DOMAIN, "target.com")
    ip = Entity.create(EntityType.IP_ADDRESS, "192.0.2.1")
    graph.add_entity(dom)
    graph.add_entity(ip)

    rel = Relation.create(dom.id, ip.id, RelationType.RESOLVES_TO)
    graph.add_relation(rel)

    csv_data = graph.to_maltego_csv()
    assert "Source Type,Source Value,Relationship,Target Type,Target Value" in csv_data
    assert "domain,target.com,RESOLVES_TO,ip_address,192.0.2.1" in csv_data
