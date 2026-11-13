"""Knowledge graph storage and link analysis engine for Argus.

Uses NetworkX for in-memory graph representation, topological queries,
centrality calculations, and serialization for Cytoscape.js and Maltego.
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any

import networkx as nx

from argus.core.models import Entity, Relation

logger = logging.getLogger("argus.graph")


class IntelligenceGraph:
    """Manages the OSINT knowledge graph, entity deduplication, and link analysis."""

    def __init__(self, investigation_id: str = "default"):
        self.investigation_id = investigation_id
        self._graph = nx.MultiDiGraph()
        self._entities: dict[str, Entity] = {}
        self._relations: dict[str, Relation] = {}
        self._seed_ids: set[str] = set()

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def add_entity(self, entity: Entity, is_seed: bool = False) -> bool:
        """Add an entity node to the graph. Returns True if node was newly created."""
        is_new = entity.id not in self._entities
        if is_seed:
            self._seed_ids.add(entity.id)

        if is_new:
            self._entities[entity.id] = entity
            self._graph.add_node(
                entity.id,
                type=entity.type.value,
                value=entity.value,
                label=entity.label,
                source_module=entity.source_module,
                confidence=entity.confidence,
                depth=entity.depth,
                metadata=entity.metadata,
                first_seen=entity.first_seen.isoformat(),
            )
        else:
            # Merge metadata if entity already exists
            existing = self._entities[entity.id]
            existing.metadata.update(entity.metadata)
            self._graph.nodes[entity.id]["metadata"].update(entity.metadata)
            if entity.depth < existing.depth:
                existing.depth = entity.depth
                self._graph.nodes[entity.id]["depth"] = entity.depth

        return is_new

    def get_entity(self, entity_id: str) -> Entity | None:
        """Retrieve an entity by its unique ID."""
        return self._entities.get(entity_id)

    def get_all_entities(self) -> list[Entity]:
        """Return all entities in the graph."""
        return list(self._entities.values())

    def add_relation(self, relation: Relation) -> bool:
        """Add a directed relationship between two existing entities."""
        # Ensure source and target entities exist in graph
        if relation.source_id not in self._entities or relation.target_id not in self._entities:
            logger.warning(
                "Cannot add relation %s: missing source %s or target %s",
                relation.type,
                relation.source_id,
                relation.target_id,
            )
            return False

        if relation.id in self._relations:
            return False

        self._relations[relation.id] = relation
        self._graph.add_edge(
            relation.source_id,
            relation.target_id,
            key=relation.id,
            relation_type=relation.type.value,
            label=relation.label,
            confidence=relation.confidence,
            metadata=relation.metadata,
        )
        return True

    def get_all_relations(self) -> list[Relation]:
        """Return all relations in the graph."""
        return list(self._relations.values())

    def get_neighbors(self, entity_id: str) -> list[Entity]:
        """Get all entities directly connected to this entity (both in and out)."""
        if entity_id not in self._graph:
            return []
        neighbor_ids = set(self._graph.predecessors(entity_id)) | set(self._graph.successors(entity_id))
        return [self._entities[nid] for nid in neighbor_ids if nid in self._entities]

    def compute_analytics(self) -> dict[str, Any]:
        """Calculate graph metrics: degree centrality, hubs, and clustering."""
        if self.node_count == 0:
            return {
                "node_count": 0,
                "edge_count": 0,
                "entities_by_type": {},
                "top_hubs": [],
                "density": 0.0,
            }

        # Entities distribution by type
        by_type: dict[str, int] = {}
        for entity in self._entities.values():
            t = entity.type.value
            by_type[t] = by_type.get(t, 0) + 1

        # Centrality metrics
        degree_dict = dict(self._graph.degree())
        sorted_nodes = sorted(degree_dict.items(), key=lambda item: item[1], reverse=True)

        top_hubs = []
        for node_id, degree in sorted_nodes[:8]:
            hub = self._entities.get(node_id)
            if hub:
                top_hubs.append(
                    {
                        "id": hub.id,
                        "label": hub.label,
                        "type": hub.type.value,
                        "degree": degree,
                    }
                )

        density = nx.density(self._graph) if self.node_count > 1 else 0.0

        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "entities_by_type": by_type,
            "top_hubs": top_hubs,
            "density": round(density, 4),
        }

    def to_cytoscape_elements(self) -> list[dict[str, Any]]:
        """Serialize graph to Cytoscape.js format for interactive frontend rendering."""
        elements: list[dict[str, Any]] = []

        # Nodes
        for entity_id, entity in self._entities.items():
            degree = self._graph.degree(entity_id) if entity_id in self._graph else 1
            node_data = {
                "id": entity.id,
                "label": entity.label,
                "value": entity.value,
                "type": entity.type.value,
                "confidence": entity.confidence,
                "depth": entity.depth,
                "source_module": entity.source_module,
                "is_seed": entity_id in self._seed_ids,
                "degree": degree,
                "metadata": entity.metadata,
            }
            elements.append({"group": "nodes", "data": node_data})

        # Edges
        for rel in self._relations.values():
            edge_data = {
                "id": rel.id,
                "source": rel.source_id,
                "target": rel.target_id,
                "label": rel.label,
                "type": rel.type.value,
                "confidence": rel.confidence,
            }
            elements.append({"group": "edges", "data": edge_data})

        return elements

    def to_dict(self) -> dict[str, Any]:
        """Export full graph as JSON-serializable dictionary."""
        return {
            "investigation_id": self.investigation_id,
            "nodes": [e.model_dump(mode="json") for e in self._entities.values()],
            "edges": [r.model_dump(mode="json") for r in self._relations.values()],
            "analytics": self.compute_analytics(),
        }

    def to_maltego_csv(self) -> str:
        """Export relationships in a Maltego-compatible tabular CSV structure."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Source Type", "Source Value", "Relationship", "Target Type", "Target Value"])

        for rel in self._relations.values():
            src = self._entities.get(rel.source_id)
            tgt = self._entities.get(rel.target_id)
            if src and tgt:
                writer.writerow(
                    [
                        src.type.value,
                        src.value,
                        rel.type.value,
                        tgt.type.value,
                        tgt.value,
                    ]
                )

        return output.getvalue()
