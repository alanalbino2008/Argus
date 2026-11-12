"""Topological graph analysis, hub identification, and threat surface assessment."""

from __future__ import annotations

import logging
from typing import Any, Dict, List
import networkx as nx

from argus.core.graph import IntelligenceGraph
from argus.core.models import EntityType

logger = logging.getLogger("argus.analytics")


class GraphIntelligenceAnalyzer:
    """Performs link analysis, pivotal node detection, and attack surface risk scoring."""

    @staticmethod
    def analyze(graph: IntelligenceGraph) -> Dict[str, Any]:
        """Produce deep intelligence insights from the current graph topology."""
        g = graph._graph
        if g.number_of_nodes() == 0:
            return {"status": "empty"}

        # 1. Degree Centrality (Top Hubs / Pivots)
        degree_dict = dict(g.degree())
        sorted_degrees = sorted(degree_dict.items(), key=lambda x: x[1], reverse=True)
        hubs = []
        for nid, deg in sorted_degrees[:5]:
            e = graph.get_entity(nid)
            if e:
                hubs.append({
                    "id": nid,
                    "label": e.label,
                    "type": e.type.value,
                    "connections": deg,
                })

        # 2. Bridge Nodes (Cross-cluster pivots, e.g., emails connecting domains to persons)
        undirected_g = g.to_undirected()
        components = list(nx.connected_components(undirected_g))

        # 3. Attack Surface & Threat Exposure Metric
        exposure_points = 0
        risk_flags: List[str] = []

        for entity in graph.get_all_entities():
            # Flag subdomains as potential attack vectors
            if entity.type == EntityType.SUBDOMAIN:
                exposure_points += 2

            # Flag poor security headers
            grade = entity.metadata.get("security_headers_grade")
            if grade in ("D", "F"):
                exposure_points += 10
                risk_flags.append(f"Insecure HTTP security posture (Grade {grade}) on {entity.label}")

            # Flag disposable email
            if entity.type == EntityType.DOMAIN and entity.metadata.get("is_disposable_provider"):
                exposure_points += 15
                risk_flags.append(f"Associated with disposable/temporary email provider {entity.label}")

            # Flag missing DMARC
            if entity.type == EntityType.DOMAIN and "has_valid_mx" in entity.metadata:
                if not entity.metadata.get("has_valid_mx"):
                    risk_flags.append(f"Domain {entity.label} lacks operational MX records")

        # Determine surface score 0-100
        threat_score = min(100, max(10, exposure_points))

        return {
            "node_count": g.number_of_nodes(),
            "edge_count": g.number_of_edges(),
            "connected_components_count": len(components),
            "top_pivots": hubs,
            "threat_exposure_score": threat_score,
            "risk_flags": risk_flags[:10],
            "density": round(nx.density(g), 4),
        }
