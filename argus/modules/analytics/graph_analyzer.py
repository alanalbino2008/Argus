"""Topological graph analysis, hub identification, and threat surface assessment."""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from argus.core.graph import IntelligenceGraph
from argus.core.models import EntityType

logger = logging.getLogger("argus.analytics")


class GraphIntelligenceAnalyzer:
    """Performs link analysis, pivotal node detection, and attack surface risk scoring."""

    @staticmethod
    def analyze(graph: IntelligenceGraph) -> dict[str, Any]:
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
                hubs.append(
                    {
                        "id": nid,
                        "label": e.label,
                        "type": e.type.value,
                        "connections": deg,
                    }
                )

        # 2. Bridge Nodes (Cross-cluster pivots, e.g., emails connecting domains to persons)
        undirected_g = g.to_undirected()
        components = list(nx.connected_components(undirected_g))

        # 3. Attack Surface & Threat Exposure Metric
        exposure_points = 0
        risk_flags: list[str] = []

        for entity in graph.get_all_entities():
            # Flag CVE vulnerabilities
            if entity.type == EntityType.VULNERABILITY:
                exposure_points += 25
                kev = (entity.metadata.get("intel") or {}).get("kev")
                if kev:  # exploited in the wild: lead the list so it survives truncation
                    exposure_points += 15
                    extra = ", used by ransomware" if kev.get("ransomware") else ""
                    risk_flags.insert(0, f"Actively exploited CVE (CISA KEV{extra}): {entity.label}")
                else:
                    risk_flags.append(f"Known CVE Vulnerability: {entity.label}")

            # Flag software whose vendor no longer ships security fixes
            life = entity.metadata.get("lifecycle") or {}
            if life.get("eol"):
                exposure_points += 12
                since = f" since {life['eol_date']}" if life.get("eol_date") else ""
                risk_flags.append(f"End-of-life software{since}: {life.get('product')} {life.get('version')}")

            # Flag open ports
            if entity.type == EntityType.PORT:
                exposure_points += 3

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

            # Flag domains without working mail exchangers (None = lookup failed, unknown)
            if entity.type == EntityType.DOMAIN and entity.metadata.get("has_valid_mx") is False:
                risk_flags.append(f"Domain {entity.label} lacks operational MX records")

            # Third-party reputation and breach exposure
            vt = entity.metadata.get("virustotal") or {}
            if vt.get("malicious", 0) > 0:
                exposure_points += 15
                risk_flags.append(f"{entity.label} flagged malicious by {vt['malicious']} VirusTotal engine(s)")
            if entity.type == EntityType.BREACH:
                exposure_points += 8
                classes = ", ".join(entity.metadata.get("data_classes", [])[:4]) or "unknown data"
                risk_flags.append(f"Exposed in {entity.value} breach ({classes})")

            # Flag broken TLS hygiene
            if entity.type == EntityType.CERTIFICATE:
                host = entity.metadata.get("observed_on", entity.label)
                if entity.metadata.get("expired"):
                    exposure_points += 10
                    risk_flags.append(f"Expired TLS certificate served on {host}")
                elif entity.metadata.get("self_signed"):
                    exposure_points += 8
                    risk_flags.append(f"Self-signed TLS certificate served on {host}")
                elif 0 <= entity.metadata.get("days_remaining", 999) < 14:
                    exposure_points += 3
                    risk_flags.append(f"TLS certificate on {host} expires in {entity.metadata['days_remaining']} days")

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
