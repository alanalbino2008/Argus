"""Data models and schemas for Argus OSINT Platform.

Uses Pydantic v2 for high-performance validation, serialization,
and type safety.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """Supported entity categories in the Argus knowledge graph."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    ASN = "asn"
    EMAIL = "email"
    USERNAME = "username"
    SOCIAL_PROFILE = "social_profile"
    PERSON = "person"
    ORGANIZATION = "organization"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    DNS_RECORD = "dns_record"
    PHONE = "phone"
    VULNERABILITY = "vulnerability"
    PORT = "port"
    BREACH = "breach"
    LOCATION = "location"
    GENERIC = "generic"


class RelationType(str, Enum):
    """Semantic relation types between entities."""

    RESOLVES_TO = "RESOLVES_TO"
    SUBDOMAIN_OF = "SUBDOMAIN_OF"
    HOSTED_ON = "HOSTED_ON"
    LOCATED_IN = "LOCATED_IN"
    HAS_ACCOUNT = "HAS_ACCOUNT"
    BELONGS_TO = "BELONGS_TO"
    OPERATES = "OPERATES"
    SECURED_BY = "SECURED_BY"
    USES_TECH = "USES_TECH"
    HAS_DNS_RECORD = "HAS_DNS_RECORD"
    EXPOSES = "EXPOSES"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    EXTRACTED_FROM = "EXTRACTED_FROM"


def generate_entity_id(entity_type: EntityType, value: str) -> str:
    """Generate a deterministic, unique ID for an entity based on type and normalized value."""
    normalized = f"{entity_type.value}:{value.strip().lower()}"
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
    return f"{entity_type.value}_{digest}"


class Entity(BaseModel):
    """Node in the intelligence graph."""

    id: str = Field(description="Deterministic unique identifier")
    type: EntityType = Field(description="Category of intelligence entity")
    value: str = Field(description="Primary value / name / identifier")
    label: str = Field(description="Human-readable label for graph display")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary enriched attributes")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_module: str = Field(default="core", description="Identifier of the module that discovered this entity")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score of entity validity")
    depth: int = Field(default=0, ge=0, description="Hops from original investigation seed")

    @classmethod
    def create(
        cls,
        entity_type: EntityType,
        value: str,
        label: str | None = None,
        metadata: dict[str, Any] | None = None,
        source_module: str = "core",
        confidence: float = 1.0,
        depth: int = 0,
    ) -> Entity:
        """Helper factory to create an entity with an auto-generated deterministic ID."""
        val_clean = value.strip()
        e_id = generate_entity_id(entity_type, val_clean)
        display_label = label or val_clean
        return cls(
            id=e_id,
            type=entity_type,
            value=val_clean,
            label=display_label,
            metadata=metadata or {},
            source_module=source_module,
            confidence=confidence,
            depth=depth,
        )


class Relation(BaseModel):
    """Directed edge between two entities in the intelligence graph."""

    id: str = Field(description="Deterministic edge identifier")
    source_id: str = Field(description="Origin entity ID")
    target_id: str = Field(description="Destination entity ID")
    type: RelationType = Field(description="Semantic link type")
    label: str = Field(description="Display label on edge")
    metadata: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def create(
        cls,
        source_id: str,
        target_id: str,
        rel_type: RelationType,
        label: str | None = None,
        metadata: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ) -> Relation:
        rel_label = label or rel_type.value
        edge_key = f"{source_id}->{rel_type.value}->{target_id}"
        edge_id = hashlib.sha256(edge_key.encode("utf-8")).hexdigest()[:12]
        return cls(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            type=rel_type,
            label=rel_label,
            metadata=metadata or {},
            confidence=confidence,
        )


class ScanConfig(BaseModel):
    """Configuration passed to the Argus engine to execute an investigation."""

    target: str = Field(description="Target seed value (e.g., domain, username, email, IP)")
    target_type: EntityType = Field(description="Entity type of the target seed")
    max_depth: int = Field(default=2, ge=0, le=4, description="Maximum recursive enrichment hops")
    enabled_modules: list[str] | None = Field(
        default=None, description="Subset of module names to execute, or None for all"
    )
    concurrency_limit: int = Field(default=15, ge=1, le=50, description="Max concurrent async workers")
    rate_limit_delay: float = Field(
        default=0.05, ge=0.0, description="Sleep interval between queries per worker in seconds"
    )
    timeout_seconds: float = Field(default=12.0, ge=1.0, description="Network timeout per request")
    module_timeout_seconds: float = Field(
        default=120.0, ge=1.0, description="Hard wall-clock limit for one module run on one entity"
    )
    max_retries: int = Field(
        default=3, ge=0, le=10, description="Retries for transient HTTP failures (429/5xx/connection errors)"
    )
    per_host_concurrency: int = Field(
        default=6, ge=1, le=50, description="Max simultaneous requests to any single host"
    )
    max_entities: int = Field(
        default=2000, ge=1, le=100000, description="Safety cap on total graph nodes per investigation"
    )
    allow_private_targets: bool = Field(
        default=False, description="Permit connections to private/internal networks (authorised internal tests only)"
    )
    circuit_breaker_threshold: int = Field(
        default=5, ge=1, description="Consecutive failures before a module is disabled for the rest of the scan"
    )


class InvestigationStatus(str, Enum):
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class Investigation(BaseModel):
    """State of an ongoing or completed investigation."""

    id: str
    name: str
    config: ScanConfig
    status: InvestigationStatus = InvestigationStatus.INITIALIZING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    node_count: int = 0
    edge_count: int = 0
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    module_stats: dict[str, dict[str, Any]] = Field(default_factory=dict)
    http_stats: dict[str, Any] = Field(default_factory=dict)
    truncated: bool = False
    analytics: dict[str, Any] | None = None
    created_by: str | None = None
    purpose: str | None = None
    monitor_id: str | None = None


class SystemMetrics(BaseModel):
    """Real-time performance and graph analytics metrics."""

    total_nodes: int = 0
    total_edges: int = 0
    entities_by_type: dict[str, int] = Field(default_factory=dict)
    active_tasks: int = 0
    completed_modules: int = 0
