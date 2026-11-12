"""Unit tests for Argus Pydantic data schemas."""

import pytest
from argus.core.models import (
    Entity,
    EntityType,
    Relation,
    RelationType,
    ScanConfig,
    generate_entity_id,
)


def test_deterministic_entity_id():
    id1 = generate_entity_id(EntityType.DOMAIN, "example.com")
    id2 = generate_entity_id(EntityType.DOMAIN, "EXAMPLE.COM ")
    assert id1 == id2
    assert id1.startswith("domain_")


def test_entity_creation():
    entity = Entity.create(
        entity_type=EntityType.USERNAME,
        value="testuser",
        label="Test User",
        metadata={"platform": "github"},
        source_module="username_hunter",
        confidence=0.9,
    )
    assert entity.type == EntityType.USERNAME
    assert entity.value == "testuser"
    assert entity.confidence == 0.9
    assert entity.metadata["platform"] == "github"


def test_relation_creation():
    src_id = generate_entity_id(EntityType.DOMAIN, "example.com")
    tgt_id = generate_entity_id(EntityType.IP_ADDRESS, "93.184.216.34")

    rel = Relation.create(
        source_id=src_id,
        target_id=tgt_id,
        rel_type=RelationType.RESOLVES_TO,
        label="DNS A Record",
    )
    assert rel.source_id == src_id
    assert rel.target_id == tgt_id
    assert rel.type == RelationType.RESOLVES_TO
    assert rel.label == "DNS A Record"
    assert rel.id is not None


def test_scan_config_validation():
    config = ScanConfig(
        target="test.org",
        target_type=EntityType.DOMAIN,
        max_depth=3,
        concurrency_limit=10,
    )
    assert config.target == "test.org"
    assert config.max_depth == 3
    assert config.concurrency_limit == 10
