"""Tests for new modules: Shodan InternetDB, GitHub hunter, and phone recon."""

from argus.cli.console import detect_target_type
from argus.core.models import EntityType
from argus.modules.identity.phone_recon import PhoneReconModule
from argus.modules.infrastructure.shodan_internetdb import ShodanInternetDbModule


def test_detect_phone_target_type():
    assert detect_target_type("+44 7911 123456") == EntityType.PHONE
    assert detect_target_type("+1 202-555-0199") == EntityType.PHONE


def test_shodan_internetdb_module_metadata():
    mod = ShodanInternetDbModule()
    assert mod.name == "shodan_internetdb"
    assert EntityType.IP_ADDRESS in mod.supported_entity_types
    assert 443 in mod.PORT_SERVICE_MAP
    assert mod.PORT_SERVICE_MAP[443] == "HTTPS"


def test_phone_recon_prefix_mapping():
    mod = PhoneReconModule()
    assert mod.name == "phone_recon"
    assert EntityType.PHONE in mod.supported_entity_types
