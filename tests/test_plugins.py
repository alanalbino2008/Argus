"""Plugin system: allowlisting, validation, failure isolation, auditing."""

from importlib.metadata import EntryPoint

import pytest

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.models import Entity, EntityType, ScanConfig
from argus.core.settings import get_settings
from argus.modules import get_default_modules, get_module_catalog, plugin_report
from argus.modules import plugins as plugin_loader
from argus.modules.base import BaseModule


class GoodPlugin(BaseModule):
    name = "good_plugin"
    description = "Example third-party collector"
    supported_entity_types = [EntityType.DOMAIN]
    attack_techniques = ("T1596.001",)

    async def run(self, entity, session, config):
        yield Entity.create(EntityType.SUBDOMAIN, f"plugin.{entity.value}", depth=entity.depth + 1)


class ShadowsBuiltin(GoodPlugin):
    name = "dns_recon"


class InventsTechniques(GoodPlugin):
    name = "bad_attack"
    attack_techniques = ("T9999",)


class NotAModule:
    name = "not_a_module"


ENTRY_POINTS = {
    "good": "tests.test_plugins:GoodPlugin",
    "shadow": "tests.test_plugins:ShadowsBuiltin",
    "invents": "tests.test_plugins:InventsTechniques",
    "notmodule": "tests.test_plugins:NotAModule",
    "broken": "tests.does_not_exist:Nothing",
}


@pytest.fixture
def installed(monkeypatch):
    eps = [EntryPoint(name=n, value=v, group=plugin_loader.ENTRY_POINT_GROUP) for n, v in ENTRY_POINTS.items()]
    monkeypatch.setattr(
        plugin_loader, "entry_points", lambda group: eps if group == plugin_loader.ENTRY_POINT_GROUP else []
    )

    def allow(*names):
        monkeypatch.setenv("ARGUS_PLUGINS", "[" + ",".join(f'"{n}"' for n in names) + "]")
        get_settings.cache_clear()

    yield allow
    get_settings.cache_clear()


def test_installed_plugins_do_nothing_unless_allowlisted(installed):
    installed()  # empty allowlist
    assert "good_plugin" not in get_module_catalog()
    report = plugin_report()
    assert report.loaded == {} and sorted(report.available) == sorted(ENTRY_POINTS)


def test_allowlisted_plugin_loads_and_runs(installed):
    installed("good")
    modules = get_default_modules()
    assert modules["good_plugin"].origin == "plugin:tests.test_plugins:GoodPlugin"


async def test_plugin_runs_inside_the_engine(installed):
    installed("good")
    engine = ArgusEngine(
        ScanConfig(target="example.com", target_type=EntityType.DOMAIN, max_depth=1),
        bus=EventBus(),
        modules={"good_plugin": get_default_modules()["good_plugin"]},
    )
    graph = await engine.start()
    assert "plugin.example.com" in {e.value for e in graph.get_all_entities()}


@pytest.mark.parametrize(
    "name,reason",
    [
        ("shadow", "shadow a built-in"),
        ("invents", "unknown ATT&CK technique"),
        ("notmodule", "not a BaseModule subclass"),
        ("broken", "failed to import"),
    ],
)
def test_bad_plugins_are_rejected_without_breaking_argus(installed, name, reason):
    installed(name, "good")
    report = plugin_report()
    assert reason in report.errors[name]
    assert "good_plugin" in report.loaded  # the good one still loads
    assert get_module_catalog()["dns_recon"].origin == "builtin"  # built-in never replaced


def test_allowlisted_but_missing_plugin_is_reported(installed):
    installed("ghost")
    assert "no such plugin is installed" in plugin_report().errors["ghost"]


def test_plugins_endpoint_and_startup_audit(installed, make_client):
    installed("good", "broken")
    client = make_client(plugins='["good","broken"]')
    status = client.get("/api/plugins").json()
    assert status["loaded"] == {"good_plugin": "tests.test_plugins:GoodPlugin"}
    assert "broken" in status["errors"]
    audit = {(e["action"], e["resource"]) for e in client.get("/api/audit").json()}
    assert ("plugin.loaded", "good_plugin") in audit and ("plugin.rejected", "broken") in audit
    modules = {m["name"]: m for m in client.get("/api/modules").json()}
    assert modules["good_plugin"]["origin"].startswith("plugin:")
