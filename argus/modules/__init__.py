"""Module loader and registry for Argus OSINT framework."""

from argus.modules.base import BaseModule
from argus.modules.identity.email_recon import EmailReconModule
from argus.modules.identity.github_hunter import GitHubHunterModule
from argus.modules.identity.phone_recon import PhoneReconModule
from argus.modules.identity.profile_enricher import ProfileEnricherModule
from argus.modules.identity.username_hunter import UsernameHunterModule
from argus.modules.infrastructure.dns_recon import DnsReconModule
from argus.modules.infrastructure.http_fingerprint import HttpFingerprintModule
from argus.modules.infrastructure.ip_intelligence import IpIntelligenceModule
from argus.modules.infrastructure.shodan_internetdb import ShodanInternetDbModule
from argus.modules.infrastructure.software_intel import SoftwareIntelModule
from argus.modules.infrastructure.subdomain_finder import SubdomainFinderModule
from argus.modules.infrastructure.tls_analyzer import TlsAnalyzerModule
from argus.modules.infrastructure.whois_lookup import WhoisLookupModule
from argus.modules.plugins import PluginReport, discover_plugins
from argus.modules.threat_intel.hibp import HibpModule
from argus.modules.threat_intel.shodan_host import ShodanHostModule
from argus.modules.threat_intel.virustotal import VirusTotalModule

ALL_MODULE_CLASSES: list[type[BaseModule]] = [
    UsernameHunterModule,
    ProfileEnricherModule,
    EmailReconModule,
    GitHubHunterModule,
    PhoneReconModule,
    DnsReconModule,
    SubdomainFinderModule,
    IpIntelligenceModule,
    ShodanInternetDbModule,
    WhoisLookupModule,
    TlsAnalyzerModule,
    HttpFingerprintModule,
    SoftwareIntelModule,
    # Optional: enabled only when their API key is configured
    VirusTotalModule,
    HibpModule,
    ShodanHostModule,
]


def _all_classes() -> list[type[BaseModule]]:
    plugins, _ = discover_plugins({cls.name for cls in ALL_MODULE_CLASSES})
    return [*ALL_MODULE_CLASSES, *plugins]


def get_default_modules() -> dict[str, BaseModule]:
    """Instantiate every module that can run (API-key modules only when their key is set)."""
    return {cls.name: cls() for cls in _all_classes() if cls.is_configured()}


def get_module_catalog() -> dict[str, BaseModule]:
    """Every known module, configured or not (for listings and validation)."""
    return {cls.name: cls() for cls in _all_classes()}


def plugin_report() -> PluginReport:
    """Which plugins are allowlisted, loaded, rejected (and why) or merely installed."""
    return discover_plugins({cls.name for cls in ALL_MODULE_CLASSES})[1]
