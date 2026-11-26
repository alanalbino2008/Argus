"""Module loader and registry for Argus OSINT framework."""

from argus.modules.base import BaseModule
from argus.modules.corporate.companies_house import CompaniesHouseModule
from argus.modules.corporate.europe import FinlandRegistryModule, FranceRegistryModule, NorwayRegistryModule
from argus.modules.corporate.opencorporates import OpenCorporatesModule
from argus.modules.corporate.registers import GleifModule, OffshoreLeaksModule, SanctionsScreenModule, SecEdgarModule
from argus.modules.crypto.bitcoin import BitcoinWalletModule
from argus.modules.crypto.evm import EvmWalletModule
from argus.modules.discovery.cloud_storage import CloudStorageModule
from argus.modules.discovery.code_leaks import CodeLeaksModule
from argus.modules.discovery.document_metadata import DocumentMetadataModule
from argus.modules.discovery.passive_dns import PassiveDnsModule
from argus.modules.discovery.site_crawler import SiteCrawlerModule
from argus.modules.discovery.wayback import WaybackModule
from argus.modules.discovery.web_recon import WebReconModule
from argus.modules.identity.email_recon import EmailReconModule
from argus.modules.identity.git_identity import GitIdentityModule
from argus.modules.identity.github_hunter import GitHubHunterModule
from argus.modules.identity.github_org import GitHubOrgModule
from argus.modules.identity.name_guesser import NameGuesserModule
from argus.modules.identity.pgp_keyserver import PgpKeyserverModule
from argus.modules.identity.phone_recon import PhoneReconModule
from argus.modules.identity.profile_enricher import ProfileEnricherModule
from argus.modules.identity.profile_history import ProfileHistoryModule
from argus.modules.identity.profile_viewer import ProfileViewerModule
from argus.modules.identity.public_records import DeveloperFootprintModule, PublicRecordsModule
from argus.modules.identity.social_pages import SocialPagesModule
from argus.modules.identity.username_hunter import UsernameHunterModule
from argus.modules.identity.web_mentions import WebMentionsModule
from argus.modules.infrastructure.dns_recon import DnsReconModule
from argus.modules.infrastructure.favicon import FaviconPivotModule
from argus.modules.infrastructure.http_fingerprint import HttpFingerprintModule
from argus.modules.infrastructure.ip_intelligence import IpIntelligenceModule
from argus.modules.infrastructure.network_ranges import NetworkRangesModule
from argus.modules.infrastructure.server_fingerprints import JarmModule, SshFingerprintModule
from argus.modules.infrastructure.shodan_internetdb import ShodanInternetDbModule
from argus.modules.infrastructure.software_intel import SoftwareIntelModule
from argus.modules.infrastructure.subdomain_finder import SubdomainFinderModule
from argus.modules.infrastructure.tls_analyzer import TlsAnalyzerModule
from argus.modules.infrastructure.whois_lookup import WhoisLookupModule
from argus.modules.legal.courts import CourtRecordsModule
from argus.modules.legal.gazette import GazetteInsolvencyModule
from argus.modules.plugins import PluginReport, discover_plugins
from argus.modules.threat_intel.hibp import HibpModule
from argus.modules.threat_intel.infrastructure_pivot import InfrastructurePivotModule
from argus.modules.threat_intel.lookalike_domains import LookalikeDomainsModule
from argus.modules.threat_intel.shodan_host import ShodanHostModule
from argus.modules.threat_intel.virustotal import VirusTotalModule

ALL_MODULE_CLASSES: list[type[BaseModule]] = [
    CompaniesHouseModule,
    GleifModule,
    FranceRegistryModule,
    NorwayRegistryModule,
    FinlandRegistryModule,
    OpenCorporatesModule,
    GazetteInsolvencyModule,
    CourtRecordsModule,
    SecEdgarModule,
    OffshoreLeaksModule,
    SanctionsScreenModule,
    BitcoinWalletModule,
    EvmWalletModule,
    UsernameHunterModule,
    ProfileEnricherModule,
    EmailReconModule,
    GitHubHunterModule,
    GitIdentityModule,
    NameGuesserModule,
    PublicRecordsModule,
    DeveloperFootprintModule,
    ProfileHistoryModule,
    SocialPagesModule,
    ProfileViewerModule,
    GitHubOrgModule,
    PgpKeyserverModule,
    PhoneReconModule,
    DnsReconModule,
    LookalikeDomainsModule,
    InfrastructurePivotModule,
    SubdomainFinderModule,
    PassiveDnsModule,
    WaybackModule,
    DocumentMetadataModule,
    IpIntelligenceModule,
    ShodanInternetDbModule,
    WhoisLookupModule,
    TlsAnalyzerModule,
    HttpFingerprintModule,
    FaviconPivotModule,
    JarmModule,
    SshFingerprintModule,
    SoftwareIntelModule,
    WebReconModule,
    SiteCrawlerModule,
    CloudStorageModule,
    # Optional: enabled only when their API key is configured
    VirusTotalModule,
    HibpModule,
    ShodanHostModule,
    CodeLeaksModule,
    WebMentionsModule,
    NetworkRangesModule,
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
