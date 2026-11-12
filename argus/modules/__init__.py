"""Module loader and registry for Argus OSINT framework."""

from typing import Dict, List, Type
from argus.modules.base import BaseModule
from argus.modules.identity.username_hunter import UsernameHunterModule
from argus.modules.identity.email_recon import EmailReconModule
from argus.modules.infrastructure.dns_recon import DnsReconModule
from argus.modules.infrastructure.subdomain_finder import SubdomainFinderModule
from argus.modules.infrastructure.ip_intelligence import IpIntelligenceModule
from argus.modules.infrastructure.whois_lookup import WhoisLookupModule
from argus.modules.infrastructure.tls_analyzer import TlsAnalyzerModule
from argus.modules.infrastructure.http_fingerprint import HttpFingerprintModule
from argus.modules.infrastructure.shodan_internetdb import ShodanInternetDbModule
from argus.modules.identity.github_hunter import GitHubHunterModule
from argus.modules.identity.phone_recon import PhoneReconModule

ALL_MODULE_CLASSES: List[Type[BaseModule]] = [
    UsernameHunterModule,
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
]


def get_default_modules() -> Dict[str, BaseModule]:
    """Instantiate and return mapping of all active reconnaissance modules."""
    return {cls.name: cls() for cls in ALL_MODULE_CLASSES}
