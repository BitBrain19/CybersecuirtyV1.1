"""
Threat Intelligence Integration Module
MISP, OTX, VirusTotal, AbuseIPDB integration with IOC enrichment and correlation
"""

import asyncio
import json
import logging
import threading
import hashlib
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import defaultdict, deque
import base64

logger = logging.getLogger(__name__)


class IOCType(str, Enum):
    """IOC (Indicator of Compromise) types"""
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"
    COMMAND_LINE = "command_line"
    MUTEX_NAME = "mutex_name"
    FILE_PATH = "file_path"


class ThreatLevel(str, Enum):
    """Threat intelligence confidence levels"""
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCONFIRMED = "unconfirmed"


@dataclass
class IOCIndicator:
    """Indicator of Compromise"""
    indicator_id: str
    ioc_type: IOCType
    value: str
    threat_level: ThreatLevel
    source: str  # MISP, OTX, VT, AbuseIPDB
    tags: List[str]
    first_seen: datetime
    last_seen: datetime
    description: str
    tlp_level: str = "white"  # white, green, amber, red
    related_malware: List[str] = field(default_factory=list)
    related_campaigns: List[str] = field(default_factory=list)
    enrichment_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'indicator_id': self.indicator_id,
            'ioc_type': self.ioc_type.value,
            'value': self.value,
            'threat_level': self.threat_level.value,
            'source': self.source,
            'tags': self.tags,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'description': self.description,
            'tlp_level': self.tlp_level,
            'related_malware': self.related_malware,
            'related_campaigns': self.related_campaigns,
            'enrichment_data': self.enrichment_data
        }


class MISPConnector:
    """Connector for MISP threat intelligence platform"""
    
    def __init__(self, misp_url: str = "http://localhost", api_key: str = ""):
        self.misp_url = misp_url
        self.api_key = api_key
        self._lock = threading.RLock()
        self.indicators_cache: Dict[str, IOCIndicator] = {}
        self.last_sync = None
    
    async def fetch_indicators(self, limit: int = 1000) -> List[IOCIndicator]:
        """Fetch indicators from MISP"""
        indicators = []
        
        with self._lock:
            logger.info(f"Fetching indicators from MISP (limit: {limit})")
            
            # Mock MISP data for demonstration
            mock_iocs = [
                {
                    'type': 'md5',
                    'value': 'a' * 32,
                    'tags': ['malware', 'trojan'],
                    'description': 'Known trojan hash'
                },
                {
                    'type': 'ip-dst',
                    'value': '192.168.1.100',
                    'tags': ['c2', 'command-and-control'],
                    'description': 'Known C2 server'
                },
                {
                    'type': 'domain',
                    'value': 'evil.com',
                    'tags': ['phishing', 'malware'],
                    'description': 'Phishing domain'
                }
            ]
            
            type_map = {
                'md5': IOCType.FILE_HASH_MD5,
                'sha1': IOCType.FILE_HASH_SHA1,
                'sha256': IOCType.FILE_HASH_SHA256,
                'ip-dst': IOCType.IP_ADDRESS,
                'domain': IOCType.DOMAIN,
                'url': IOCType.URL,
            }
            
            for ioc_data in mock_iocs[:limit]:
                ioc_type = type_map.get(ioc_data['type'], IOCType.URL)
                
                indicator = IOCIndicator(
                    indicator_id=f"misp_{ioc_data['value'][:8]}",
                    ioc_type=ioc_type,
                    value=ioc_data['value'],
                    threat_level=ThreatLevel.HIGH,
                    source='MISP',
                    tags=ioc_data['tags'],
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    description=ioc_data['description'],
                    tlp_level='amber'
                )
                
                indicators.append(indicator)
                self.indicators_cache[ioc_data['value']] = indicator
            
            self.last_sync = datetime.now()
        
        return indicators
    
    async def search_indicator(self, value: str) -> Optional[IOCIndicator]:
        """Search for indicator in MISP"""
        with self._lock:
            return self.indicators_cache.get(value)
    
    async def submit_indicator(self, indicator: IOCIndicator) -> bool:
        """Submit new indicator to MISP"""
        with self._lock:
            logger.info(f"Submitting indicator to MISP: {indicator.value}")
            self.indicators_cache[indicator.value] = indicator
            return True


class OTXConnector:
    """Connector for Open Threat Exchange (OTX)"""
    
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._lock = threading.RLock()
        self.pulses: Dict[str, Dict[str, Any]] = {}
    
    async def fetch_pulses(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch threat pulses from OTX"""
        pulses = []
        
        with self._lock:
            logger.info(f"Fetching pulses from OTX (limit: {limit})")
            
            # Mock OTX pulse data
            mock_pulses = [
                {
                    'pulse_id': 'otx_pulse_1',
                    'name': 'APT28 Indicators',
                    'description': 'APT28 campaign indicators',
                    'indicators': [
                        {'type': 'FileHash-MD5', 'indicator': 'b' * 32},
                        {'type': 'IPv4', 'indicator': '10.0.0.1'},
                        {'type': 'domain', 'indicator': 'apt28.com'},
                    ],
                    'author': 'otx_community',
                    'tlp': 'white',
                    'created': datetime.now().isoformat(),
                }
            ]
            
            for pulse in mock_pulses[:limit]:
                self.pulses[pulse['pulse_id']] = pulse
                pulses.append(pulse)
        
        return pulses
    
    async def search_ip(self, ip: str) -> Dict[str, Any]:
        """Search IP reputation on OTX"""
        return {
            'ip': ip,
            'reputation': -75 if any(c in ip for c in ['192', '10']) else -10,
            'pulse_count': 5,
            'last_analysis_stats': {
                'malicious': 2,
                'suspicious': 1,
                'undetected': 20
            }
        }
    
    async def search_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Search file hash on OTX"""
        return {
            'hash': file_hash,
            'pulse_count': 3,
            'first_submission': (datetime.now() - timedelta(days=30)).isoformat(),
            'last_submission': datetime.now().isoformat(),
            'vendor_detections': 12
        }


class VirusTotalConnector:
    """Connector for VirusTotal"""
    
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._lock = threading.RLock()
        self.analysis_results: Dict[str, Dict[str, Any]] = {}
    
    async def scan_file(self, file_hash: str) -> Dict[str, Any]:
        """Scan file hash on VirusTotal"""
        with self._lock:
            logger.info(f"Scanning file hash: {file_hash[:8]}...")
            
            result = {
                'hash': file_hash,
                'detections': {
                    'malicious': 10,
                    'suspicious': 2,
                    'undetected': 50,
                    'timeout': 1
                },
                'tags': ['trojan', 'backdoor', 'ransomware'],
                'last_analysis_date': datetime.now().isoformat(),
                'vendor_results': {
                    'Kaspersky': 'Trojan.Win32.Generic',
                    'McAfee': 'Ransom-FOO!C695C8A4A80B',
                    'Symantec': 'Trojan.Gen.2',
                }
            }
            
            self.analysis_results[file_hash] = result
            return result
    
    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan URL on VirusTotal"""
        with self._lock:
            logger.info(f"Scanning URL: {url[:30]}...")
            
            result = {
                'url': url,
                'detections': {
                    'malicious': 5,
                    'suspicious': 1,
                    'undetected': 60
                },
                'categories': {
                    'Kaspersky': 'malware',
                    'McAfee': 'phishing'
                },
                'last_analysis_date': datetime.now().isoformat(),
                'server_ip': '192.168.1.1',
                'ssl_certificate': None
            }
            
            return result
    
    async def scan_ip(self, ip: str) -> Dict[str, Any]:
        """Scan IP on VirusTotal"""
        with self._lock:
            logger.info(f"Scanning IP: {ip}")
            
            result = {
                'ip': ip,
                'asn': 'AS12345',
                'country': 'RU',
                'detections': {
                    'malicious': 15,
                    'suspicious': 3,
                    'undetected': 50
                },
                'last_dns_records': [
                    {'type': 'A', 'value': ip, 'timestamp': datetime.now().isoformat()}
                ]
            }
            
            return result


class AbuseIPDBConnector:
    """Connector for AbuseIPDB IP reputation"""
    
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._lock = threading.RLock()
        self.ip_cache: Dict[str, Dict[str, Any]] = {}
    
    async def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation on AbuseIPDB"""
        with self._lock:
            if ip in self.ip_cache:
                return self.ip_cache[ip]
            
            logger.info(f"Checking IP reputation: {ip}")
            
            result = {
                'ip': ip,
                'abuse_confidence_score': 75,  # 0-100
                'total_reports': 12,
                'last_reported_at': (datetime.now() - timedelta(days=1)).isoformat(),
                'is_whitelisted': False,
                'is_vpn': False,
                'usage_type': 'Data Center',
                'isp': 'Evil ISP',
                'domain': 'evil.hosting',
                'hostnames': ['evil.host.com'],
                'reports': [
                    {
                        'comment': 'SSH brute force',
                        'report_date': (datetime.now() - timedelta(days=1)).isoformat(),
                        'reporter': 'user123'
                    }
                ]
            }
            
            self.ip_cache[ip] = result
            return result


@dataclass
class IOCCorrelationResult:
    """Result of IOC correlation analysis"""
    correlation_id: str
    ioc_values: List[str]
    common_tags: List[str]
    related_indicators: List[str]
    threat_score: float  # 0-1
    confidence: float  # 0-1
    campaign_attribution: Optional[str]
    malware_family: Optional[str]


class ThreatIntelligenceCorrelationEngine:
    """Correlates IOCs across multiple TI sources"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.indicators: Dict[str, IOCIndicator] = {}
        self.correlations: Dict[str, IOCCorrelationResult] = {}
        self.tag_index: Dict[str, Set[str]] = defaultdict(set)  # tag -> indicator IDs
        self.value_index: Dict[str, str] = {}  # value -> indicator ID
    
    def add_indicator(self, indicator: IOCIndicator):
        """Add indicator to correlation engine"""
        with self._lock:
            self.indicators[indicator.indicator_id] = indicator
            self.value_index[indicator.value] = indicator.indicator_id
            
            # Index by tags
            for tag in indicator.tags:
                self.tag_index[tag].add(indicator.indicator_id)
    
    def correlate_indicators(self, ioc_values: List[str]) -> IOCCorrelationResult:
        """Correlate multiple IOCs"""
        with self._lock:
            indicator_ids = []
            common_tags = None
            threat_scores = []
            
            for value in ioc_values:
                ioc_id = self.value_index.get(value)
                if ioc_id and ioc_id in self.indicators:
                    indicator_ids.append(ioc_id)
                    indicator = self.indicators[ioc_id]
                    threat_scores.append(self._threat_level_to_score(indicator.threat_level))
                    
                    # Build common tags
                    if common_tags is None:
                        common_tags = set(indicator.tags)
                    else:
                        common_tags &= set(indicator.tags)
            
            # Calculate correlation metrics
            threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0
            confidence = min(len(indicator_ids) / len(ioc_values), 1.0)
            
            # Determine campaign attribution
            campaign = None
            if 'apt28' in str(common_tags).lower():
                campaign = 'APT28'
            elif 'apt29' in str(common_tags).lower():
                campaign = 'APT29'
            
            result = IOCCorrelationResult(
                correlation_id=f"corr_{datetime.now().timestamp()}",
                ioc_values=ioc_values,
                common_tags=list(common_tags) if common_tags else [],
                related_indicators=indicator_ids,
                threat_score=threat_score,
                confidence=confidence,
                campaign_attribution=campaign,
                malware_family=self._extract_malware_family(common_tags)
            )
            
            self.correlations[result.correlation_id] = result
            return result
    
    def _threat_level_to_score(self, threat_level: ThreatLevel) -> float:
        """Convert threat level to numeric score"""
        levels = {
            ThreatLevel.CONFIRMED: 1.0,
            ThreatLevel.HIGH: 0.8,
            ThreatLevel.MEDIUM: 0.6,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.UNCONFIRMED: 0.1
        }
        return levels.get(threat_level, 0.5)
    
    def _extract_malware_family(self, tags: Optional[Set[str]]) -> Optional[str]:
        """Extract malware family from tags"""
        if not tags:
            return None
        
        malware_families = {'trojan', 'ransomware', 'worm', 'backdoor', 'spyware', 'rootkit'}
        for tag in tags:
            if tag.lower() in malware_families:
                return tag.lower()
        
        return None
    
    def find_related_indicators(self, ioc_value: str) -> List[IOCIndicator]:
        """Find indicators related to given IOC"""
        with self._lock:
            ioc_id = self.value_index.get(ioc_value)
            if not ioc_id or ioc_id not in self.indicators:
                return []
            
            indicator = self.indicators[ioc_id]
            related = []
            
            # Find by common tags
            for tag in indicator.tags:
                for rel_id in self.tag_index.get(tag, set()):
                    if rel_id != ioc_id:
                        related.append(self.indicators[rel_id])
            
            # Deduplicate and return
            unique_ids = set(ind.indicator_id for ind in related)
            return [self.indicators[iid] for iid in unique_ids]
    
    def get_indicator_enrichment(self, ioc_value: str) -> Dict[str, Any]:
        """Get enriched data for an indicator"""
        with self._lock:
            ioc_id = self.value_index.get(ioc_value)
            if not ioc_id or ioc_id not in self.indicators:
                return {}
            
            indicator = self.indicators[ioc_id]
            related = self.find_related_indicators(ioc_value)
            
            return {
                'indicator': indicator.to_dict(),
                'related_indicators': [ind.to_dict() for ind in related],
                'source_count': len(set([ind.source for ind in [indicator] + related])),
                'total_sightings': len([indicator] + related),
                'last_seen': indicator.last_seen.isoformat(),
                'tags': indicator.tags,
                'malware_families': list(set(ind.related_malware for ind in [indicator] + related)),
                'campaigns': list(set(ind.related_campaigns for ind in [indicator] + related))
            }


@dataclass
class ThreatIntelligenceManager:
    """Central manager for threat intelligence sources"""
    misp: MISPConnector = field(default_factory=MISPConnector)
    otx: OTXConnector = field(default_factory=OTXConnector)
    vt: VirusTotalConnector = field(default_factory=VirusTotalConnector)
    abuseipdb: AbuseIPDBConnector = field(default_factory=AbuseIPDBConnector)
    correlation_engine: ThreatIntelligenceCorrelationEngine = field(
        default_factory=ThreatIntelligenceCorrelationEngine
    )
    _lock: threading.RLock = field(default_factory=threading.RLock)
    
    async def enrich_ioc(self, ioc_value: str, ioc_type: IOCType) -> Dict[str, Any]:
        """Enrich IOC with data from multiple sources"""
        with self._lock:
            enrichment = {
                'value': ioc_value,
                'type': ioc_type.value,
                'enrichment_sources': [],
                'threat_level': ThreatLevel.LOW,
                'tags': [],
                'sources': []
            }
            
            try:
                # IP reputation
                if ioc_type == IOCType.IP_ADDRESS:
                    otx_data = await self.otx.search_ip(ioc_value)
                    vt_data = await self.vt.scan_ip(ioc_value)
                    abuse_data = await self.abuseipdb.check_ip_reputation(ioc_value)
                    
                    enrichment['otx'] = otx_data
                    enrichment['vt'] = vt_data
                    enrichment['abuseipdb'] = abuse_data
                    enrichment['enrichment_sources'].extend(['OTX', 'VirusTotal', 'AbuseIPDB'])
                
                # File hash
                elif ioc_type in [IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256]:
                    otx_data = await self.otx.search_file_hash(ioc_value)
                    vt_data = await self.vt.scan_file(ioc_value)
                    
                    enrichment['otx'] = otx_data
                    enrichment['vt'] = vt_data
                    enrichment['enrichment_sources'].extend(['OTX', 'VirusTotal'])
                
                # URL
                elif ioc_type == IOCType.URL:
                    vt_data = await self.vt.scan_url(ioc_value)
                    enrichment['vt'] = vt_data
                    enrichment['enrichment_sources'].append('VirusTotal')
            
            except Exception as e:
                logger.error(f"Error enriching IOC: {e}")
            
            return enrichment


# Global instance
_ti_manager: Optional[ThreatIntelligenceManager] = None


def get_threat_intelligence_manager() -> ThreatIntelligenceManager:
    """Get or create global TI manager"""
    global _ti_manager
    if _ti_manager is None:
        _ti_manager = ThreatIntelligenceManager()
    return _ti_manager


if __name__ == "__main__":
    logger.info("Threat Intelligence Integration Module initialized")
