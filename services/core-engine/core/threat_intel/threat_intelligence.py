from typing import Dict, Any, Optional, List, Set, Union
import json
import hashlib
import ipaddress
import aiohttp
import asyncio
import re
from datetime import datetime, timedelta
import os
from utils.logger import get_logger
from config import settings
import urllib.parse
import time

logger = get_logger(__name__)

class ThreatIntelligence:
    """
    Integration with Threat Intelligence feeds for IOC enrichment and detection.
    Supports IP addresses, domains, file hashes, and URLs.
    """
    
    def __init__(self, cache_dir: str = None):
        """
        Initialize the Threat Intelligence provider.
        
        Args:
            cache_dir: Directory to cache TI data (defaults to 'cache/threat_intel' under project root)
        """
        self.cache_dir = cache_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cache', 'threat_intel')
        
        # Ensure cache directory exists
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
            
        # Initialize caches
        self.ip_cache = {}
        self.domain_cache = {}
        self.hash_cache = {}
        self.url_cache = {}
        self.cache_expiry = {}
        
        # Configure TI sources
        self.configure_sources()
        
        # Load cached data
        self.load_cache()
        
    def configure_sources(self):
        """Configure threat intelligence sources."""
        # Base configuration for sources
        self.sources = {
            "ip": [
                {
                    "name": "AbuseIPDB",
                    "enabled": True,
                    "url": "https://api.abuseipdb.com/api/v2/check",
                    "api_key": settings.ABUSEIPDB_API_KEY if hasattr(settings, 'ABUSEIPDB_API_KEY') else None,
                    "headers": {"Key": settings.ABUSEIPDB_API_KEY if hasattr(settings, 'ABUSEIPDB_API_KEY') else None},
                    "params": {"ipAddress": "{indicator}", "maxAgeInDays": 90},
                    "response_path": "data",
                    "malicious_check": lambda data: data.get("abuseConfidenceScore", 0) > 80
                },
                {
                    "name": "AlienVault OTX",
                    "enabled": True,
                    "url": "https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general",
                    "api_key": settings.OTX_API_KEY if hasattr(settings, 'OTX_API_KEY') else None,
                    "headers": {"X-OTX-API-KEY": settings.OTX_API_KEY if hasattr(settings, 'OTX_API_KEY') else None},
                    "response_path": None,
                    "malicious_check": lambda data: data.get("pulse_info", {}).get("count", 0) > 0
                },
                {
                    "name": "VirusTotal",
                    "enabled": True,
                    "url": "https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
                    "api_key": settings.VIRUSTOTAL_API_KEY if hasattr(settings, 'VIRUSTOTAL_API_KEY') else None,
                    "headers": {"x-apikey": settings.VIRUSTOTAL_API_KEY if hasattr(settings, 'VIRUSTOTAL_API_KEY') else None},
                    "response_path": "data.attributes",
                    "malicious_check": lambda data: data.get("last_analysis_stats", {}).get("malicious", 0) > 0
                }
            ],
            "domain": [
                {
                    "name": "VirusTotal",
                    "enabled": True,
                    "url": "https://www.virustotal.com/api/v3/domains/{indicator}",
                    "api_key": settings.VIRUSTOTAL_API_KEY if hasattr(settings, 'VIRUSTOTAL_API_KEY') else None,
                    "headers": {"x-apikey": settings.VIRUSTOTAL_API_KEY if hasattr(settings, 'VIRUSTOTAL_API_KEY') else None},
                    "response_path": "data.attributes",
                    "malicious_check": lambda data: data.get("last_analysis_stats", {}).get("malicious", 0) > 0
                },
                {
                    "name": "AlienVault OTX",
                    "enabled": True,
                    "url": "https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general",
                    "api_key": settings.OTX_API_KEY if hasattr(settings, 'OTX_API_KEY') else None,
                    "headers": {"X-OTX-API-KEY": settings.OTX_API_KEY if hasattr(settings, 'OTX_API_KEY') else None},
                    "response_path": None,
                    "malicious_check": lambda data: data.get("pulse_info", {}).get("count", 0) > 0
                }
            ],
            "hash": [
                {
                    "name": "VirusTotal",
                    "enabled": True,
                    "url": "https://www.virustotal.com/api/v3/files/{indicator}",
                    "api_key": settings.VIRUSTOTAL_API_KEY if hasattr(settings, 'VIRUSTOTAL_API_KEY') else None,
                    "headers": {"x-apikey": settings.VIRUSTOTAL_API_KEY if hasattr(settings, 'VIRUSTOTAL_API_KEY') else None},
                    "response_path": "data.attributes",
                    "malicious_check": lambda data: data.get("last_analysis_stats", {}).get("malicious", 0) > 1
                },
                {
                    "name": "AlienVault OTX",
                    "enabled": True,
                    "url": "https://otx.alienvault.com/api/v1/indicators/file/{indicator}/general",
                    "api_key": settings.OTX_API_KEY if hasattr(settings, 'OTX_API_KEY') else None,
                    "headers": {"X-OTX-API-KEY": settings.OTX_API_KEY if hasattr(settings, 'OTX_API_KEY') else None},
                    "response_path": None,
                    "malicious_check": lambda data: data.get("pulse_info", {}).get("count", 0) > 0
                }
            ],
            "url": [
                {
                    "name": "VirusTotal",
                    "enabled": True,
                    "url": "https://www.virustotal.com/api/v3/urls/{indicator}",
                    "api_key": settings.VIRUSTOTAL_API_KEY if hasattr(settings, 'VIRUSTOTAL_API_KEY') else None,
                    "headers": {"x-apikey": settings.VIRUSTOTAL_API_KEY if hasattr(settings, 'VIRUSTOTAL_API_KEY') else None},
                    "response_path": "data.attributes",
                    "malicious_check": lambda data: data.get("last_analysis_stats", {}).get("malicious", 0) > 0,
                    "preprocess": lambda url: hashlib.sha256(url.encode()).hexdigest()
                },
                {
                    "name": "AlienVault OTX",
                    "enabled": True,
                    "url": "https://otx.alienvault.com/api/v1/indicators/url/{indicator}/general",
                    "api_key": settings.OTX_API_KEY if hasattr(settings, 'OTX_API_KEY') else None,
                    "headers": {"X-OTX-API-KEY": settings.OTX_API_KEY if hasattr(settings, 'OTX_API_KEY') else None},
                    "response_path": None,
                    "malicious_check": lambda data: data.get("pulse_info", {}).get("count", 0) > 0,
                    "preprocess": lambda url: urllib.parse.quote_plus(url)
                }
            ]
        }
        
        # Configure OSINT feed sources (no API key required)
        self.osint_feeds = {
            "ip": [
                {
                    "name": "Emerging Threats - Known Compromised IPs",
                    "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                    "format": "line",
                    "cache_path": os.path.join(self.cache_dir, "et_compromised_ips.txt"),
                    "expiry": 24  # hours
                },
                {
                    "name": "Tor Exit Nodes",
                    "url": "https://check.torproject.org/exit-addresses",
                    "format": "line_regex",
                    "regex": r"ExitAddress\s+(\d+\.\d+\.\d+\.\d+)",
                    "cache_path": os.path.join(self.cache_dir, "tor_exit_nodes.txt"),
                    "expiry": 12  # hours
                },
                {
                    "name": "Blocklist.de Attackers",
                    "url": "https://lists.blocklist.de/lists/all.txt",
                    "format": "line",
                    "cache_path": os.path.join(self.cache_dir, "blocklist_de_all.txt"),
                    "expiry": 24  # hours
                }
            ],
            "domain": [
                {
                    "name": "Malware Domain List",
                    "url": "https://www.malwaredomainlist.com/hostslist/hosts.txt",
                    "format": "line_regex",
                    "regex": r"\s+([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})",
                    "cache_path": os.path.join(self.cache_dir, "malware_domain_list.txt"),
                    "expiry": 24  # hours
                }
            ]
        }
    
    def load_cache(self):
        """Load cached threat intelligence data."""
        try:
            # Load IP cache
            ip_cache_path = os.path.join(self.cache_dir, "ip_cache.json")
            if os.path.exists(ip_cache_path):
                with open(ip_cache_path, 'r') as f:
                    self.ip_cache = json.load(f)
                    
            # Load domain cache
            domain_cache_path = os.path.join(self.cache_dir, "domain_cache.json")
            if os.path.exists(domain_cache_path):
                with open(domain_cache_path, 'r') as f:
                    self.domain_cache = json.load(f)
                    
            # Load hash cache
            hash_cache_path = os.path.join(self.cache_dir, "hash_cache.json")
            if os.path.exists(hash_cache_path):
                with open(hash_cache_path, 'r') as f:
                    self.hash_cache = json.load(f)
                    
            # Load URL cache
            url_cache_path = os.path.join(self.cache_dir, "url_cache.json")
            if os.path.exists(url_cache_path):
                with open(url_cache_path, 'r') as f:
                    self.url_cache = json.load(f)
                    
            # Load cache expiry data
            expiry_path = os.path.join(self.cache_dir, "cache_expiry.json")
            if os.path.exists(expiry_path):
                with open(expiry_path, 'r') as f:
                    self.cache_expiry = json.load(f)
                    
            logger.info("Loaded threat intelligence cache")
            
            # Populate OSINT data
            asyncio.create_task(self.update_osint_feeds())
            
        except Exception as e:
            logger.error(f"Error loading threat intelligence cache: {str(e)}")
    
    def save_cache(self):
        """Save cached threat intelligence data."""
        try:
            # Save IP cache
            ip_cache_path = os.path.join(self.cache_dir, "ip_cache.json")
            with open(ip_cache_path, 'w') as f:
                json.dump(self.ip_cache, f)
                
            # Save domain cache
            domain_cache_path = os.path.join(self.cache_dir, "domain_cache.json")
            with open(domain_cache_path, 'w') as f:
                json.dump(self.domain_cache, f)
                
            # Save hash cache
            hash_cache_path = os.path.join(self.cache_dir, "hash_cache.json")
            with open(hash_cache_path, 'w') as f:
                json.dump(self.hash_cache, f)
                
            # Save URL cache
            url_cache_path = os.path.join(self.cache_dir, "url_cache.json")
            with open(url_cache_path, 'w') as f:
                json.dump(self.url_cache, f)
                
            # Save cache expiry data
            expiry_path = os.path.join(self.cache_dir, "cache_expiry.json")
            with open(expiry_path, 'w') as f:
                json.dump(self.cache_expiry, f)
                
            logger.info("Saved threat intelligence cache")
            
        except Exception as e:
            logger.error(f"Error saving threat intelligence cache: {str(e)}")
    
    async def update_osint_feeds(self):
        """Update OSINT feed data."""
        for indicator_type, feeds in self.osint_feeds.items():
            for feed in feeds:
                await self._update_feed(indicator_type, feed)
                
    async def _update_feed(self, indicator_type, feed):
        """
        Update a specific OSINT feed.
        
        Args:
            indicator_type: Type of indicator (ip, domain, hash, url)
            feed: Feed configuration
        """
        cache_path = feed["cache_path"]
        
        # Check if cache file exists and is still valid
        if os.path.exists(cache_path):
            # Check file modification time
            mod_time = os.path.getmtime(cache_path)
            if time.time() - mod_time < feed["expiry"] * 3600:
                logger.debug(f"OSINT feed {feed['name']} is still valid, skipping update")
                return
                
        try:
            logger.info(f"Updating OSINT feed: {feed['name']}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(feed["url"]) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Save raw content to cache
                        with open(cache_path, 'w') as f:
                            f.write(content)
                            
                        logger.info(f"Successfully updated OSINT feed: {feed['name']}")
                    else:
                        logger.warning(f"Failed to update OSINT feed {feed['name']}: HTTP {response.status}")
                        
        except Exception as e:
            logger.error(f"Error updating OSINT feed {feed['name']}: {str(e)}")
    
    async def check_indicator(self, indicator: str, indicator_type: str = None) -> Dict[str, Any]:
        """
        Check an indicator against threat intelligence sources.
        
        Args:
            indicator: The indicator to check (IP, domain, hash, or URL)
            indicator_type: Type of indicator (auto-detected if not specified)
            
        Returns:
            Dictionary with threat intelligence results
        """
        # Auto-detect indicator type if not specified
        if not indicator_type:
            indicator_type = self._detect_indicator_type(indicator)
            
        if not indicator_type:
            logger.warning(f"Could not determine indicator type for: {indicator}")
            return {"indicator": indicator, "is_malicious": False, "sources": []}
            
        # Check cache first
        cache = self._get_cache_for_type(indicator_type)
        if indicator in cache:
            # Check if cache entry is still valid
            expiry = self.cache_expiry.get(f"{indicator_type}:{indicator}")
            if expiry and time.time() < expiry:
                logger.debug(f"Using cached data for {indicator_type} indicator: {indicator}")
                return cache[indicator]
                
        # Check OSINT feeds first (they're faster and don't have rate limits)
        is_malicious, sources = await self._check_osint_feeds(indicator, indicator_type)
        
        # If not found in OSINT feeds, check API sources
        if not is_malicious:
            api_results = await self._check_api_sources(indicator, indicator_type)
            is_malicious = api_results["is_malicious"]
            sources.extend(api_results["sources"])
            
        # Prepare result
        result = {
            "indicator": indicator,
            "type": indicator_type,
            "is_malicious": is_malicious,
            "sources": sources,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Update cache
        cache[indicator] = result
        self.cache_expiry[f"{indicator_type}:{indicator}"] = time.time() + (24 * 3600)  # 24-hour cache
        
        # Save cache periodically (here we just save after each update for simplicity)
        self.save_cache()
        
        return result
    
    def _get_cache_for_type(self, indicator_type):
        """Get the appropriate cache dictionary for an indicator type."""
        if indicator_type == "ip":
            return self.ip_cache
        elif indicator_type == "domain":
            return self.domain_cache
        elif indicator_type == "hash":
            return self.hash_cache
        elif indicator_type == "url":
            return self.url_cache
        else:
            return {}
    
    def _detect_indicator_type(self, indicator):
        """
        Detect the type of an indicator.
        
        Args:
            indicator: The indicator to detect
            
        Returns:
            Indicator type: "ip", "domain", "hash", or "url", or None if not detected
        """
        # Check if it's an IP address
        try:
            ipaddress.ip_address(indicator)
            return "ip"
        except ValueError:
            pass
            
        # Check if it's a domain
        domain_pattern = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')
        if domain_pattern.match(indicator):
            return "domain"
            
        # Check if it's a URL
        url_pattern = re.compile(r'^(http|https|ftp)://.*')
        if url_pattern.match(indicator):
            return "url"
            
        # Check if it's a file hash
        hash_patterns = {
            "md5": re.compile(r'^[a-fA-F0-9]{32}'),    # Fixed
            "sha1": re.compile(r'^[a-fA-F0-9]{40}'),    # Fixed
            "sha256": re.compile(r'^[a-fA-F0-9]{64}')   # Fixed
        }
        
        for hash_type, pattern in hash_patterns.items():
            if pattern.match(indicator):
                return "hash"
                
        return None
    
    async def _check_osint_feeds(self, indicator, indicator_type):
        """
        Check an indicator against OSINT feeds.
        
        Args:
            indicator: The indicator to check
            indicator_type: Type of indicator
            
        Returns:
            Tuple of (is_malicious, sources)
        """
        is_malicious = False
        sources = []
        
        # Check if we have feeds for this indicator type
        if indicator_type not in self.osint_feeds:
            return is_malicious, sources
            
        for feed in self.osint_feeds[indicator_type]:
            cache_path = feed["cache_path"]
            
            # Skip if cache file doesn't exist
            if not os.path.exists(cache_path):
                continue
                
            try:
                with open(cache_path, 'r') as f:
                    content = f.read()
                    
                format_type = feed["format"]
                
                # Process based on format
                if format_type == "line":
                    # Simple line-by-line format
                    if indicator in content.splitlines():
                        is_malicious = True
                        sources.append({
                            "name": feed["name"],
                            "result": "malicious",
                            "description": f"Indicator found in {feed['name']} blocklist"
                        })
                        
                elif format_type == "line_regex":
                    # Line-by-line with regex extraction
                    regex = feed["regex"]
                    matches = re.findall(regex, content)
                    
                    if indicator in matches:
                        is_malicious = True
                        sources.append({
                            "name": feed["name"],
                            "result": "malicious",
                            "description": f"Indicator found in {feed['name']} blocklist"
                        })
                        
            except Exception as e:
                logger.error(f"Error checking OSINT feed {feed['name']}: {str(e)}")
                
        return is_malicious, sources
    
    async def _check_api_sources(self, indicator, indicator_type):
        """
        Check an indicator against API sources.
        
        Args:
            indicator: The indicator to check
            indicator_type: Type of indicator
            
        Returns:
            Dictionary with API results
        """
        is_malicious = False
        sources = []
        
        # If no API key is configured, skip API checks
        if indicator_type not in self.sources:
            return {"is_malicious": is_malicious, "sources": sources}
            
        source_configs = self.sources[indicator_type]
        enabled_sources = [s for s in source_configs if s["enabled"] and s["api_key"]]
        
        if not enabled_sources:
            return {"is_malicious": is_malicious, "sources": sources}
            
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for source in enabled_sources:
                task = self._query_source(session, source, indicator)
                tasks.append(task)
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                source = enabled_sources[i]
                
                if isinstance(result, Exception):
                    logger.error(f"Error querying {source['name']} for {indicator}: {str(result)}")
                    continue
                    
                if result["status"] == "success":
                    sources.append({
                        "name": source["name"],
                        "result": "malicious" if result["malicious"] else "clean",
                        "data": result["data"]
                    })
                    
                    if result["malicious"]:
                        is_malicious = True
                        
                else:
                    logger.warning(f"Failed to query {source['name']} for {indicator}: {result['message']}")
                    
        return {"is_malicious": is_malicious, "sources": sources}
    
    async def _query_source(self, session, source, indicator):
        """
        Query a specific threat intelligence source.
        
        Args:
            session: aiohttp ClientSession
            source: Source configuration
            indicator: Indicator to check
            
        Returns:
            Dictionary with query results
        """
        try:
            # Preprocess indicator if needed
            if "preprocess" in source:
                processed_indicator = source["preprocess"](indicator)
            else:
                processed_indicator = indicator
                
            # Build URL
            url = source["url"].format(indicator=processed_indicator)
            
            # Prepare request parameters
            headers = source["headers"]
            params = source.get("params", {})
            if params:
                # Format parameters
                formatted_params = {}
                for key, value in params.items():
                    if isinstance(value, str) and "{indicator}" in value:
                        formatted_params[key] = value.format(indicator=processed_indicator)
                    else:
                        formatted_params[key] = value
            else:
                formatted_params = None
                
            # Make request
            async with session.get(url, headers=headers, params=formatted_params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Extract data using response_path if specified
                    if source["response_path"]:
                        parts = source["response_path"].split('.')
                        for part in parts:
                            if data and part in data:
                                data = data[part]
                            else:
                                data = {}
                                break
                                
                    # Check if malicious
                    malicious = source["malicious_check"](data)
                    
                    return {
                        "status": "success",
                        "malicious": malicious,
                        "data": data
                    }
                else:
                    return {
                        "status": "error",
                        "message": f"HTTP error {response.status}",
                        "malicious": False,
                        "data": {}
                    }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "malicious": False,
                "data": {}
            }
    
    async def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an event with threat intelligence data.
        
        Args:
            event: The event to enrich
            
        Returns:
            Enriched event with threat intelligence data
        """
        # Clone the event to avoid modifying the original
        enriched_event = event.copy()
        
        # Initialize TI enrichment field
        if "ti_enrichment" not in enriched_event:
            enriched_event["ti_enrichment"] = {
                "indicators": [],
                "is_malicious": False
            }
            
        # Extract indicators from the event
        indicators = self._extract_indicators(event)
        
        # Check each indicator
        for indicator_type, indicator_list in indicators.items():
            for indicator in indicator_list:
                # Check the indicator
                result = await self.check_indicator(indicator, indicator_type)
                
                # Add to enrichment data
                enriched_event["ti_enrichment"]["indicators"].append(result)
                
                # Update overall malicious flag
                if result["is_malicious"]:
                    enriched_event["ti_enrichment"]["is_malicious"] = True
                    
        return enriched_event
    
    def _extract_indicators(self, event: Dict[str, Any]) -> Dict[str, Set[str]]:
        """
        Extract indicators from an event.
        
        Args:
            event: The event to extract indicators from
            
        Returns:
            Dictionary of indicator types to sets of indicators
        """
        indicators = {
            "ip": set(),
            "domain": set(),
            "hash": set(),
            "url": set()
        }
        
        # Extract IPs
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        # Extract domains
        domain_pattern = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b')
        # Extract URLs
        url_pattern = re.compile(r'\b(?:http|https|ftp)://[^\s/$.?#].[^\s]*\b')
        # Extract hashes
        md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        
        # Convert event to JSON string for regex extraction
        event_str = json.dumps(event)
        
        # Extract all indicators using regex
        for ip in ip_pattern.findall(event_str):
            # Validate IP
            try:
                ipaddress.ip_address(ip)
                if not self._is_private_ip(ip):
                    indicators["ip"].add(ip)
            except ValueError:
                pass
                
        for domain in domain_pattern.findall(event_str):
            # Skip domains that are part of URLs
            if f"http://{domain}" in event_str or f"https://{domain}" in event_str:
                continue
            indicators["domain"].add(domain)
            
        for url in url_pattern.findall(event_str):
            indicators["url"].add(url)
            
        for md5 in md5_pattern.findall(event_str):
            indicators["hash"].add(md5)
            
        for sha1 in sha1_pattern.findall(event_str):
            indicators["hash"].add(sha1)
            
        for sha256 in sha256_pattern.findall(event_str):
            indicators["hash"].add(sha256)
            
        # Also look for specific fields in the event
        data = event.get('data', {})
        
        # Network events
        src_ip = data.get('src_ip')
        if src_ip and self._is_valid_ip(src_ip) and not self._is_private_ip(src_ip):
            indicators["ip"].add(src_ip)
            
        dst_ip = data.get('dst_ip')
        if dst_ip and self._is_valid_ip(dst_ip) and not self._is_private_ip(dst_ip):
            indicators["ip"].add(dst_ip)
            
        # Domain and URL events
        domain = data.get('domain')
        if domain and self._is_valid_domain(domain):
            indicators["domain"].add(domain)
            
        url = data.get('url')
        if url and self._is_valid_url(url):
            indicators["url"].add(url)
            
        # File events
        file_hash = data.get('file_hash')
        if file_hash and self._is_valid_hash(file_hash):
            indicators["hash"].add(file_hash)
            
        return indicators
    
    def _is_valid_ip(self, ip):
        """Check if an IP address is valid."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def _is_private_ip(self, ip):
        """Check if an IP address is private/internal."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
            
    def _is_valid_domain(self, domain):
        """Check if a domain is valid."""
        domain_pattern = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')
        return bool(domain_pattern.match(domain))
        
    def _is_valid_url(self, url):
        """Check if a URL is valid."""
        url_pattern = re.compile(r'^(?:http|https|ftp)://.*')
        return bool(url_pattern.match(url))
        
    def _is_valid_hash(self, hash_str):
        """Check if a string is a valid hash."""
        hash_patterns = {
            "md5": re.compile(r'^[a-fA-F0-9]{32}$'),
            "sha1": re.compile(r'^[a-fA-F0-9]{40}$'),
            "sha256": re.compile(r'^[a-fA-F0-9]{64}$')
         
        }
        
        for hash_type, pattern in hash_patterns.items():
            if pattern.match(hash_str):
                return True
                
        return False


class ThreatIntelligenceDetector:
    """
    Detector that uses Threat Intelligence to identify threats.
    """
    
    def __init__(self):
        """Initialize the Threat Intelligence detector."""
        self.ti_provider = ThreatIntelligence()
        
    async def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect threats in an event using Threat Intelligence.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result if a threat is found, None otherwise
        """
        # Enrich the event with threat intelligence
        enriched_event = await self.ti_provider.enrich_event(event)
        
        # Check if any indicators were found to be malicious
        if enriched_event.get("ti_enrichment", {}).get("is_malicious", False):
            # Get all malicious indicators
            malicious_indicators = [
                indicator for indicator in enriched_event["ti_enrichment"]["indicators"]
                if indicator["is_malicious"]
            ]
            
            if not malicious_indicators:
                return None
                
            # Determine the highest severity based on indicator types
            severity = "medium"  # Default
            if any(ind["type"] == "ip" for ind in malicious_indicators):
                if any(ind["type"] == "hash" for ind in malicious_indicators):
                    severity = "critical"
                else:
                    severity = "high"
                    
            # Create detection result
            indicator_str = ", ".join([f"{ind['indicator']} ({ind['type']})" for ind in malicious_indicators])
            
            source_list = []
            for indicator in malicious_indicators:
                for source in indicator["sources"]:
                    if source["result"] == "malicious":
                        source_list.append(f"{source['name']} ({indicator['indicator']})")
                        
            source_str = ", ".join(source_list)
            
            # Get potential MITRE ATT&CK mappings
            mitre_tactics = []
            mitre_techniques = []
            
            # Add IP-based tactics/techniques
            if any(ind["type"] == "ip" for ind in malicious_indicators):
                mitre_tactics.append("TA0011")  # Command and Control
                mitre_techniques.append("T1071")  # Standard Application Layer Protocol
                
            # Add URL/domain-based tactics/techniques
            if any(ind["type"] in ["url", "domain"] for ind in malicious_indicators):
                mitre_tactics.append("TA0011")  # Command and Control
                mitre_tactics.append("TA0001")  # Initial Access
                mitre_techniques.append("T1071")  # Standard Application Layer Protocol
                mitre_techniques.append("T1566")  # Phishing
                
            # Add hash-based tactics/techniques
            if any(ind["type"] == "hash" for ind in malicious_indicators):
                mitre_tactics.append("TA0002")  # Execution
                mitre_techniques.append("T1204")  # User Execution
                
            # Remove duplicates
            mitre_tactics = list(set(mitre_tactics))
            mitre_techniques = list(set(mitre_techniques))
            
            return {
                "name": "Threat Intelligence Match",
                "description": f"Event contains malicious indicators: {indicator_str}",
                "severity": severity,
                "detection_type": "threat_intel",
                "confidence": 0.9,  # High confidence for TI matches
                "details": {
                    "indicators": malicious_indicators,
                    "source": source_str
                },
                "tags": ["threat-intelligence", "ioc", "external-threat"],
                "mitre_tactics": mitre_tactics,
                "mitre_techniques": mitre_techniques
            }
            
        return None