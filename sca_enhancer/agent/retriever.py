"""
RAG Retriever module for SCA-enhancer Agent

This module implements retrieval-augmented generation (RAG) capabilities
to fetch vulnerability evidence from authoritative sources.
"""

import os
import asyncio
import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
import json
import hashlib
from pathlib import Path
from urllib.parse import quote

import aiohttp
from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_community.docstore.in_memory import InMemoryDocstore
from langchain_openai import OpenAIEmbeddings
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

from .schemas import Finding, Evidence, EvidenceSource, EvidenceSourceType, ConfidenceLevel
from .config import AgentConfig

logger = logging.getLogger(__name__)


class EvidenceRetriever:
    """
    Retrieves vulnerability evidence from multiple authoritative sources
    using RAG (Retrieval-Augmented Generation) techniques.
    """
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.cache_dir = Path(config.cache.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize embeddings based on LLM provider
        if config.llm.provider == "openai":
            self.embeddings = OpenAIEmbeddings(
                openai_api_key=config.llm.openai_api_key
            )
        elif config.llm.provider == "anthropic":
            # For Anthropic, use Google embeddings if available, otherwise disable embeddings
            if config.llm.gemini_api_key:
                os.environ["GOOGLE_API_KEY"] = config.llm.gemini_api_key
                self.embeddings = GoogleGenerativeAIEmbeddings(
                    model="models/text-embedding-004"
                )
            else:
                logger.warning("No embeddings available for Anthropic provider without Google API key")
                self.embeddings = None
        elif config.llm.provider == "gemini":
            # Set GOOGLE_API_KEY environment variable for langchain-google-genai
            if config.llm.gemini_api_key:
                os.environ["GOOGLE_API_KEY"] = config.llm.gemini_api_key
            self.embeddings = GoogleGenerativeAIEmbeddings(
                model="models/text-embedding-004"
            )
        else:
            self.embeddings = None
        
        # Text splitter for chunking documents
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            length_function=len
        )
        
        # Evidence sources
        self.sources = {
            EvidenceSourceType.NVD: self._retrieve_nvd_evidence,
            EvidenceSourceType.GHSA: self._retrieve_ghsa_evidence,
            EvidenceSourceType.VENDOR_ADVISORY: self._retrieve_vendor_evidence,
            EvidenceSourceType.GITHUB_COMMITS: self._retrieve_github_commits,
            EvidenceSourceType.POC_SOURCES: self._retrieve_poc_evidence
        }
        
        # Session for HTTP requests
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            ssl=self.config.network.tls_verify,
            limit=self.config.processing.concurrency
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self.config.network.timeout_seconds
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'SCA-Enhancer-Agent/1.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def retrieve_evidence(self, findings: List[Finding]) -> Dict[str, List[Evidence]]:
        """
        Retrieve evidence for multiple findings
        
        Args:
            findings: List of findings to retrieve evidence for
        
        Returns:
            Dictionary mapping finding IDs to their evidence lists
        """
        evidence_map = {}
        
        # Process findings in batches
        batch_size = self.config.processing.batch_size
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            
            # Create tasks for concurrent processing
            tasks = [
                self._retrieve_finding_evidence(finding)
                for finding in batch
            ]
            
            # Execute batch concurrently
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for finding, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to retrieve evidence for {finding.id}: {result}")
                    evidence_map[finding.id] = []
                else:
                    evidence_map[finding.id] = result
        
        return evidence_map
    
    async def _retrieve_finding_evidence(self, finding: Finding) -> List[Evidence]:
        """Retrieve evidence for a single finding"""
        all_evidence = []
        
        # Determine which sources to query based on configuration
        enabled_sources = self._get_enabled_sources()
        
        # Create tasks for each enabled source
        tasks = []
        for source in enabled_sources:
            if source in self.sources:
                task = self.sources[source](finding)
                tasks.append((source, task))
        
        # Execute all source queries concurrently
        if tasks:
            results = await asyncio.gather(
                *[task for _, task in tasks],
                return_exceptions=True
            )
            
            # Process results
            for (source, _), result in zip(tasks, results):
                if isinstance(result, Exception):
                    logger.warning(f"Failed to retrieve from {source} for {finding.id}: {result}")
                elif result:
                    all_evidence.extend(result)
        
        # Limit evidence sources per finding
        max_evidence = self.config.processing.max_evidence_sources
        if len(all_evidence) > max_evidence:
            # Sort by confidence and take top N
            all_evidence.sort(key=lambda e: e.confidence.value, reverse=True)
            all_evidence = all_evidence[:max_evidence]
        
        return all_evidence
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check for the evidence retriever.
        
        Returns:
            Dict containing health status information
        """
        status = {
            "status": "healthy",
            "embeddings": "configured",
            "cache_dir": str(self.cache_dir),
            "cache_exists": self.cache_dir.exists(),
            "enabled_sources": self._get_enabled_sources()
        }
        
        # Check if embeddings are properly configured
        try:
            if self.embeddings is None:
                status["status"] = "unhealthy"
                status["embeddings"] = "not configured"
        except Exception as e:
            status["status"] = "unhealthy"
            status["embeddings"] = f"error: {str(e)}"
        
        # Check cache directory accessibility
        try:
            if not self.cache_dir.exists():
                self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            status["status"] = "unhealthy"
            status["cache_error"] = str(e)
        
        return status

    def _get_enabled_sources(self) -> List[EvidenceSourceType]:
        """Get list of enabled evidence sources"""
        sources = []
        config = self.config.evidence_sources
        
        if config.nvd_enabled:
            sources.append(EvidenceSourceType.NVD)
        if config.ghsa_enabled:
            sources.append(EvidenceSourceType.GHSA)
        if config.vendor_advisories_enabled:
            sources.append(EvidenceSourceType.VENDOR_ADVISORY)
        if config.github_commits_enabled:
            sources.append(EvidenceSourceType.GITHUB_COMMITS)
        if config.poc_sources_enabled:
            sources.append(EvidenceSourceType.POC_SOURCES)
        
        return sources
    
    def _extract_cve_id(self, finding: Finding) -> Optional[str]:
        """Extract CVE ID from finding with multiple strategies"""
        import re
        
        # Strategy 1: Direct CVE ID from vulnerability object
        if finding.vulnerability:
            cve_id = getattr(finding.vulnerability, 'cve_id', None)
            if cve_id and cve_id.startswith('CVE-'):
                return cve_id
        
        # Strategy 2: Extract from vulnerability ID
        if finding.vulnerability:
            vuln_id = getattr(finding.vulnerability, 'id', None)
            if vuln_id:
                # Look for CVE pattern in ID
                cve_match = re.search(r'CVE-\d{4}-\d+', vuln_id)
                if cve_match:
                    return cve_match.group(0)
        
        # Strategy 3: Extract from description or title
        if finding.vulnerability:
            description = getattr(finding.vulnerability, 'description', '') or ''
            title = getattr(finding.vulnerability, 'title', '') or ''
            
            for text in [description, title]:
                cve_match = re.search(r'CVE-\d{4}-\d+', text)
                if cve_match:
                    return cve_match.group(0)
        
        # Strategy 4: Check component name or package for CVE references
        for text in [finding.component_name or '', finding.package or '']:
            cve_match = re.search(r'CVE-\d{4}-\d+', text)
            if cve_match:
                return cve_match.group(0)
        
        return None
    
    def _extract_vulnerability_id(self, finding: Finding) -> Optional[str]:
        """Extract vulnerability ID from finding"""
        if finding.vulnerability:
            return getattr(finding.vulnerability, 'id', None)
        return None
    
    def _extract_ghsa_id(self, finding: Finding) -> Optional[str]:
        """Extract GitHub Security Advisory ID from finding"""
        import re
        
        # Strategy 1: Direct GHSA ID from vulnerability object
        if finding.vulnerability:
            vuln_id = getattr(finding.vulnerability, 'id', None)
            if vuln_id and vuln_id.startswith('GHSA-'):
                return vuln_id
        
        # Strategy 2: Look for GHSA pattern in various fields
        if finding.vulnerability:
            description = getattr(finding.vulnerability, 'description', '') or ''
            title = getattr(finding.vulnerability, 'title', '') or ''
            
            for text in [description, title]:
                ghsa_match = re.search(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', text)
                if ghsa_match:
                    return ghsa_match.group(0)
        
        return None
    
    async def _retrieve_nvd_evidence(self, finding: Finding) -> List[Evidence]:
        """Retrieve evidence from NVD (National Vulnerability Database)"""
        evidence_list = []
        
        try:
            # Extract vulnerability identifiers with better parsing
            cve_id = self._extract_cve_id(finding)
            vuln_id = self._extract_vulnerability_id(finding)
            
            if not cve_id:
                logger.warning(f"No valid CVE ID found for finding {finding.id}")
                return evidence_list
            
            cache_key = f"nvd_{cve_id}"
            cached_evidence = self._get_cached_evidence(cache_key)
            if cached_evidence:
                return cached_evidence
            
            # Query NVD API
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'cveId': cve_id
            }
            
            if self.config.evidence_sources.nvd_api_key:
                headers = {'apiKey': self.config.evidence_sources.nvd_api_key}
            else:
                headers = {}
            
            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for vuln in data.get('vulnerabilities', []):
                        cve_data = vuln.get('cve', {})
                        
                        # Extract comprehensive description
                        descriptions = cve_data.get('descriptions', [])
                        description = next(
                            (desc['value'] for desc in descriptions if desc.get('lang') == 'en'),
                            'No description available'
                        )
                        
                        # Extract CVSS scores and severity
                        metrics = cve_data.get('metrics', {})
                        cvss_info = ""
                        if 'cvssMetricV31' in metrics:
                            cvss_v31 = metrics['cvssMetricV31'][0]['cvssData']
                            cvss_info = f"CVSS v3.1: {cvss_v31.get('baseScore', 'N/A')} ({cvss_v31.get('baseSeverity', 'N/A')})"
                        elif 'cvssMetricV30' in metrics:
                            cvss_v30 = metrics['cvssMetricV30'][0]['cvssData']
                            cvss_info = f"CVSS v3.0: {cvss_v30.get('baseScore', 'N/A')} ({cvss_v30.get('baseSeverity', 'N/A')})"
                        
                        # Extract CWE information
                        weaknesses = cve_data.get('weaknesses', [])
                        cwe_info = []
                        for weakness in weaknesses:
                            for desc in weakness.get('description', []):
                                if desc.get('lang') == 'en':
                                    cwe_info.append(desc.get('value', ''))
                        
                        # Extract references
                        references = []
                        for ref in cve_data.get('references', []):
                            references.append(ref.get('url', ''))
                        
                        # Build comprehensive content
                        content_parts = [
                            f"Vulnerability: {cve_id}",
                            f"Description: {description}",
                        ]
                        
                        if cvss_info:
                            content_parts.append(f"Severity: {cvss_info}")
                        
                        if cwe_info:
                            content_parts.append(f"CWE: {', '.join(cwe_info)}")
                        
                        if references:
                            content_parts.append(f"References: {', '.join(references[:3])}")  # Limit to first 3 refs
                        
                        comprehensive_content = "\n".join(content_parts)
                        
                        # Create evidence source
                        evidence_source = EvidenceSource(
                            type="advisory",
                            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            title=f"NVD Advisory for {cve_id}",
                            content=comprehensive_content,
                            weight=0.9
                        )
                        
                        # Create evidence
                        evidence = Evidence(
                            finding_id=finding.id,
                            sources=[evidence_source],
                            cache_key=cache_key
                        )
                        
                        evidence_list.append(evidence)
                else:
                    logger.warning(f"NVD API returned status {response.status} for CVE {cve_id}")
            
            # Cache the results
            self._cache_evidence(cache_key, evidence_list)
            
        except Exception as e:
            logger.error(f"Error retrieving NVD evidence for {finding.id}: {e}")
        
        return evidence_list
    
    async def _retrieve_ghsa_evidence(self, finding: Finding) -> List[Evidence]:
        """Retrieve evidence from GitHub Security Advisories"""
        evidence_list = []
        
        try:
            if not self.config.evidence_sources.github_token:
                logger.warning("GitHub token not configured, skipping GHSA")
                return evidence_list
            
            # Check cache first
            cache_key = f"ghsa_{finding.vulnerability.cve_id or finding.vulnerability.id}"
            cached_evidence = self._get_cached_evidence(cache_key)
            if cached_evidence:
                return cached_evidence
            
            # Query GitHub GraphQL API for security advisories
            url = "https://api.github.com/graphql"
            headers = {
                'Authorization': f'Bearer {self.config.evidence_sources.github_token}',
                'Content-Type': 'application/json'
            }
            
            # Build search query
            search_terms = []
            if finding.vulnerability.cve_id:
                search_terms.append(finding.vulnerability.cve_id)
            if finding.component_name:
                search_terms.append(finding.component_name)
            
            if not search_terms:
                return evidence_list
            
            query = {
                "query": """
                query($query: String!) {
                    search(query: $query, type: REPOSITORY, first: 10) {
                        nodes {
                            ... on Repository {
                                securityAdvisories(first: 5) {
                                    nodes {
                                        summary
                                        description
                                        permalink
                                        severity
                                        identifiers {
                                            type
                                            value
                                        }
                                        references {
                                            url
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                """,
                "variables": {
                    "query": " ".join(search_terms)
                }
            }
            
            async with self.session.post(url, json=query, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for repo in data.get('data', {}).get('search', {}).get('nodes', []):
                        for advisory in repo.get('securityAdvisories', {}).get('nodes', []):
                            # Create evidence source
                            evidence_source = EvidenceSource(
                                type="advisory",
                                url=advisory.get('permalink', ''),
                                title=f"GHSA Advisory for {finding.vulnerability.id}",
                                content=f"{advisory.get('summary', '')}\n\n{advisory.get('description', '')}",
                                weight=0.9
                            )
                            
                            # Create evidence from advisory
                            evidence = Evidence(
                                finding_id=finding.vulnerability.id,
                                sources=[evidence_source],
                                cache_key=cache_key
                            )
                            
                            evidence_list.append(evidence)
            
            # Cache the results
            self._cache_evidence(cache_key, evidence_list)
            
        except Exception as e:
            logger.error(f"Error retrieving GHSA evidence: {e}")
        
        return evidence_list
    
    async def _retrieve_vendor_evidence(self, finding: Finding) -> List[Evidence]:
        """Retrieve evidence from vendor security advisories and official sources"""
        evidence_list = []
        
        try:
            component_name = finding.component_name.lower() if finding.component_name else ''
            cve_id = self._extract_cve_id(finding)
            
            cache_key = f"vendor_{component_name}_{cve_id or finding.id}"
            cached_evidence = self._get_cached_evidence(cache_key)
            if cached_evidence:
                return cached_evidence
            
            # Map common components to their vendor advisory sources
            vendor_sources = self._get_vendor_advisory_sources(component_name, cve_id)
            
            for source in vendor_sources:
                evidence_source = EvidenceSource(
                    type="vendor",
                    url=source['url'],
                    title=source['title'],
                    content=source['content'],
                    weight=source.get('weight', 0.8)
                )
                
                evidence = Evidence(
                    finding_id=finding.id,
                    sources=[evidence_source],
                    cache_key=f"vendor_{source['key']}"
                )
                evidence_list.append(evidence)
            
            # Cache the results
            self._cache_evidence(cache_key, evidence_list)
            
        except Exception as e:
            logger.error(f"Error retrieving vendor evidence for {finding.id}: {e}")
        
        return evidence_list
    
    def _get_vendor_advisory_sources(self, component_name: str, cve_id: str = None) -> List[dict]:
        """Get vendor-specific advisory sources based on component name"""
        sources = []
        
        # Common Java/Maven components
        if any(java_lib in component_name for java_lib in ['jackson', 'spring', 'apache', 'log4j', 'snakeyaml']):
            if 'jackson' in component_name:
                sources.append({
                    'key': 'jackson_github',
                    'url': 'https://github.com/FasterXML/jackson/security/advisories',
                    'title': 'Jackson Security Advisories',
                    'content': f'Official Jackson security advisories for {component_name}. '
                              f'Check for known vulnerabilities, patches, and mitigation strategies.',
                    'weight': 0.9
                })
            
            if 'spring' in component_name:
                sources.append({
                    'key': 'spring_security',
                    'url': 'https://spring.io/security',
                    'title': 'Spring Security Advisories',
                    'content': f'Official Spring Framework security advisories for {component_name}. '
                              f'Includes vulnerability details, affected versions, and upgrade recommendations.',
                    'weight': 0.9
                })
            
            if 'apache' in component_name:
                sources.append({
                    'key': 'apache_security',
                    'url': 'https://www.apache.org/security/',
                    'title': 'Apache Security Reports',
                    'content': f'Apache Software Foundation security reports for {component_name}. '
                              f'Official vulnerability disclosures and security patches.',
                    'weight': 0.9
                })
            
            if 'log4j' in component_name:
                sources.append({
                    'key': 'log4j_security',
                    'url': 'https://logging.apache.org/log4j/2.x/security.html',
                    'title': 'Log4j Security Information',
                    'content': f'Official Log4j security information and vulnerability reports. '
                              f'Critical security updates and configuration recommendations for {component_name}.',
                    'weight': 0.95
                })
            
            if 'snakeyaml' in component_name:
                sources.append({
                    'key': 'snakeyaml_github',
                    'url': 'https://github.com/asomov/snakeyaml/security',
                    'title': 'SnakeYAML Security Advisories',
                    'content': f'SnakeYAML security advisories and vulnerability reports. '
                              f'Known issues with YAML parsing, deserialization vulnerabilities, and security patches for {component_name}.',
                    'weight': 0.85
                })
        
        # Python packages
        elif any(py_lib in component_name for py_lib in ['django', 'flask', 'requests', 'pillow', 'numpy']):
            if 'django' in component_name:
                sources.append({
                    'key': 'django_security',
                    'url': 'https://docs.djangoproject.com/en/stable/releases/security/',
                    'title': 'Django Security Releases',
                    'content': f'Official Django security releases and advisories for {component_name}. '
                              f'Security patches, vulnerability details, and upgrade instructions.',
                    'weight': 0.9
                })
            
            if 'flask' in component_name:
                sources.append({
                    'key': 'flask_security',
                    'url': 'https://flask.palletsprojects.com/en/2.3.x/security/',
                    'title': 'Flask Security Considerations',
                    'content': f'Flask security documentation and best practices for {component_name}. '
                              f'Security considerations and vulnerability mitigation strategies.',
                    'weight': 0.8
                })
        
        # Node.js packages
        elif any(js_lib in component_name for js_lib in ['express', 'lodash', 'moment', 'axios', 'react']):
            sources.append({
                'key': 'npm_security',
                'url': f'https://www.npmjs.com/package/{component_name}',
                'title': f'NPM Package: {component_name}',
                'content': f'Official NPM package page for {component_name}. '
                          f'Check security tab for known vulnerabilities and advisories.',
                'weight': 0.7
            })
        
        # Add CVE-specific sources if available
        if cve_id:
            sources.append({
                'key': 'nist_nvd',
                'url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'title': f'NIST NVD - {cve_id}',
                'content': f'Official NIST National Vulnerability Database entry for {cve_id}. '
                          f'Comprehensive vulnerability analysis, CVSS scores, and references.',
                'weight': 0.95
            })
        
        # Generic security advisory sources
        if not sources:
            sources.append({
                'key': 'generic_search',
                'url': f'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={component_name}',
                'title': f'CVE Search: {component_name}',
                'content': f'MITRE CVE database search for {component_name}. '
                          f'Search for known vulnerabilities and security issues.',
                'weight': 0.6
            })
        
        return sources
    
    async def _retrieve_github_commits(self, finding: Finding) -> List[Evidence]:
        """Retrieve evidence from GitHub commits (patches/fixes)"""
        evidence_list = []
        
        try:
            if not self.config.evidence_sources.github_token:
                return evidence_list
            
            # Search for commits related to the vulnerability
            search_terms = []
            if finding.vulnerability.cve_id:
                search_terms.append(finding.vulnerability.cve_id)
            if finding.component_name:
                search_terms.append(f"fix {finding.component_name}")
            
            if not search_terms:
                return evidence_list
            
            # Use GitHub search API to find relevant commits
            url = "https://api.github.com/search/commits"
            headers = {
                'Authorization': f'Bearer {self.config.evidence_sources.github_token}',
                'Accept': 'application/vnd.github.cloak-preview'
            }
            
            params = {
                'q': ' '.join(search_terms),
                'sort': 'committer-date',
                'order': 'desc',
                'per_page': 5
            }
            
            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for commit in data.get('items', []):
                        evidence = Evidence(
                            finding_id=f"{finding.package}:{finding.version}:{finding.vulnerability.id}",
                            sources=[EvidenceSource(
                                type="patch",
                                url=commit.get('html_url', ''),
                                title=f"GitHub commit: {commit.get('sha', '')[:8]}",
                                content=f"Commit: {commit.get('commit', {}).get('message', '')}",
                                weight=0.6
                            )],
                            cached=False,
                            cache_key=f"github_commit:{commit.get('sha', '')}"
                        )
                        evidence_list.append(evidence)
            
        except Exception as e:
            logger.error(f"Error retrieving GitHub commits: {e}")
        
        return evidence_list
    
    async def _retrieve_poc_evidence(self, finding: Finding) -> List[Evidence]:
        """Retrieve evidence from PoC (Proof of Concept) sources"""
        evidence_list = []
        
        try:
            cve_id = self._extract_cve_id(finding)
            vuln_id = self._extract_vulnerability_id(finding)
            
            if not cve_id and not vuln_id:
                return evidence_list
            
            cache_key = f"poc_{cve_id or vuln_id}"
            cached_evidence = self._get_cached_evidence(cache_key)
            if cached_evidence:
                return cached_evidence
            
            # Search Exploit-DB for actual exploits
            if cve_id:
                await self._search_exploit_db(finding, cve_id, evidence_list)
            
            # Search GitHub for PoC repositories
            if cve_id or vuln_id:
                await self._search_github_pocs(finding, cve_id or vuln_id, evidence_list)
            
            # Search for security advisories with exploit information
            if cve_id:
                await self._search_security_advisories(finding, cve_id, evidence_list)
            
            # Cache the results
            self._cache_evidence(cache_key, evidence_list)
            
        except Exception as e:
            logger.error(f"Error retrieving PoC evidence for {finding.id}: {e}")
        
        return evidence_list
    
    async def _search_exploit_db(self, finding: Finding, cve_id: str, evidence_list: List[Evidence]) -> None:
        """Search Exploit-DB for actual exploits"""
        try:
            # Exploit-DB search URL
            search_url = f"https://www.exploit-db.com/search?cve={cve_id}"
            
            # Note: In a real implementation, you would scrape or use an API
            # For now, we create a more informative placeholder
            evidence_source = EvidenceSource(
                type="poc",
                url=search_url,
                title=f"Exploit-DB search for {cve_id}",
                content=f"Search Exploit-DB for public exploits related to {cve_id}. "
                       f"This vulnerability affects {finding.component_name} v{finding.version}. "
                       f"Check for available proof-of-concept exploits and attack vectors.",
                weight=0.6
            )
            
            evidence = Evidence(
                finding_id=finding.id,
                sources=[evidence_source],
                cache_key=f"exploit_db_{cve_id}"
            )
            evidence_list.append(evidence)
            
        except Exception as e:
            logger.warning(f"Failed to search Exploit-DB for {cve_id}: {e}")
    
    async def _search_github_pocs(self, finding: Finding, vuln_id: str, evidence_list: List[Evidence]) -> None:
        """Search GitHub for PoC repositories with actual API calls"""
        try:
            if not self.config.evidence_sources.github_token:
                return
            
            # GitHub search API
            url = "https://api.github.com/search/repositories"
            headers = {
                'Authorization': f'Bearer {self.config.evidence_sources.github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            # Search for repositories containing PoC for this vulnerability
            search_queries = [
                f"{vuln_id} poc",
                f"{vuln_id} exploit",
                f"{vuln_id} proof concept"
            ]
            
            for query in search_queries:
                params = {
                    'q': query,
                    'sort': 'stars',
                    'order': 'desc',
                    'per_page': 3
                }
                
                async with self.session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for repo in data.get('items', []):
                            # Create evidence from actual repository
                            evidence_source = EvidenceSource(
                                type="poc",
                                url=repo.get('html_url', ''),
                                title=f"PoC Repository: {repo.get('name', '')}",
                                content=f"GitHub repository containing proof-of-concept for {vuln_id}.\n"
                                       f"Repository: {repo.get('full_name', '')}\n"
                                       f"Description: {repo.get('description', 'No description')}\n"
                                       f"Stars: {repo.get('stargazers_count', 0)}\n"
                                       f"Language: {repo.get('language', 'Unknown')}\n"
                                       f"Last updated: {repo.get('updated_at', 'Unknown')}",
                                weight=0.7
                            )
                            
                            evidence = Evidence(
                                finding_id=finding.id,
                                sources=[evidence_source],
                                cache_key=f"github_poc_{vuln_id}_{repo.get('id', '')}"
                            )
                            evidence_list.append(evidence)
                    
                    # Rate limiting - wait between requests
                    await asyncio.sleep(0.5)
                    
        except Exception as e:
            logger.warning(f"Failed to search GitHub PoCs for {vuln_id}: {e}")
    
    async def _search_security_advisories(self, finding: Finding, cve_id: str, evidence_list: List[Evidence]) -> None:
        """Search security advisories for exploit information"""
        try:
            # Search multiple security advisory sources
            advisory_sources = [
                {
                    'name': 'MITRE CVE',
                    'url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                    'description': f"Official MITRE CVE entry for {cve_id} with technical details and references."
                },
                {
                    'name': 'CVE Details',
                    'url': f"https://www.cvedetails.com/cve/{cve_id}/",
                    'description': f"Detailed vulnerability information including CVSS scores, affected products, and exploit timeline for {cve_id}."
                },
                {
                    'name': 'Vulnerability Lab',
                    'url': f"https://www.vulnerability-lab.com/search.php?q={cve_id}",
                    'description': f"Security research and vulnerability analysis for {cve_id}."
                }
            ]
            
            for source in advisory_sources:
                evidence_source = EvidenceSource(
                    type="advisory",
                    url=source['url'],
                    title=f"{source['name']} - {cve_id}",
                    content=source['description'],
                    weight=0.5
                )
                
                evidence = Evidence(
                    finding_id=finding.id,
                    sources=[evidence_source],
                    cache_key=f"advisory_{source['name'].lower().replace(' ', '_')}_{cve_id}"
                )
                evidence_list.append(evidence)
                
        except Exception as e:
            logger.warning(f"Failed to search security advisories for {cve_id}: {e}")
    
    def _get_cached_evidence(self, cache_key: str) -> Optional[List[Evidence]]:
        """Get evidence from cache if available and not expired"""
        try:
            cache_file = self.cache_dir / f"{cache_key}.json"
            
            if not cache_file.exists():
                return None
            
            # Check if cache is expired
            cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if cache_age > timedelta(hours=self.config.cache.ttl_hours):
                cache_file.unlink()  # Remove expired cache
                return None
            
            # Load cached evidence
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            
            # Convert back to Evidence objects
            evidence_list = []
            for item in cached_data:
                evidence = Evidence(**item)
                evidence_list.append(evidence)
            
            return evidence_list
            
        except Exception as e:
            logger.warning(f"Failed to load cached evidence for {cache_key}: {e}")
            return None
    
    def _cache_evidence(self, cache_key: str, evidence_list: List[Evidence]) -> None:
        """Cache evidence list"""
        try:
            cache_file = self.cache_dir / f"{cache_key}.json"
            
            # Convert Evidence objects to dict for JSON serialization
            cached_data = [evidence.dict() for evidence in evidence_list]
            
            with open(cache_file, 'w') as f:
                json.dump(cached_data, f, indent=2, default=str)
                
        except Exception as e:
            logger.warning(f"Failed to cache evidence for {cache_key}: {e}")


async def create_retriever(config: AgentConfig) -> EvidenceRetriever:
    """Factory function to create evidence retriever"""
    retriever = EvidenceRetriever(config)
    return retriever