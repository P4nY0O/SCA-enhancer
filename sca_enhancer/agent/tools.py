"""
Tools module for SCA-enhancer Agent

This module provides various tools for evidence collection including
web search, GitHub analysis, and other external data sources.
"""

import logging
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional
from urllib.parse import quote, urljoin
import json
import re
from datetime import datetime

from .schemas import Finding, Evidence, EvidenceSource
from .config import AgentConfig

logger = logging.getLogger(__name__)


class WebSearchTool:
    """Web search tool for vulnerability evidence collection"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.network.timeout_seconds)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def search_vulnerability_info(self, finding: Finding) -> List[Evidence]:
        """Search for vulnerability information using web search"""
        evidence_list = []
        
        try:
            # Construct search queries
            search_queries = self._build_search_queries(finding)
            
            for query in search_queries:
                # Use DuckDuckGo instant answer API (no API key required)
                results = await self._search_duckduckgo(query)
                
                for result in results:
                    evidence = Evidence(
                        finding_id=f"{finding.package}:{finding.version}:{finding.vulnerability.id}",
                        sources=[EvidenceSource(
                            type="web_search",
                            url=result.get('url', ''),
                            title=result.get('title', ''),
                            content=result.get('snippet', ''),
                            weight=0.5
                        )],
                        cached=False,
                        cache_key=f"web_search:{finding.vulnerability.id}:{query}"
                    )
                    evidence_list.append(evidence)
                    
        except Exception as e:
            logger.error(f"Error in web search: {e}")
            
        return evidence_list
    
    def _build_search_queries(self, finding: Finding) -> List[str]:
        """Build search queries for the vulnerability"""
        queries = []
        
        # CVE-based queries
        if finding.vulnerability.cve_id:
            queries.extend([
                f"{finding.vulnerability.cve_id} vulnerability",
                f"{finding.vulnerability.cve_id} exploit",
                f"{finding.vulnerability.cve_id} patch",
                f"{finding.vulnerability.cve_id} {finding.package}"
            ])
        
        # Component-based queries
        if finding.package:
            queries.extend([
                f"{finding.package} {finding.version} vulnerability",
                f"{finding.package} security advisory",
                f"{finding.package} CVE"
            ])
            
        return queries[:5]  # Limit to 5 queries to avoid rate limiting
    
    async def _search_duckduckgo(self, query: str) -> List[Dict[str, Any]]:
        """Search using DuckDuckGo instant answer API"""
        results = []
        
        try:
            # DuckDuckGo instant answer API
            url = "https://api.duckduckgo.com/"
            params = {
                'q': query,
                'format': 'json',
                'no_html': '1',
                'skip_disambig': '1'
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Extract relevant results
                    if data.get('RelatedTopics'):
                        for topic in data['RelatedTopics'][:3]:  # Limit to 3 results
                            if isinstance(topic, dict) and 'FirstURL' in topic:
                                results.append({
                                    'url': topic.get('FirstURL', ''),
                                    'title': topic.get('Text', '').split(' - ')[0] if topic.get('Text') else '',
                                    'snippet': topic.get('Text', '')
                                })
                    
                    # Also check abstract
                    if data.get('Abstract'):
                        results.append({
                            'url': data.get('AbstractURL', ''),
                            'title': data.get('AbstractSource', ''),
                            'snippet': data.get('Abstract', '')
                        })
                        
        except Exception as e:
            logger.error(f"DuckDuckGo search error: {e}")
            
        return results


class GitHubAnalysisTool:
    """GitHub analysis tool for patch and commit analysis"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.network.timeout_seconds)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def analyze_patches(self, finding: Finding) -> List[Evidence]:
        """Analyze GitHub patches and commits for vulnerability fixes"""
        evidence_list = []
        
        try:
            if not self.config.evidence_sources.github_token:
                logger.warning("GitHub token not configured, skipping patch analysis")
                return evidence_list
            
            # Search for relevant repositories and commits
            repos = await self._find_relevant_repositories(finding)
            
            for repo in repos:
                commits = await self._analyze_repository_commits(repo, finding)
                evidence_list.extend(commits)
                
        except Exception as e:
            logger.error(f"Error in GitHub patch analysis: {e}")
            
        return evidence_list
    
    async def _find_relevant_repositories(self, finding: Finding) -> List[Dict[str, Any]]:
        """Find repositories related to the vulnerable component"""
        repos = []
        
        try:
            # Search GitHub for repositories
            url = "https://api.github.com/search/repositories"
            headers = {
                'Authorization': f'Bearer {self.config.evidence_sources.github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            # Build search query
            query_parts = []
            if finding.package:
                query_parts.append(finding.package)
            if finding.vulnerability.cve_id:
                query_parts.append(finding.vulnerability.cve_id)
            
            params = {
                'q': ' '.join(query_parts),
                'sort': 'stars',
                'order': 'desc',
                'per_page': 5
            }
            
            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    repos = data.get('items', [])
                    
        except Exception as e:
            logger.error(f"Error finding repositories: {e}")
            
        return repos
    
    async def _analyze_repository_commits(self, repo: Dict[str, Any], finding: Finding) -> List[Evidence]:
        """Analyze commits in a repository for vulnerability fixes"""
        evidence_list = []
        
        try:
            # Search commits in the repository
            url = f"https://api.github.com/repos/{repo['full_name']}/commits"
            headers = {
                'Authorization': f'Bearer {self.config.evidence_sources.github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            # Build search parameters
            params = {'per_page': 10}
            if finding.vulnerability.cve_id:
                params['q'] = finding.vulnerability.cve_id
            
            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    commits = await response.json()
                    
                    for commit in commits:
                        # Check if commit message contains vulnerability-related keywords
                        message = commit.get('commit', {}).get('message', '').lower()
                        if self._is_security_related_commit(message, finding):
                            evidence = Evidence(
                                finding_id=f"{finding.package}:{finding.version}:{finding.vulnerability.id}",
                                sources=[EvidenceSource(
                                    type="patch_analysis",
                                    url=commit.get('html_url', ''),
                                    title=f"Security fix commit: {commit.get('sha', '')[:8]}",
                                    content=f"Commit message: {commit.get('commit', {}).get('message', '')}",
                                    weight=0.8
                                )],
                                cached=False,
                                cache_key=f"github_commit:{commit.get('sha', '')}"
                            )
                            evidence_list.append(evidence)
                            
        except Exception as e:
            logger.error(f"Error analyzing repository commits: {e}")
            
        return evidence_list
    
    def _is_security_related_commit(self, message: str, finding: Finding) -> bool:
        """Check if a commit message is related to security fixes"""
        security_keywords = [
            'security', 'vulnerability', 'cve', 'fix', 'patch', 
            'exploit', 'injection', 'xss', 'csrf', 'rce'
        ]
        
        # Check for CVE ID
        if finding.vulnerability.cve_id and finding.vulnerability.cve_id.lower() in message:
            return True
            
        # Check for security keywords
        for keyword in security_keywords:
            if keyword in message:
                return True
                
        return False


class POCSearchTool:
    """Proof of Concept search tool"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.network.timeout_seconds)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def search_poc(self, finding: Finding) -> List[Evidence]:
        """Search for Proof of Concept exploits"""
        evidence_list = []
        
        try:
            # Search multiple POC sources
            poc_sources = [
                await self._search_exploit_db(finding),
                await self._search_github_pocs(finding),
                await self._search_packetstorm(finding)
            ]
            
            for source_results in poc_sources:
                evidence_list.extend(source_results)
                
        except Exception as e:
            logger.error(f"Error in POC search: {e}")
            
        return evidence_list
    
    async def _search_exploit_db(self, finding: Finding) -> List[Evidence]:
        """Search Exploit-DB for POCs"""
        evidence_list = []
        
        if finding.vulnerability.cve_id:
            # Create evidence pointing to Exploit-DB search
            evidence = Evidence(
                finding_id=f"{finding.package}:{finding.version}:{finding.vulnerability.id}",
                sources=[EvidenceSource(
                    type="poc",
                    url=f"https://www.exploit-db.com/search?cve={finding.vulnerability.cve_id}",
                    title=f"Exploit-DB search for {finding.vulnerability.cve_id}",
                    content=f"Search Exploit-DB for POCs related to {finding.vulnerability.cve_id}",
                    weight=0.6
                )],
                cached=False,
                cache_key=f"exploit_db:{finding.vulnerability.cve_id}"
            )
            evidence_list.append(evidence)
            
        return evidence_list
    
    async def _search_github_pocs(self, finding: Finding) -> List[Evidence]:
        """Search GitHub for POC repositories"""
        evidence_list = []
        
        if finding.vulnerability.cve_id:
            # Create evidence pointing to GitHub POC search
            evidence = Evidence(
                finding_id=f"{finding.package}:{finding.version}:{finding.vulnerability.id}",
                sources=[EvidenceSource(
                    type="poc",
                    url=f"https://github.com/search?q={finding.vulnerability.cve_id}+poc&type=repositories",
                    title=f"GitHub POC search for {finding.vulnerability.cve_id}",
                    content=f"Search GitHub repositories for POCs related to {finding.vulnerability.cve_id}",
                    weight=0.5
                )],
                cached=False,
                cache_key=f"github_poc:{finding.vulnerability.cve_id}"
            )
            evidence_list.append(evidence)
            
        return evidence_list
    
    async def _search_packetstorm(self, finding: Finding) -> List[Evidence]:
        """Search PacketStorm for exploits"""
        evidence_list = []
        
        if finding.vulnerability.cve_id:
            # Create evidence pointing to PacketStorm search
            evidence = Evidence(
                finding_id=f"{finding.package}:{finding.version}:{finding.vulnerability.id}",
                sources=[EvidenceSource(
                    type="poc",
                    url=f"https://packetstormsecurity.com/search/?q={finding.vulnerability.cve_id}",
                    title=f"PacketStorm search for {finding.vulnerability.cve_id}",
                    content=f"Search PacketStorm for exploits related to {finding.vulnerability.cve_id}",
                    weight=0.4
                )],
                cached=False,
                cache_key=f"packetstorm:{finding.vulnerability.cve_id}"
            )
            evidence_list.append(evidence)
            
        return evidence_list