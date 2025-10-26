"""
Ingestion module for SCA-enhancer Agent

This module handles the ingestion and parsing of SCA tool outputs,
converting them into standardized Finding objects for further processing.
"""

import json
import logging
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from datetime import datetime

from .schemas import (
    Finding, Vulnerability, VulnerabilityType, ConfidenceLevel,
    ProcessingResult
)
from .config import AgentConfig

logger = logging.getLogger(__name__)


class SCAIngestor:
    """
    Handles ingestion of SCA tool outputs and converts them to standardized Finding objects.
    
    Supports multiple SCA tool formats with extensible parsers.
    """
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.parsers = {
            'opensca': self._parse_opensca_output,
            'snyk': self._parse_snyk_output,
            'owasp_dependency_check': self._parse_owasp_output,
            'generic': self._parse_generic_output
        }
    
    def ingest_file(self, file_path: Union[str, Path], format_type: str = 'auto') -> ProcessingResult:
        """
        Ingest SCA tool output from file
        
        Args:
            file_path: Path to the SCA tool output file
            format_type: Format type ('opensca', 'snyk', 'owasp_dependency_check', 'generic', 'auto')
        
        Returns:
            ProcessingResult containing parsed findings
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            return self.ingest_content(content, format_type, str(file_path))
            
        except Exception as e:
            logger.error(f"Error ingesting file {file_path}: {e}")
            return ProcessingResult(
                findings=[],
                total_findings=0,
                successful_sast=0,
                successful_dast=0,
                errors=[str(e)],
                cache_hit_rate=0.0,
                processing_time=0.0
            )
    
    def ingest_content(self, content: str, format_type: str = 'auto', source: str = 'unknown') -> ProcessingResult:
        """
        Ingest SCA tool output from content string
        
        Args:
            content: Raw content from SCA tool
            format_type: Format type ('opensca', 'snyk', 'owasp_dependency_check', 'generic', 'auto')
            source: Source identifier for the content
        
        Returns:
            ProcessingResult containing parsed findings
        """
        start_time = datetime.now()
        
        try:
            # Auto-detect format if needed
            if format_type == 'auto':
                format_type = self._detect_format(content)
            
            # Get appropriate parser
            parser = self.parsers.get(format_type)
            if not parser:
                raise ValueError(f"Unsupported format type: {format_type}")
            
            # Parse content
            findings = parser(content, source)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return ProcessingResult(
                findings=findings,
                total_findings=len(findings),
                successful_sast=0,
                successful_dast=0,
                errors=[],
                cache_hit_rate=0.0,
                processing_time=processing_time
            )
            
        except Exception as e:
            logger.error(f"Error ingesting content from {source}: {e}")
            return ProcessingResult(
                findings=[],
                total_findings=0,
                successful_sast=0,
                successful_dast=0,
                errors=[str(e)],
                cache_hit_rate=0.0,
                processing_time=0.0
            )
    
    def _detect_format(self, content: str) -> str:
        """
        Auto-detect the format of SCA tool output
        
        Args:
            content: Raw content to analyze
            
        Returns:
            Detected format type
        """
        try:
            data = json.loads(content)
            
            # Check for OpenSCA format
            if 'task_info' in data or 'dependencies' in data or 'children' in data:
                return 'opensca'
            
            # Check for Snyk format
            if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
                if any('packageName' in vuln for vuln in data['vulnerabilities'][:3]):
                    return 'snyk'
            
            # Check for OWASP Dependency Check format
            if 'dependencies' in data and 'reportSchema' in data:
                return 'owasp_dependency_check'
            
            # Default to generic
            return 'generic'
            
        except json.JSONDecodeError:
            # If not JSON, assume generic text format
            return 'generic'
    
    def _parse_opensca_output(self, content: str, source: str) -> List[Finding]:
        """Parse OpenSCA JSON output format"""
        findings = []
        
        try:
            data = json.loads(content)
            
            # Handle standard OpenSCA format with vulnerabilities array
            if 'vulnerabilities' in data:
                for vuln_item in data['vulnerabilities']:
                    # Only process items with actual vulnerability data
                    if self._has_vulnerability_data(vuln_item):
                        component_findings = self._parse_opensca_component(vuln_item, source)
                        findings.extend(component_findings)
                    else:
                        # Log skipped safe component
                        component_name = vuln_item.get('component', vuln_item.get('name', 'unknown'))
                        version = vuln_item.get('version', 'unknown')
                        logger.debug(f"Skipping safe component: {component_name}@{version}")
            
            # Handle dependency tree format (user's current format)
            elif 'dependencies' in data or 'task_info' in data or 'children' in data:
                findings = self._parse_opensca_dependency_tree(data, source)
            
            logger.info(f"Parsed OpenSCA output: found {len(findings)} vulnerable components")
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in OpenSCA output: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing OpenSCA output: {e}")
            return []

    def _has_vulnerability_data(self, item: Dict[str, Any]) -> bool:
        """Check if a component item has actual vulnerability data"""
        # Check for vulnerability field
        vuln_data = item.get('vulnerability', {})
        if vuln_data and vuln_data.get('id'):
            return True
        
        # Check for vulnerabilities array (new format)
        vulnerabilities = item.get('vulnerabilities', [])
        if vulnerabilities:
            # Check if any vulnerability has meaningful data
            for vuln in vulnerabilities:
                if (vuln.get('id') or vuln.get('cve_id') or 
                    vuln.get('name') or vuln.get('description')):
                    return True
        
        # Check for indirect vulnerabilities count (new format)
        if item.get('indirect_vulnerabilities', 0) > 0:
            return True
        
        # Check for CVE or other vulnerability indicators
        if item.get('cve_id') or item.get('cve') or item.get('security_issues'):
            return True
        
        return False

    def _parse_opensca_component(self, item: Dict[str, Any], source: str) -> List[Finding]:
        """Parse individual OpenSCA component"""
        findings = []
        
        # Extract basic component information
        component_name = item.get('name', item.get('component', ''))
        version = item.get('version', '')
        language = item.get('language', 'unknown')
        vendor = item.get('vendor', '')
        
        # Check for vulnerability data
        vuln_data = item.get('vulnerability', {})
        vulnerabilities = item.get('vulnerabilities', [])
        
        # Process vulnerability data if present
        if vuln_data and vuln_data.get('id'):
            # Single vulnerability
            vulnerability = Vulnerability(
                id=vuln_data.get('id', ''),
                title=vuln_data.get('name', vuln_data.get('title', vuln_data.get('id', 'Unknown vulnerability'))),
                description=vuln_data.get('description', 'No description available'),
                type=self._map_vulnerability_type(vuln_data.get('cwe_id', vuln_data.get('cwe', ''))),
                severity=vuln_data.get('security_level_id', vuln_data.get('severity', 'unknown')),
                range=f"<={version}",
                references=vuln_data.get('references', []),
                cve_id=vuln_data.get('cve_id', vuln_data.get('id', ''))
            )
            
            finding = Finding(
                package=component_name,
                version=version,
                language=language,
                purl=f"pkg:{language.lower()}/{vendor}/{component_name}@{version}" if vendor else f"pkg:{language.lower()}/{component_name}@{version}",
                vulnerability=vulnerability,
                paths=item.get('paths', item.get('dependency_path', [])),
                direct=len(item.get('paths', item.get('dependency_path', []))) <= 2,
                component_name=component_name,
                component_language=language,
                component_vendor=vendor if vendor else None
            )
            
            findings.append(finding)
            
        elif vulnerabilities:
            # Multiple vulnerabilities
            for vuln_data in vulnerabilities:
                if vuln_data.get('id') or vuln_data.get('cve_id'):
                    # Map security_level_id to severity string
                    severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low', 5: 'info'}
                    severity_id = vuln_data.get('security_level_id', 0)
                    severity = severity_map.get(severity_id, 'unknown')
                    
                    vulnerability = Vulnerability(
                        id=vuln_data.get('id', vuln_data.get('cve_id', '')),
                        title=vuln_data.get('name', vuln_data.get('title', 'Unknown vulnerability')),
                        description=vuln_data.get('description', 'No description available'),
                        type=self._map_vulnerability_type(vuln_data.get('cwe_id', vuln_data.get('cwe', ''))),
                        severity=severity,
                        range=f"<={version}",
                        references=vuln_data.get('references', []),
                        cve_id=vuln_data.get('cve_id', vuln_data.get('id', ''))
                    )
                    
                    finding = Finding(
                        package=component_name,
                        version=version,
                        language=language,
                        purl=f"pkg:{language.lower()}/{vendor}/{component_name}@{version}" if vendor else f"pkg:{language.lower()}/{component_name}@{version}",
                        vulnerability=vulnerability,
                        paths=item.get('paths', item.get('dependency_path', [])),
                        direct=len(item.get('paths', item.get('dependency_path', []))) <= 2,
                        component_name=component_name,
                        component_language=language,
                        component_vendor=vendor if vendor else None
                    )
                    
                    findings.append(finding)
        
        return findings

    def _parse_opensca_dependency_tree(self, data: Dict[str, Any], source: str) -> List[Finding]:
        """Parse OpenSCA dependency tree format (user's format)"""
        findings = []
        
        def process_dependency(dep: Dict[str, Any], path: List[str] = None, is_direct: bool = True):
            if path is None:
                path = []
            
            # Extract component information
            name = dep.get('name', '')
            version = dep.get('version', '')
            language = dep.get('language', 'unknown')
            vendor = dep.get('vendor', '')
            
            # Create PURL
            if vendor:
                purl = f"pkg:{language.lower()}/{vendor}/{name}@{version}"
            else:
                purl = f"pkg:{language.lower()}/{name}@{version}"
            
            # Process vulnerabilities if present
            vulnerabilities = dep.get('vulnerabilities', [])
            if vulnerabilities:
                logger.info(f"Processing {len(vulnerabilities)} vulnerabilities for {name}@{version}")
                for vuln_data in vulnerabilities:
                    if vuln_data.get('id') or vuln_data.get('cve_id'):  # Check both id and cve_id
                        # Map security_level_id to severity string
                        severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low', 5: 'info'}
                        severity_id = vuln_data.get('security_level_id', 0)
                        severity = severity_map.get(severity_id, 'unknown')
                        
                        vulnerability = Vulnerability(
                            id=vuln_data.get('id', vuln_data.get('cve_id', '')),
                            title=vuln_data.get('name', vuln_data.get('title', vuln_data.get('id', 'Unknown vulnerability'))),
                            description=vuln_data.get('description', 'No description available'),
                            type=self._map_vulnerability_type(vuln_data.get('cwe_id', vuln_data.get('cwe', ''))),
                            severity=severity,
                            range=f"<={version}",
                            references=vuln_data.get('references', []),
                            cve_id=vuln_data.get('cve_id', vuln_data.get('id', ''))
                        )
                        
                        finding = Finding(
                            package=name,
                            version=version,
                            language=language,
                            purl=purl,
                            vulnerability=vulnerability,
                            paths=dep.get('paths', path + [name] if name else path),
                            direct=is_direct,
                            component_name=name,
                            component_language=language,
                            component_vendor=vendor if vendor else None
                        )
                        
                        findings.append(finding)
                        logger.info(f"Added finding for {name}@{version}: {vuln_data.get('name', vuln_data.get('id', ''))}")
            else:
                # Log skipped safe component only if it has a name
                if name:
                    logger.debug(f"Skipping safe dependency: {name}@{version}")
            
            # Process child dependencies
            for child in dep.get('children', []):
                process_dependency(child, path + [name] if name else path, False)
        
        # Start processing from the root's children, not the root itself
        if 'children' in data:
            logger.info(f"Processing dependency tree with {len(data['children'])} root children")
            for child in data['children']:
                process_dependency(child, [], True)
        else:
            # Fallback: process the data as a single dependency
            logger.info("Processing single dependency")
            process_dependency(data, [], True)
        
        logger.info(f"Processed dependency tree: found {len(findings)} vulnerable components")
        return findings

    def _parse_snyk_output(self, content: str, source: str) -> List[Finding]:
        """Parse Snyk JSON output format"""
        findings = []
        
        try:
            data = json.loads(content)
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln_data in vulnerabilities:
                # Extract package information
                package_name = vuln_data.get('packageName', '')
                version = vuln_data.get('version', '')
                
                # Create vulnerability object
                vulnerability = Vulnerability(
                    id=vuln_data.get('id', ''),
                    title=vuln_data.get('title', 'Unknown vulnerability'),
                    description=vuln_data.get('description', 'No description available'),
                    type=self._map_vulnerability_type(vuln_data.get('type', '')),
                    severity=vuln_data.get('severity', 'unknown').lower(),
                    range=vuln_data.get('semver', {}).get('vulnerable', ''),
                    references=vuln_data.get('references', []),
                    cve_id=vuln_data.get('identifiers', {}).get('CVE', [''])[0] if vuln_data.get('identifiers', {}).get('CVE') else ''
                )
                
                # Create finding
                finding = Finding(
                    package=package_name,
                    version=version,
                    language=vuln_data.get('language', 'unknown'),
                    purl=f"pkg:{vuln_data.get('language', 'unknown').lower()}/{package_name}@{version}",
                    vulnerability=vulnerability,
                    paths=vuln_data.get('from', []),
                    direct=len(vuln_data.get('from', [])) <= 2
                )
                
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error parsing Snyk output: {e}")
            
        return findings

    def _parse_owasp_output(self, content: str, source: str) -> List[Finding]:
        """Parse OWASP Dependency Check JSON output format"""
        findings = []
        
        try:
            data = json.loads(content)
            dependencies = data.get('dependencies', [])
            
            for dep in dependencies:
                vulnerabilities = dep.get('vulnerabilities', [])
                
                for vuln_data in vulnerabilities:
                    # Create vulnerability object
                    vulnerability = Vulnerability(
                        id=vuln_data.get('name', ''),
                        title=vuln_data.get('name', 'Unknown vulnerability'),
                        description=vuln_data.get('description', 'No description available'),
                        type=self._map_vulnerability_type(vuln_data.get('cwe', '')),
                        severity=vuln_data.get('severity', 'unknown').lower(),
                        range='',
                        references=vuln_data.get('references', []),
                        cve_id=vuln_data.get('name', '') if vuln_data.get('name', '').startswith('CVE-') else ''
                    )
                    
                    # Create finding
                    finding = Finding(
                        package=dep.get('fileName', ''),
                        version='',
                        language='unknown',
                        purl=f"pkg:unknown/{dep.get('fileName', '')}",
                        vulnerability=vulnerability,
                        paths=[dep.get('filePath', '')],
                        direct=True
                    )
                    
                    findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error parsing OWASP output: {e}")
            
        return findings

    def _parse_generic_output(self, content: str, source: str) -> List[Finding]:
        """Parse generic JSON output format"""
        findings = []
        
        try:
            data = json.loads(content)
            
            # Try to extract findings from various possible structures
            items = []
            if isinstance(data, list):
                items = data
            elif 'findings' in data:
                items = data['findings']
            elif 'vulnerabilities' in data:
                items = data['vulnerabilities']
            elif 'results' in data:
                items = data['results']
            
            for item in items:
                # Extract basic information with fallbacks
                package = item.get('package', item.get('component', item.get('name', 'unknown')))
                version = item.get('version', '')
                
                # Create a basic vulnerability
                vulnerability = Vulnerability(
                    id=item.get('id', item.get('cve', 'UNKNOWN')),
                    title=item.get('title', item.get('summary', 'Unknown vulnerability')),
                    description=item.get('description', item.get('details', 'No description available')),
                    type=self._map_vulnerability_type(item.get('type', item.get('category', ''))),
                    severity=item.get('severity', 'unknown').lower(),
                    range=item.get('affected_versions', ''),
                    references=item.get('references', []),
                    cve_id=item.get('cve', '')
                )
                
                # Create finding
                finding = Finding(
                    package=package,
                    version=version,
                    language=item.get('language', 'unknown'),
                    purl=f"pkg:unknown/{package}@{version}",
                    vulnerability=vulnerability,
                    paths=item.get('paths', []),
                    direct=item.get('direct', True)
                )
                
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error parsing generic output: {e}")
            
        return findings

    def _map_vulnerability_type(self, type_str: str) -> VulnerabilityType:
        """Map vulnerability type string to VulnerabilityType enum"""
        if not type_str:
            return VulnerabilityType.OTHER
        
        type_str = type_str.lower()
        type_mapping = {
            'xss': VulnerabilityType.XSS,
            'sql_injection': VulnerabilityType.SQL_INJECTION,
            'deserialization': VulnerabilityType.DESERIALIZATION,
            'path_traversal': VulnerabilityType.PATH_TRAVERSAL,
            'ssrf': VulnerabilityType.SSRF,
            'xxe': VulnerabilityType.XXE,
            'template_injection': VulnerabilityType.TEMPLATE_INJECTION,
            'command_injection': VulnerabilityType.COMMAND_INJECTION,
            'rce': VulnerabilityType.RCE,
            'remote_code_execution': VulnerabilityType.RCE,
            'known_vulnerability': VulnerabilityType.KNOWN_VULNERABILITY,
            # CWE mappings
            'cwe-79': VulnerabilityType.XSS,
            'cwe-89': VulnerabilityType.SQL_INJECTION,
            'cwe-502': VulnerabilityType.DESERIALIZATION,
            'cwe-22': VulnerabilityType.PATH_TRAVERSAL,
            'cwe-918': VulnerabilityType.SSRF,
            'cwe-611': VulnerabilityType.XXE,
            'cwe-94': VulnerabilityType.TEMPLATE_INJECTION,
            'cwe-78': VulnerabilityType.COMMAND_INJECTION,
            'cwe-400': VulnerabilityType.OTHER,  # DoS
            'cwe-20': VulnerabilityType.OTHER,   # Input validation
            'cwe-917': VulnerabilityType.OTHER   # Expression language injection
        }
        
        return type_mapping.get(type_str, VulnerabilityType.OTHER)

    def _calculate_confidence(self, vuln_data: Dict[str, Any]) -> ConfidenceLevel:
        """Calculate confidence level based on vulnerability data quality"""
        score = 0
        
        # Check for CVE ID
        if vuln_data.get('cve_id') or vuln_data.get('id', '').startswith('CVE-'):
            score += 3
        
        # Check for detailed description
        if len(vuln_data.get('description', '')) > 50:
            score += 2
        
        # Check for references
        if vuln_data.get('references'):
            score += 1
        
        # Check for CVSS score
        if vuln_data.get('cvss_score') or vuln_data.get('score'):
            score += 1
        
        # Determine confidence level
        if score >= 5:
            return ConfidenceLevel.HIGH
        elif score >= 3:
            return ConfidenceLevel.MEDIUM
        
        # Low confidence otherwise
        return ConfidenceLevel.LOW


def create_ingestor(config: AgentConfig) -> SCAIngestor:
    """Factory function to create SCA ingestor"""
    return SCAIngestor(config)