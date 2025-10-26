"""
SAST Extractor module for SCA-enhancer Agent

This module extracts SAST (Static Application Security Testing) sinks
from vulnerability findings to enable targeted static analysis.
"""

import os
import logging
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path
import json
from datetime import datetime

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI

from .schemas import Finding, Evidence, SASTSink, CallPattern, ConfigKey, ConfidenceLevel
from .config import AgentConfig

logger = logging.getLogger(__name__)


class SASTExtractor:
    """
    Extracts SAST sinks from vulnerability findings using LLM-powered analysis
    and pattern matching to generate targeted static analysis configurations.
    """
    
    def __init__(self, config: AgentConfig):
        self.config = config
        
        # Initialize LLM based on configuration
        if config.llm.provider == "openai":
            # Check if using DeepSeek model
            if "deepseek" in config.llm.model.lower():
                self.llm = ChatOpenAI(
                    model=config.llm.model,
                    temperature=config.llm.temperature,
                    max_tokens=config.llm.max_tokens,
                    openai_api_key=config.llm.openai_api_key,
                    base_url="https://api.deepseek.com/v1"
                )
            else:
                self.llm = ChatOpenAI(
                    model=config.llm.model,
                    temperature=config.llm.temperature,
                    max_tokens=config.llm.max_tokens,
                    openai_api_key=config.llm.openai_api_key
                )
        elif config.llm.provider == "anthropic":
            self.llm = ChatAnthropic(
                model=config.llm.model,
                temperature=config.llm.temperature,
                max_tokens=config.llm.max_tokens,
                anthropic_api_key=config.llm.anthropic_api_key
            )
        elif config.llm.provider == "gemini":
            # Set GOOGLE_API_KEY environment variable for langchain-google-genai
            if config.llm.gemini_api_key:
                os.environ["GOOGLE_API_KEY"] = config.llm.gemini_api_key
            self.llm = ChatGoogleGenerativeAI(
                model=config.llm.model,
                temperature=config.llm.temperature,
                max_output_tokens=config.llm.max_tokens
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {config.llm.provider}")
        
        # Language-specific patterns and configurations
        self.language_configs = config.language_mappings
        
        # SAST sink extraction prompt
        self.extraction_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a security expert specializing in static analysis.
Your task is to analyze vulnerability findings and extract specific code patterns
that SAST tools should look for to detect similar vulnerabilities.

Focus on:
1. Dangerous function calls and their parameters
2. Data flow patterns from sources to sinks
3. Configuration keys that might indicate vulnerabilities
4. Language-specific security anti-patterns

Provide specific, actionable patterns that can be used by SAST tools."""),
            
            ("human", """Analyze this vulnerability finding and extract SAST sink patterns:

Component: {component_name} v{component_version}
Language: {language}
Vulnerability: {vulnerability_title}
Description: {vulnerability_description}
CVE: {cve_id}
CWE: {cwe_id}

Evidence:
{evidence_content}

Based on this information, extract:
1. Dangerous function calls to look for
2. Source-to-sink data flow patterns
3. Configuration keys that indicate vulnerability
4. Code patterns specific to this vulnerability type

Format your response as JSON with the following structure:
{{
    "dangerous_functions": [
        {{
            "function_name": "function_name",
            "parameters": ["param1", "param2"],
            "description": "why this function is dangerous",
            "confidence": "high|medium|low"
        }}
    ],
    "call_patterns": [
        {{
            "pattern": "regex_pattern",
            "description": "what this pattern detects",
            "severity": "critical|high|medium|low"
        }}
    ],
    "config_keys": [
        {{
            "key": "config.key.name",
            "dangerous_values": ["value1", "value2"],
            "description": "why this configuration is dangerous"
        }}
    ],
    "data_flow_patterns": [
        {{
            "source": "source_pattern",
            "sink": "sink_pattern",
            "description": "vulnerability description"
        }}
    ]
}}""")
        ])
    
    async def extract_sast_sinks(self, findings: List[Finding], evidence_map: Dict[str, List[Evidence]]) -> List[SASTSink]:
        """
        Extract SAST sinks from findings and evidence
        
        Args:
            findings: List of vulnerability findings
            evidence_map: Map of finding IDs to their evidence
        
        Returns:
            List of SAST sink configurations
        """
        sast_sinks = []
        
        # Group findings by language for more efficient processing
        language_groups = self._group_findings_by_language(findings)
        
        for language, lang_findings in language_groups.items():
            logger.info(f"Processing {len(lang_findings)} findings for language: {language}")
            
            # Process findings in batches
            batch_size = self.config.processing.batch_size
            for i in range(0, len(lang_findings), batch_size):
                batch = lang_findings[i:i + batch_size]
                
                # Extract sinks for this batch
                batch_sinks = await self._extract_batch_sinks(batch, evidence_map, language)
                sast_sinks.extend(batch_sinks)
        
        # Deduplicate and merge similar sinks
        deduplicated_sinks = self._deduplicate_sinks(sast_sinks)
        
        logger.info(f"Extracted {len(deduplicated_sinks)} unique SAST sinks")
        return deduplicated_sinks
    
    def _group_findings_by_language(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by programming language"""
        language_groups = {}
        
        for finding in findings:
            language = finding.component_language or 'unknown'
            if language not in language_groups:
                language_groups[language] = []
            language_groups[language].append(finding)
        
        return language_groups
    
    async def _extract_batch_sinks(self, findings: List[Finding], evidence_map: Dict[str, List[Evidence]], language: str) -> List[SASTSink]:
        """Extract SAST sinks for a batch of findings"""
        sinks = []
        
        for finding in findings:
            try:
                # Get evidence for this finding
                evidence_list = evidence_map.get(finding.id, [])
                evidence_content = self._format_evidence_content(evidence_list)
                
                # Extract sink using LLM
                sink = await self._extract_single_sink(finding, evidence_content, language)
                if sink:
                    sinks.append(sink)
                
                # Also extract using pattern matching
                pattern_sink = self._extract_pattern_sink(finding, language)
                if pattern_sink:
                    sinks.append(pattern_sink)
                    
            except Exception as e:
                logger.error(f"Failed to extract sink for finding {finding.id}: {e}")
                continue
        
        return sinks
    
    async def _extract_single_sink(self, finding: Finding, evidence_content: str, language: str) -> Optional[SASTSink]:
        """Extract SAST sink from a single finding using LLM"""
        try:
            # Get evidence for this finding
            evidence_list = []
            if evidence_content:
                # Parse evidence content to extract sources
                evidence_sources = self._parse_evidence_sources(evidence_content)
                evidence_list = evidence_sources
            
            # Prepare prompt variables with safe attribute access
            vulnerability = finding.vulnerability
            prompt_vars = {
                'component_name': finding.component_name or finding.package or 'unknown',
                'component_version': finding.version or 'unknown',
                'language': language,
                'vulnerability_title': (getattr(vulnerability, 'title', None) if vulnerability else None) or (getattr(vulnerability, 'id', None) if vulnerability else None) or 'Unknown vulnerability',
                'vulnerability_description': (getattr(vulnerability, 'description', None) if vulnerability else None) or 'No description available',
                'cve_id': (getattr(vulnerability, 'cve_id', None) if vulnerability else None) or (getattr(vulnerability, 'id', None) if vulnerability else None) or 'No CVE',
                'cwe_id': (getattr(vulnerability, 'cwe_id', None) if vulnerability else None) or 'No CWE',
                'evidence_content': evidence_content or 'No evidence available'
            }
            
            # Generate extraction prompt
            messages = self.extraction_prompt.format_messages(**prompt_vars)
            
            # Call LLM
            response = await self.llm.ainvoke(messages)
            
            # Parse LLM response with multiple strategies
            extracted_data = self._parse_llm_response(response.content, finding.id)
            if extracted_data:
                return self._create_sast_sink_from_llm_response(finding, extracted_data, language, evidence_list)
            else:
                logger.warning(f"Failed to parse LLM response for {finding.id}, falling back to pattern-based extraction")
                return self._extract_pattern_sink(finding, language)
                
        except Exception as e:
            logger.error(f"LLM extraction failed for {finding.id}: {e}")
            return None
    
    def _extract_pattern_sink(self, finding: Finding, language: str) -> Optional[SASTSink]:
        """Extract SAST sink using predefined patterns"""
        try:
            # Get language-specific configuration
            lang_config = self.language_configs.get(language, {})
            dangerous_functions = lang_config.get('dangerous_functions', [])
            sources = lang_config.get('sources', [])
            sinks = lang_config.get('sinks', [])
            
            if not dangerous_functions:
                return None
            
            # Create call patterns based on vulnerability type and component
            call_patterns = []
            config_keys = []
            
            # Generate patterns based on component name and vulnerability
            component_name = finding.component_name or ''
            vulnerability = finding.vulnerability
            vuln_description = (getattr(vulnerability, 'description', None) if vulnerability else None) or ''
            
            # Look for function calls related to the vulnerability
            for func in dangerous_functions:
                if any(keyword in vuln_description.lower() for keyword in ['exec', 'eval', 'deserial', 'inject']):
                    pattern = CallPattern(
                        pattern=f"\\b{re.escape(func)}\\s*\\(",
                        description=f"Dangerous {func} function call in {component_name}",
                        severity='high'
                    )
                    call_patterns.append(pattern)
            
            # Generate configuration keys if relevant
            if 'config' in vuln_description.lower() or 'setting' in vuln_description.lower():
                config_key = ConfigKey(
                    key=f"{component_name.lower()}.security",
                    dangerous_values=['false', 'disabled', 'off'],
                    description=f"Security configuration for {component_name}"
                )
                config_keys.append(config_key)
            
            if call_patterns or config_keys:
                return SASTSink(
                    id=f"pattern_{finding.id}",
                    finding_id=finding.id,
                    package=finding.package,
                    version=finding.version,
                    cve=finding.vulnerability.id if finding.vulnerability else '',
                    language=language,
                    vuln_type=finding.vulnerability.type if finding.vulnerability else VulnerabilityType.OTHER,
                    dangerous_functions=dangerous_functions[:3],  # Limit to top 3
                    call_patterns=call_patterns,
                    config_keys=config_keys,
                    sources=[],
                    sinks=[],
                    confidence=ConfidenceLevel.MEDIUM
                )
            
        except Exception as e:
            logger.error(f"Pattern extraction failed for {finding.id}: {e}")
        
        return None
    
    def _create_sast_sink_from_llm_response(self, finding: Finding, extracted_data: Dict[str, Any], language: str, evidence_list: List = None) -> SASTSink:
        """Create SASTSink from LLM extraction response"""
        # Extract dangerous functions
        dangerous_functions = []
        for func_data in extracted_data.get('dangerous_functions', []):
            if isinstance(func_data, str):
                dangerous_functions.append(func_data)
            elif isinstance(func_data, dict):
                dangerous_functions.append(func_data.get('function_name', ''))
        
        # Extract call patterns
        call_patterns = []
        for pattern_data in extracted_data.get('call_patterns', []):
            pattern = CallPattern(
                api=pattern_data.get('api', ''),
                arg_positions=pattern_data.get('arg_positions', []),
                note=pattern_data.get('note', '')
            )
            call_patterns.append(pattern)
        
        # Extract config keys
        config_keys = []
        for config_data in extracted_data.get('config_keys', []):
            config_key = ConfigKey(
                key=config_data.get('key', ''),
                suggest=config_data.get('suggest', ''),
                note=config_data.get('note', '')
            )
            config_keys.append(config_key)
        
        # Determine confidence based on LLM response quality
        confidence = ConfidenceLevel.HIGH if (dangerous_functions and call_patterns) else ConfidenceLevel.MEDIUM
        
        return SASTSink(
            id=f"sast_{finding.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            finding_id=finding.id,
            package=finding.package,
            version=finding.version,
            cve=finding.vulnerability.id if finding.vulnerability else '',
            language=language,
            vuln_type=finding.vulnerability.type if finding.vulnerability else None,
            config_keys=config_keys,
            danger_funcs=dangerous_functions,
            call_patterns=call_patterns,
            sources=extracted_data.get('sources', []),
            sinks=extracted_data.get('sinks', []),
            evidence=evidence_list or [],
            evidence_refs=extracted_data.get('evidence_refs', []),
            confidence=confidence
        )
    
    def _format_evidence_content(self, evidence_list: List[Evidence]) -> str:
        """Format evidence content for LLM prompt"""
        if not evidence_list:
            return "No evidence available"
        
        formatted_content = []
        for evidence in evidence_list:
            source_name = getattr(evidence.source, 'value', evidence.source) if evidence.source else 'unknown'
            content = evidence.content[:500]  # Limit content length
            formatted_content.append(f"[{source_name}] {content}")
        
        return "\n\n".join(formatted_content)
    
    def _deduplicate_sinks(self, sinks: List[SASTSink]) -> List[SASTSink]:
        """Deduplicate and merge similar SAST sinks"""
        # Group sinks by component and language
        sink_groups = {}
        
        for sink in sinks:
            key = (sink.package, sink.language, sink.vuln_type.value)
            if key not in sink_groups:
                sink_groups[key] = []
            sink_groups[key].append(sink)
        
        # Merge sinks in each group
        deduplicated = []
        for group_sinks in sink_groups.values():
            if len(group_sinks) == 1:
                deduplicated.append(group_sinks[0])
            else:
                merged_sink = self._merge_sinks(group_sinks)
                deduplicated.append(merged_sink)
        
        return deduplicated
    
    def _merge_sinks(self, sinks: List[SASTSink]) -> SASTSink:
        """Merge multiple SAST sinks into one"""
        if not sinks:
            raise ValueError("Cannot merge empty sink list")
        
        # Use the first sink as base
        base_sink = sinks[0]
        
        # Merge dangerous functions
        all_functions = set(base_sink.dangerous_functions)
        for sink in sinks[1:]:
            all_functions.update(sink.dangerous_functions)
        
        # Merge call patterns
        all_patterns = []
        pattern_signatures = set()
        
        for sink in sinks:
            for pattern in sink.call_patterns:
                signature = pattern.pattern
                if signature not in pattern_signatures:
                    all_patterns.append(pattern)
                    pattern_signatures.add(signature)
        
        # Merge config keys
        all_config_keys = []
        config_signatures = set()
        
        for sink in sinks:
            for config_key in sink.config_keys:
                signature = config_key.key
                if signature not in config_signatures:
                    all_config_keys.append(config_key)
                    config_signatures.add(signature)
        
        # Determine merged confidence (take highest)
        max_confidence = max(sink.confidence for sink in sinks)
        
        # Merge metadata
        merged_metadata = {}
        for sink in sinks:
            merged_metadata.update(sink.metadata)
        merged_metadata['merged_from'] = [sink.id for sink in sinks]
        
        return SASTSink(
            id=f"merged_{base_sink.component_name}_{base_sink.language}",
            finding_id=base_sink.finding_id,
            component_name=base_sink.component_name,
            language=base_sink.language,
            vulnerability_type=base_sink.vuln_type,
            dangerous_functions=list(all_functions),
            call_patterns=all_patterns,
            config_keys=all_config_keys,
            confidence=max_confidence,
            metadata=merged_metadata
        )
    
    def export_sast_sinks(self, sinks: List[SASTSink], output_path: str) -> None:
        """Export SAST sinks to JSON file"""
        output_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_sinks': len(sinks),
                'extractor_version': '1.0.0'
            },
            'sinks': [
                {
                    'id': sink.id,
                    'finding_id': sink.finding_id,
                    'language': sink.language,
                    'dangerous_functions': sink.dangerous_functions,
                    'call_patterns': [pattern.model_dump() for pattern in sink.call_patterns],
                    'config_keys': [key.model_dump() for key in sink.config_keys],
                    'confidence': sink.confidence.value,
                    'created_at': sink.created_at.isoformat(),
                    'evidence': [evidence.model_dump() for evidence in (sink.evidence or [])]
                }
                for sink in sinks
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Exported {len(sinks)} SAST sinks to {output_path}")

    def _parse_evidence_sources(self, evidence_content: str):
        """Parse evidence content to extract EvidenceSource objects"""
        from .schemas import EvidenceSource
        
        evidence_sources = []
        if not evidence_content:
            return evidence_sources
            
        # Simple parsing - in practice you might want more sophisticated parsing
        lines = evidence_content.split('\n')
        current_source = None
        current_content = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('Source:') or line.startswith('URL:'):
                if current_source and current_content:
                    evidence_sources.append(EvidenceSource(
                        type="advisory",
                        url=current_source,
                        content='\n'.join(current_content),
                        weight=0.8
                    ))
                current_source = line.split(':', 1)[1].strip()
                current_content = []
            elif line and current_source:
                current_content.append(line)
        
        # Add the last source
        if current_source and current_content:
            evidence_sources.append(EvidenceSource(
                type="advisory",
                url=current_source,
                content='\n'.join(current_content),
                weight=0.8
            ))
        
        return evidence_sources

    def _parse_llm_response(self, response_content: str, finding_id: str) -> Optional[Dict[str, Any]]:
        """Parse LLM response with multiple strategies for robustness"""
        # Strategy 1: Direct JSON parsing
        try:
            return json.loads(response_content)
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Extract JSON from markdown code blocks
        json_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
        matches = re.findall(json_pattern, response_content, re.DOTALL)
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue
        
        # Strategy 3: Find JSON-like content between braces
        brace_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        matches = re.findall(brace_pattern, response_content, re.DOTALL)
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue
        
        # Strategy 4: Try to fix common JSON issues
        cleaned_content = response_content.strip()
        if cleaned_content.startswith('```') and cleaned_content.endswith('```'):
            # Remove markdown code block markers
            lines = cleaned_content.split('\n')
            if len(lines) > 2:
                cleaned_content = '\n'.join(lines[1:-1])
        
        # Fix common issues like trailing commas, unquoted keys, etc.
        try:
            # Remove trailing commas before closing brackets/braces
            cleaned_content = re.sub(r',(\s*[}\]])', r'\1', cleaned_content)
            return json.loads(cleaned_content)
        except json.JSONDecodeError:
            pass
        
        # Strategy 5: Extract structured data manually if JSON parsing fails
        try:
            return self._extract_structured_data_from_text(response_content)
        except Exception:
            pass
        
        logger.error(f"All parsing strategies failed for finding {finding_id}. Response content: {response_content[:500]}...")
        return None
    
    def _extract_structured_data_from_text(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract structured data from free-form text as fallback"""
        result = {
            "dangerous_functions": [],
            "call_patterns": [],
            "config_keys": [],
            "data_flow_patterns": []
        }
        
        # Look for function names in the text
        function_pattern = r'(?:function|method|call):\s*([a-zA-Z_][a-zA-Z0-9_]*)'
        functions = re.findall(function_pattern, text, re.IGNORECASE)
        for func in functions:
            result["dangerous_functions"].append({
                "function_name": func,
                "parameters": [],
                "description": f"Potentially dangerous function: {func}",
                "confidence": "medium"
            })
        
        # Look for patterns
        pattern_keywords = ['pattern', 'regex', 'match']
        for keyword in pattern_keywords:
            pattern_regex = rf'{keyword}:\s*([^\n]+)'
            patterns = re.findall(pattern_regex, text, re.IGNORECASE)
            for pattern in patterns:
                result["call_patterns"].append({
                    "pattern": pattern.strip(),
                    "description": f"Pattern extracted from text: {pattern}",
                    "severity": "medium"
                })
        
        return result if any(result.values()) else None


def create_sast_extractor(config: AgentConfig) -> SASTExtractor:
    """Factory function to create SAST extractor"""
    return SASTExtractor(config)