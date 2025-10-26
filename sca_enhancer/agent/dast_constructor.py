"""
DAST Constructor module for SCA-enhancer Agent

This module constructs DAST (Dynamic Application Security Testing) inputs
from vulnerability findings to enable targeted dynamic testing.
"""

import os
import logging
import json
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
import base64

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_vertexai import ChatVertexAI

from .schemas import Finding, Evidence, DASTInput, AttackVector, Payload, Detector, ConfidenceLevel, VulnerabilityType
from .config import AgentConfig

logger = logging.getLogger(__name__)


class DASTConstructor:
    """
    DAST Constructor for generating dynamic application security testing inputs.
    
    This class uses LLM analysis to generate targeted dynamic testing scenarios
    from vulnerability findings and evidence.
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
            # Try Vertex AI first for better model support
            if config.llm.model.startswith("gemini-2.5"):
                try:
                    # Set GOOGLE_APPLICATION_CREDENTIALS if using service account
                    if config.llm.gemini_api_key:
                        os.environ["GOOGLE_API_KEY"] = config.llm.gemini_api_key
                    self.llm = ChatVertexAI(
                        model_name=config.llm.model,
                        temperature=config.llm.temperature,
                        max_output_tokens=config.llm.max_tokens
                    )
                except Exception as e:
                    logger.warning(f"Failed to initialize Vertex AI, falling back to Google GenAI: {e}")
                    # Fallback to regular Google GenAI
                    if config.llm.gemini_api_key:
                        os.environ["GOOGLE_API_KEY"] = config.llm.gemini_api_key
                    self.llm = ChatGoogleGenerativeAI(
                        model=config.llm.model,
                        temperature=config.llm.temperature,
                        max_output_tokens=config.llm.max_tokens
                    )
            else:
                # Use regular Google GenAI for older models
                if config.llm.gemini_api_key:
                    os.environ["GOOGLE_API_KEY"] = config.llm.gemini_api_key
                self.llm = ChatGoogleGenerativeAI(
                    model=config.llm.model,
                    temperature=config.llm.temperature,
                    max_output_tokens=config.llm.max_tokens
                )
        else:
            raise ValueError(f"Unsupported LLM provider: {config.llm.provider}")
        

        
        # DAST input construction prompt
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a security expert specializing in dynamic application security testing (DAST).
Your task is to analyze vulnerability findings and create comprehensive DAST test inputs.

For each vulnerability finding, you need to generate:
1. Attack vectors (HTTP methods, endpoints, parameters)
2. Test payloads for exploitation
3. Detection patterns to identify successful exploitation

Provide specific, actionable test scenarios that can be used by DAST tools."""),
            ("human", """Analyze this vulnerability finding and create DAST test inputs:

Finding: {finding_info}
Evidence: {evidence_content}

Generate comprehensive DAST inputs including:
1. Attack vectors with specific HTTP methods and injection points
2. Test payloads for this vulnerability type
3. Detection patterns to identify successful exploitation
4. Risk assessment and testing notes

Return the response in JSON format with the following structure:
{{
    "attack_vectors": [
        {{
            "protocol": "HTTP",
            "interface_type": "web",
            "injection_points": ["specific endpoints or parameters"]
        }}
    ],
    "payloads": [
        {{
            "name": "payload_name",
            "raw": "actual_payload_content",
            "placement": "parameter|header|body",
            "encoding": "raw|url|base64",
            "notes": "payload description"
        }}
    ],
    "detectors": [
        {{
            "pattern": "detection_pattern",
            "value": "detection_value",
            "hint": "what this detects"
        }}
    ],
    "risk_notes": "assessment and testing guidance"
}}""")
        ])
    
    async def construct_dast_inputs(self, findings: List[Finding], evidence_map: Dict[str, List[Evidence]]) -> List[DASTInput]:
        """
        Construct DAST inputs from findings and evidence
        
        Args:
            findings: List of vulnerability findings
            evidence_map: Map of finding IDs to their evidence
        
        Returns:
            List of DAST input configurations
        """
        dast_inputs = []
        
        # Group findings by vulnerability type for more efficient processing
        vuln_type_groups = self._group_findings_by_vulnerability_type(findings)
        
        for vuln_type, type_findings in vuln_type_groups.items():
            logger.info(f"Processing {len(type_findings)} findings for vulnerability type: {vuln_type}")
            
            # Process findings in batches
            batch_size = self.config.processing.batch_size
            for i in range(0, len(type_findings), batch_size):
                batch = type_findings[i:i + batch_size]
                
                # Construct inputs for this batch
                batch_inputs = await self._construct_batch_inputs(batch, evidence_map, vuln_type)
                dast_inputs.extend(batch_inputs)
        
        # Deduplicate and merge similar inputs
        deduplicated_inputs = self._deduplicate_inputs(dast_inputs)
        
        logger.info(f"Constructed {len(deduplicated_inputs)} unique DAST inputs")
        return deduplicated_inputs
    
    def _group_findings_by_vulnerability_type(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by vulnerability type"""
        type_groups = {}
        
        for finding in findings:
            # Safe access to vulnerability type
            vulnerability = getattr(finding, 'vulnerability', None)
            if vulnerability and hasattr(vulnerability, 'type') and vulnerability.type:
                vuln_type = vulnerability.type.value
            else:
                vuln_type = 'OTHER'  # Default type for findings without vulnerability info
                
            if vuln_type not in type_groups:
                type_groups[vuln_type] = []
            type_groups[vuln_type].append(finding)
        
        return type_groups
    
    async def _construct_batch_inputs(self, findings: List[Finding], evidence_map: Dict[str, List[Evidence]], vuln_type: str) -> List[DASTInput]:
        """Construct DAST inputs for a batch of findings"""
        inputs = []
        
        for finding in findings:
            try:
                # Get evidence for this finding
                evidence_list = evidence_map.get(finding.id, [])
                evidence_content = self._format_evidence_content(evidence_list)
                
                # Construct input using LLM
                llm_input = await self._construct_single_input_llm(finding, evidence_content)
                if llm_input:
                    inputs.append(llm_input)
                

                    
            except Exception as e:
                logger.error(f"Failed to construct DAST input for finding {finding.id}: {e}")
                continue
        
        return inputs
    
    async def _construct_single_input_llm(self, finding: Finding, evidence_content: str) -> Optional[DASTInput]:
        """Construct DAST input for a single finding using LLM"""
        try:
            # Get evidence for this finding
            evidence_list = []
            if evidence_content:
                # Parse evidence content to extract sources
                evidence_sources = self._parse_evidence_sources(evidence_content)
                evidence_list = evidence_sources
            
            # Prepare prompt variables with safe attribute access
            vulnerability = getattr(finding, 'vulnerability', None)
            finding_info = {
                'package': getattr(finding, 'package', 'unknown'),
                'version': getattr(finding, 'version', 'unknown'),
                'language': getattr(finding, 'language', 'unknown'),
                'vulnerability': {
                    'title': (getattr(vulnerability, 'title', None) or getattr(vulnerability, 'id', None) if vulnerability else None) or 'Unknown vulnerability',
                    'description': (getattr(vulnerability, 'description', None) if vulnerability else None) or f"Vulnerability of type {getattr(vulnerability, 'type', 'unknown') if vulnerability else 'unknown'}",
                    'cve': (getattr(vulnerability, 'cve_id', None) if vulnerability else None) or 'No CVE',
                    'severity': (getattr(vulnerability, 'severity', None) if vulnerability else None) or 'unknown'
                }
            }
            
            prompt_vars = {
                'finding_info': json.dumps(finding_info, indent=2),
                'evidence_content': evidence_content or 'No evidence available'
            }
            
            # Generate construction prompt
            messages = self.prompt.format_messages(**prompt_vars)
            
            # Call LLM
            response = await self.llm.ainvoke(messages)
            
            # Parse LLM response
            try:
                # Clean up the response content to extract JSON
                response_content = response.content.strip()
                
                # Remove markdown code blocks if present
                if response_content.startswith('```json'):
                    response_content = response_content[7:]  # Remove ```json
                if response_content.startswith('```'):
                    response_content = response_content[3:]   # Remove ```
                if response_content.endswith('```'):
                    response_content = response_content[:-3]  # Remove trailing ```
                
                response_content = response_content.strip()
                
                constructed_data = json.loads(response_content)
                return self._create_dast_input_from_llm_response(finding, constructed_data, evidence_list)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse LLM response for {finding.id}: {e}")
                logger.debug(f"Raw response: {response.content[:500]}...")
                return None
                
        except Exception as e:
            logger.error(f"LLM construction failed for {finding.id}: {e}")
            return None
    

    
    def _create_dast_input_from_llm_response(self, finding: Finding, constructed_data: Dict[str, Any], evidence_list: List = None) -> DASTInput:
        """Create DASTInput from LLM construction response"""
        # Extract attack vectors
        attack_vectors = []
        for vector_data in constructed_data.get('attack_vectors', []):
            vector = AttackVector(
                protocol=vector_data.get('protocol', 'HTTP'),
                interface_type=vector_data.get('interface_type', 'web'),
                injection_points=vector_data.get('injection_points', [])
            )
            attack_vectors.append(vector)
        
        # Extract payloads
        payloads = []
        for payload_data in constructed_data.get('payloads', []):
            payload = Payload(
                name=payload_data.get('name', 'llm_payload'),
                raw=payload_data.get('raw', ''),
                placement=payload_data.get('placement', 'parameter'),
                encoding=payload_data.get('encoding', 'raw'),
                notes=payload_data.get('notes')
            )
            payloads.append(payload)
        
        # Extract detectors
        detectors = []
        for detector_data in constructed_data.get('detectors', []):
            detector = Detector(
                type=detector_data.get('type', 'keyword'),
                value=detector_data.get('value', ''),
                hint=detector_data.get('hint')
            )
            detectors.append(detector)
        
        vulnerability = getattr(finding, 'vulnerability', None)
        
        return DASTInput(
            package=getattr(finding, 'package', 'unknown'),
            version=getattr(finding, 'version', 'unknown'),
            cve=getattr(vulnerability, 'id', 'unknown') if vulnerability else 'unknown',
            vuln_type=getattr(vulnerability, 'type', VulnerabilityType.OTHER) if vulnerability else VulnerabilityType.OTHER,
            preconditions=constructed_data.get('preconditions', []),
            attack_vectors=attack_vectors,
            payloads=payloads,
            detectors=detectors,
            evidence=evidence_list or [],
            references=getattr(vulnerability, 'references', []) if vulnerability else [],
            risk_notes=f'LLM-generated DAST input for {getattr(finding, "package", "unknown")}@{getattr(finding, "version", "unknown")}'
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
    
    def _deduplicate_inputs(self, inputs: List[DASTInput]) -> List[DASTInput]:
        """Deduplicate and merge similar DAST inputs"""
        # Group inputs by component and vulnerability type
        input_groups = {}
        
        for input_obj in inputs:
            key = (input_obj.package, input_obj.vuln_type.value)
            if key not in input_groups:
                input_groups[key] = []
            input_groups[key].append(input_obj)
        
        # Merge inputs in each group
        deduplicated = []
        for group_inputs in input_groups.values():
            if len(group_inputs) == 1:
                deduplicated.append(group_inputs[0])
            else:
                merged_input = self._merge_inputs(group_inputs)
                deduplicated.append(merged_input)
        
        return deduplicated
    
    def _merge_inputs(self, inputs: List[DASTInput]) -> DASTInput:
        """Merge multiple DAST inputs into one"""
        if not inputs:
            raise ValueError("Cannot merge empty input list")
        
        # Use the first input as base
        base_input = inputs[0]
        
        # Merge attack vectors
        all_vectors = []
        vector_signatures = set()
        
        for input_obj in inputs:
            for vector in input_obj.attack_vectors:
                signature = (vector.protocol, vector.interface_type)
                if signature not in vector_signatures:
                    all_vectors.append(vector)
                    vector_signatures.add(signature)
        
        # Merge payloads
        all_payloads = []
        payload_signatures = set()
        
        for input_obj in inputs:
            for payload in input_obj.payloads:
                signature = payload.raw
                if signature not in payload_signatures:
                    all_payloads.append(payload)
                    payload_signatures.add(signature)
        
        # Merge detectors
        all_detectors = []
        detector_signatures = set()
        
        for input_obj in inputs:
            for detector in input_obj.detectors:
                signature = detector.value
                if signature not in detector_signatures:
                    all_detectors.append(detector)
                    detector_signatures.add(signature)
        
        # Merge references
        all_references = []
        for input_obj in inputs:
            all_references.extend(input_obj.references)
        all_references = list(set(all_references))  # Remove duplicates
        
        return DASTInput(
            package=base_input.package,
            version=base_input.version,
            cve=base_input.cve,
            vuln_type=base_input.vuln_type,
            attack_vectors=all_vectors,
            payloads=all_payloads,
            detectors=all_detectors,
            references=all_references,
            risk_notes=f"Merged DAST input for {base_input.package}@{base_input.version}"
        )
    
    def export_dast_inputs(self, inputs: List[DASTInput], output_path: str) -> None:
        """Export DAST inputs to JSON file"""
        try:
            # Convert to serializable format
            export_data = {
                'metadata': {
                    'generated_at': str(datetime.now()),
                    'total_inputs': len(inputs),
                    'vulnerability_types': list(set(input_obj.vuln_type.value for input_obj in inputs)),
                    'generator': 'SCA-enhancer-Agent'
                },
                'inputs': [
                    {
                        **input_obj.dict(),
                        'evidence': [evidence.dict() for evidence in (input_obj.evidence or [])]
                    }
                    for input_obj in inputs
                ]
            }
            
            # Write to file
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Exported {len(inputs)} DAST inputs to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export DAST inputs: {e}")
            raise


def create_dast_constructor(config: AgentConfig) -> DASTConstructor:
    """Factory function to create DAST constructor"""
    return DASTConstructor(config)