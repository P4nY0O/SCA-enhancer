"""
Main SCA-enhancer Agent implementation

This module provides both the legacy SCAEnhancerAgent class and the new
LangGraph-based workflow for enhanced SCA tool outputs.
"""

import logging
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import json

from .config import AgentConfig
from .schemas import Finding, Evidence, SASTSink, DASTInput, AgentState, ProcessingResult
from .ingest import create_ingestor
from .retriever import EvidenceRetriever
from .sast_extractor import SASTExtractor
from .dast_constructor import DASTConstructor
from .graph import create_agent_graph, run_workflow

logger = logging.getLogger(__name__)


class SCAEnhancerAgent:
    """
    Main SCA-enhancer Agent that coordinates all components to enhance
    SCA tool outputs with additional security intelligence.
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the SCA-enhancer Agent
        
        Args:
            config: Agent configuration
        """
        self.config = config
        
        # Initialize components
        self.ingestor = create_ingestor(config)
        self.retriever = EvidenceRetriever(config)
        self.sast_extractor = SASTExtractor(config)
        self.dast_constructor = DASTConstructor(config)
        
        # Setup LangSmith if configured
        if config.langsmith.enabled:
            config.setup_langsmith()
        
        logger.info("SCA-enhancer Agent initialized successfully")
    
    async def process_sca_output(
        self,
        input_path: str,
        output_dir: str = "output",
        sca_tool: str = "auto"
    ) -> ProcessingResult:
        """
        Process SCA tool output and generate enhanced results
        
        Args:
            input_path: Path to SCA tool output file
            output_dir: Directory to save enhanced outputs
            sca_tool: SCA tool type ('opensca', 'snyk', 'owasp', 'generic', 'auto')
        
        Returns:
            ProcessingResult with summary and file paths
        """
        try:
            logger.info(f"Starting SCA output processing: {input_path}")
            
            # Create output directory
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Step 1: Ingest SCA tool output
            logger.info("Step 1: Ingesting SCA tool output...")
            findings = await self._ingest_sca_output(input_path, sca_tool)
            logger.info(f"Ingested {len(findings)} findings")
            
            if not findings:
                logger.warning("No findings to process")
                return ProcessingResult(
                    findings=[],
                    total_findings=0,
                    successful_sast=0,
                    successful_dast=0,
                    errors=["No findings found in input file"],
                    cache_hit_rate=0.0,
                    processing_time=0.0
                )
            
            # Step 2: Retrieve evidence for findings
            logger.info("Step 2: Retrieving vulnerability evidence...")
            evidence_map = await self._retrieve_evidence(findings)
            total_evidence = sum(len(evidence_list) for evidence_list in evidence_map.values())
            logger.info(f"Retrieved {total_evidence} pieces of evidence")
            
            # Step 3: Extract SAST sinks
            logger.info("Step 3: Extracting SAST sinks...")
            sast_sinks = await self._extract_sast_sinks(findings, evidence_map)
            logger.info(f"Extracted {len(sast_sinks)} SAST sinks")
            
            # Step 4: Construct DAST inputs
            logger.info("Step 4: Constructing DAST inputs...")
            dast_inputs = await self._construct_dast_inputs(findings, evidence_map)
            logger.info(f"Constructed {len(dast_inputs)} DAST inputs")
            
            # Step 5: Export results
            logger.info("Step 5: Exporting results...")
            output_files = await self._export_results(
                findings, evidence_map, sast_sinks, dast_inputs, output_path
            )
            
            # Create processing result
            result = ProcessingResult(
                findings=findings,
                total_findings=len(findings),
                successful_sast=len(sast_sinks),
                successful_dast=len(dast_inputs),
                errors=[],
                cache_hit_rate=0.0,  # TODO: Implement cache hit rate calculation
                processing_time=0.0  # TODO: Implement processing time calculation
            )
            
            logger.info("SCA output processing completed successfully")
            return result
            
        except Exception as e:
            logger.error(f"Failed to process SCA output: {e}")
            return ProcessingResult(
                findings=[],
                total_findings=0,
                successful_sast=0,
                successful_dast=0,
                errors=[f"Processing failed: {str(e)}"],
                cache_hit_rate=0.0,
                processing_time=0.0
            )
    
    async def _ingest_sca_output(self, input_path: str, sca_tool: str) -> List[Finding]:
        """Ingest SCA tool output"""
        try:
            result = self.ingestor.ingest_file(input_path, sca_tool)
            return result.findings
        except Exception as e:
            logger.error(f"Failed to ingest SCA output: {e}")
            raise
    
    async def _retrieve_evidence(self, findings: List[Finding]) -> Dict[str, List[Evidence]]:
        """Retrieve evidence for findings"""
        try:
            evidence_map = await self.retriever.retrieve_evidence(findings)
            return evidence_map
        except Exception as e:
            logger.error(f"Failed to retrieve evidence: {e}")
            # Return empty evidence map to continue processing
            return {}
    
    async def _extract_sast_sinks(
        self,
        findings: List[Finding],
        evidence_map: Dict[str, List[Evidence]]
    ) -> List[SASTSink]:
        """Extract SAST sinks from findings"""
        try:
            sast_sinks = await self.sast_extractor.extract_sast_sinks(findings, evidence_map)
            return sast_sinks
        except Exception as e:
            logger.error(f"Failed to extract SAST sinks: {e}")
            return []
    
    async def _construct_dast_inputs(
        self,
        findings: List[Finding],
        evidence_map: Dict[str, List[Evidence]]
    ) -> List[DASTInput]:
        """Construct DAST inputs from findings"""
        try:
            dast_inputs = await self.dast_constructor.construct_dast_inputs(findings, evidence_map)
            return dast_inputs
        except Exception as e:
            logger.error(f"Failed to construct DAST inputs: {e}")
            return []
    
    async def _export_results(
        self,
        findings: List[Finding],
        evidence_map: Dict[str, List[Evidence]],
        sast_sinks: List[SASTSink],
        dast_inputs: List[DASTInput],
        output_path: Path
    ) -> Dict[str, str]:
        """Export all results to files"""
        output_files = {}
        
        try:
            # Export enhanced findings with evidence
            enhanced_findings_path = output_path / "enhanced_findings.json"
            await self._export_enhanced_findings(findings, evidence_map, enhanced_findings_path)
            output_files['enhanced_findings'] = str(enhanced_findings_path)
            
            # Export SAST sinks
            if sast_sinks:
                sast_sinks_path = output_path / "SAST_Sinks.json"
                self.sast_extractor.export_sast_sinks(sast_sinks, str(sast_sinks_path))
                output_files['sast_sinks'] = str(sast_sinks_path)
            
            # Export DAST inputs
            if dast_inputs:
                dast_inputs_path = output_path / "DAST_Inputs.json"
                self.dast_constructor.export_dast_inputs(dast_inputs, str(dast_inputs_path))
                output_files['dast_inputs'] = str(dast_inputs_path)
            
            # Export processing summary
            summary_path = output_path / "processing_summary.json"
            await self._export_processing_summary(
                findings, evidence_map, sast_sinks, dast_inputs, summary_path
            )
            output_files['summary'] = str(summary_path)
            
            return output_files
            
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            raise
    
    async def _export_enhanced_findings(
        self,
        findings: List[Finding],
        evidence_map: Dict[str, List[Evidence]],
        output_path: Path
    ) -> None:
        """Export enhanced findings with evidence"""
        try:
            enhanced_data = {
                'metadata': {
                    'generated_at': str(asyncio.get_event_loop().time()),
                    'total_findings': len(findings),
                    'total_evidence': sum(len(evidence_list) for evidence_list in evidence_map.values()),
                    'generator': 'SCA-enhancer-Agent'
                },
                'findings': []
            }
            
            for finding in findings:
                finding_data = finding.dict()
                finding_data['evidence'] = [
                    evidence.dict() for evidence in evidence_map.get(finding.id, [])
                ]
                enhanced_data['findings'].append(finding_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(enhanced_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Exported enhanced findings to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export enhanced findings: {e}")
            raise
    
    async def _export_processing_summary(
        self,
        findings: List[Finding],
        evidence_map: Dict[str, List[Evidence]],
        sast_sinks: List[SASTSink],
        dast_inputs: List[DASTInput],
        output_path: Path
    ) -> None:
        """Export processing summary"""
        try:
            # Calculate statistics
            vuln_types = {}
            languages = {}
            severities = {}
            
            for finding in findings:
                # Vulnerability types
                vuln_type = finding.vulnerability.type.value
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                
                # Languages
                lang = finding.component_language or 'unknown'
                languages[lang] = languages.get(lang, 0) + 1
                
                # Severities
                severity = finding.vulnerability.severity or 'unknown'
                severities[severity] = severities.get(severity, 0) + 1
            
            # Evidence statistics
            evidence_sources = {}
            for evidence_list in evidence_map.values():
                for evidence in evidence_list:
                    source = getattr(evidence.source, 'value', evidence.source) if evidence.source else 'unknown'
                    evidence_sources[source] = evidence_sources.get(source, 0) + 1
            
            # SAST sink statistics
            sast_languages = {}
            for sink in sast_sinks:
                lang = sink.language
                sast_languages[lang] = sast_languages.get(lang, 0) + 1
            
            # DAST input statistics
            dast_vuln_types = {}
            for dast_input in dast_inputs:
                vuln_type = dast_input.vuln_type.value
                dast_vuln_types[vuln_type] = dast_vuln_types.get(vuln_type, 0) + 1
            
            summary_data = {
                'processing_summary': {
                    'total_findings': len(findings),
                    'total_evidence': sum(len(evidence_list) for evidence_list in evidence_map.values()),
                    'total_sast_sinks': len(sast_sinks),
                    'total_dast_inputs': len(dast_inputs)
                },
                'statistics': {
                    'vulnerability_types': vuln_types,
                    'languages': languages,
                    'severities': severities,
                    'evidence_sources': evidence_sources,
                    'sast_languages': sast_languages,
                    'dast_vulnerability_types': dast_vuln_types
                },
                'configuration': {
                    'llm_provider': self.config.llm.provider,
                    'llm_model': self.config.llm.model,
                    'evidence_sources_enabled': {
                        'nvd': self.config.evidence_sources.nvd_enabled,
                        'ghsa': self.config.evidence_sources.ghsa_enabled,
                        'vendor_advisories': self.config.evidence_sources.vendor_advisories_enabled,
                        'github_commits': self.config.evidence_sources.github_commits_enabled,
                        'poc_sources': self.config.evidence_sources.poc_sources_enabled
                    }
                }
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Exported processing summary to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export processing summary: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all components"""
        health_status = {
            'agent': 'healthy',
            'components': {},
            'configuration': {
                'llm_provider': self.config.llm.provider,
                'llm_model': self.config.llm.model,
                'cache_dir': self.config.cache.cache_dir,
                'langsmith_enabled': self.config.langsmith.enabled
            }
        }
        
        try:
            # Check ingestor
            health_status['components']['ingestor'] = 'healthy'
            
            # Check retriever
            try:
                retriever_health = self.retriever.health_check()
                if retriever_health['status'] == 'healthy':
                    health_status['components']['retriever'] = 'healthy'
                else:
                    health_status['components']['retriever'] = f"unhealthy: {retriever_health.get('embeddings', 'unknown error')}"
            except Exception as e:
                health_status['components']['retriever'] = f'unhealthy: {str(e)}'
            
            # Check SAST extractor
            health_status['components']['sast_extractor'] = 'healthy'
            
            # Check DAST constructor
            health_status['components']['dast_constructor'] = 'healthy'
            
        except Exception as e:
            health_status['agent'] = f'unhealthy: {str(e)}'
        
        return health_status


def create_agent(config: AgentConfig) -> SCAEnhancerAgent:
    """Create a legacy SCA-enhancer Agent instance"""
    return SCAEnhancerAgent(config)


async def create_langgraph_agent(config: AgentConfig):
    """
    Create a LangGraph-based SCA-enhancer Agent
    
    Args:
        config: Agent configuration
        
    Returns:
        Compiled LangGraph workflow
    """
    config_dict = config.model_dump()
    return create_agent_graph(config_dict)


async def process_with_langgraph(
    input_path: str,
    output_dir: str = "output",
    sca_tool: str = "auto",
    config: Optional[AgentConfig] = None
) -> Dict[str, Any]:
    """
    Process SCA output using LangGraph workflow
    
    Args:
        input_path: Path to SCA tool output
        output_dir: Output directory for results
        sca_tool: SCA tool type
        config: Agent configuration
        
    Returns:
        Processing results
    """
    if config is None:
        config = AgentConfig()
    
    # Setup LangSmith if configured
    if config.langsmith.enabled:
        config.setup_langsmith()
    
    # Create and run workflow
    app = await create_langgraph_agent(config)
    config_dict = config.model_dump()
    
    final_state = await run_workflow(
        input_file=input_path,
        output_dir=output_dir,
        config=config_dict,
        sca_tool=sca_tool
    )
    
    return final_state