"""
LangGraph Node functions for SCA-enhancer Agent

This module defines the node functions used in the LangGraph workflow.
Each node represents a step in the SCA enhancement process with batch processing.
"""

import logging
import asyncio
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path
import time

from .state import SCAEnhancerState
from .config import AgentConfig
from .ingest import create_ingestor
from .retriever import EvidenceRetriever
from .sast_extractor import SASTExtractor
from .dast_constructor import DASTConstructor

logger = logging.getLogger(__name__)


async def ingest_node(state: SCAEnhancerState) -> Dict[str, Any]:
    """
    Ingest SCA tool output and parse findings
    
    Args:
        state: Current workflow state
        
    Returns:
        Updated state with findings
    """
    logger.info(f"Starting ingestion of {state['input_file']}")
    start_time = time.time()
    
    try:
        config = AgentConfig.from_dict(state['config'])
        ingestor = create_ingestor(config)
        
        # Process the findings
        result = ingestor.ingest_file(state['input_file'], state.get('sca_tool', 'auto'))
        
        processing_time = time.time() - start_time
        
        # Update state with findings
        return {
            "findings": result.findings,
            "current_step": "ingestion_complete",
            "processing_stats": {
                **state.get('processing_stats', {}),
                "total_findings": len(result.findings),
                "ingestion_time": processing_time
            },
            "errors": []
        }
        
    except Exception as e:
        logger.error(f"Error in ingestion: {e}")
        return {
            "findings": [],
            "current_step": "ingestion_failed",
            "errors": [f"Ingestion error: {str(e)}"]
        }


async def batch_retrieve_evidence_node(state: SCAEnhancerState) -> Dict[str, Any]:
    """
    Retrieve evidence for all findings in batch
    
    Args:
        state: Current workflow state
        
    Returns:
        Updated state with evidence map
    """
    findings = state.get('findings', [])
    
    # Filter out findings without actual vulnerabilities
    vulnerable_findings = []
    safe_components = []
    
    for finding in findings:
        # Check if finding has actual vulnerability data
        if (finding.vulnerability and 
            finding.vulnerability.id and 
            finding.vulnerability.id != 'PLACEHOLDER'):
            vulnerable_findings.append(finding)
        else:
            safe_components.append({
                'package': finding.package,
                'version': finding.version,
                'language': finding.language
            })
    
    logger.info(f"Processing {len(vulnerable_findings)} vulnerable findings, skipping {len(safe_components)} safe components")
    
    if safe_components:
        safe_component_names = [f"{c['package']}@{c['version']}" for c in safe_components[:5]]
        logger.info(f"Safe components (no vulnerabilities): {safe_component_names}")
    
    if not vulnerable_findings:
        logger.info("No vulnerable findings to process")
        return {
            "evidence_map": {},
            "current_step": "evidence_retrieval_complete",
            "processing_stats": {
                **state.get('processing_stats', {}),
                "evidence_count": 0,
                "safe_components_count": len(safe_components),
                "evidence_retrieval_time": 0
            },
            "errors": []
        }
    
    start_time = time.time()
    
    try:
        config = AgentConfig.from_dict(state['config'])
        retriever = EvidenceRetriever(config)
        
        # Retrieve evidence for vulnerable findings only
        evidence_map = {}
        total_evidence = 0
        
        # Use the batch method to retrieve evidence for all findings at once
        try:
            async with retriever:
                evidence_map = await retriever.retrieve_evidence(vulnerable_findings)
                total_evidence = sum(len(evidence_list) for evidence_list in evidence_map.values())
                logger.info(f"Retrieved {total_evidence} total evidence for {len(vulnerable_findings)} findings")
        except Exception as e:
            logger.error(f"Failed to retrieve evidence: {e}")
            evidence_map = {finding.id: [] for finding in vulnerable_findings}
        
        processing_time = time.time() - start_time
        
        return {
            "evidence_map": evidence_map,
            "current_step": "evidence_retrieval_complete",
            "processing_stats": {
                **state.get('processing_stats', {}),
                "evidence_count": total_evidence,
                "safe_components_count": len(safe_components),
                "evidence_retrieval_time": processing_time
            },
            "errors": []
        }
        
    except Exception as e:
        logger.error(f"Error in batch evidence retrieval: {e}")
        return {
            "evidence_map": {},
            "current_step": "evidence_retrieval_failed",
            "errors": [f"Evidence retrieval error: {str(e)}"]
        }


async def batch_extract_sast_node(state: SCAEnhancerState) -> Dict[str, Any]:
    """
    Extract SAST sinks for all findings in batch
    
    Args:
        state: Current workflow state
        
    Returns:
        Updated state with SAST sinks
    """
    findings = state.get('findings', [])
    evidence_map = state.get('evidence_map', {})
    
    # Filter to only process vulnerable findings
    vulnerable_findings = [
        finding for finding in findings 
        if (finding.vulnerability and 
            finding.vulnerability.id and 
            finding.vulnerability.id != 'PLACEHOLDER')
    ]
    
    logger.info(f"Starting batch SAST extraction for {len(vulnerable_findings)} vulnerable findings")
    start_time = time.time()
    
    try:
        config = AgentConfig.from_dict(state['config'])
        extractor = SASTExtractor(config)
        
        # Extract SAST sinks for vulnerable findings only
        sast_sinks = await extractor.extract_sast_sinks(vulnerable_findings, evidence_map)
        
        processing_time = time.time() - start_time
        
        return {
            "sast_sinks": sast_sinks,
            "current_step": "sast_extraction_complete",
            "processing_stats": {
                **state.get('processing_stats', {}),
                "sast_sinks_count": len(sast_sinks),
                "sast_extraction_time": processing_time
            },
            "errors": []
        }
        
    except Exception as e:
        logger.error(f"Error in batch SAST extraction: {e}")
        return {
            "sast_sinks": [],
            "current_step": "sast_extraction_failed",
            "errors": [f"SAST extraction error: {str(e)}"]
        }


async def batch_construct_dast_node(state: SCAEnhancerState) -> Dict[str, Any]:
    """
    Construct DAST inputs for all findings in batch
    
    Args:
        state: Current workflow state
        
    Returns:
        Updated state with DAST inputs
    """
    findings = state.get('findings', [])
    evidence_map = state.get('evidence_map', {})
    
    # Filter to only process vulnerable findings
    vulnerable_findings = [
        finding for finding in findings 
        if (finding.vulnerability and 
            finding.vulnerability.id and 
            finding.vulnerability.id != 'PLACEHOLDER')
    ]
    
    logger.info(f"Starting batch DAST construction for {len(vulnerable_findings)} vulnerable findings")
    start_time = time.time()
    
    try:
        config = AgentConfig.from_dict(state['config'])
        constructor = DASTConstructor(config)
        
        # Construct DAST inputs for vulnerable findings only
        dast_inputs = await constructor.construct_dast_inputs(vulnerable_findings, evidence_map)
        
        processing_time = time.time() - start_time
        
        return {
            "dast_inputs": dast_inputs,
            "current_step": "dast_construction_complete",
            "processing_stats": {
                **state.get('processing_stats', {}),
                "successful_dast": len(dast_inputs),
                "dast_construction_time": processing_time
            },
            "errors": []
        }
        
    except Exception as e:
        logger.error(f"Error in batch DAST construction: {e}")
        return {
            "dast_inputs": [],
            "current_step": "dast_construction_failed",
            "errors": [f"DAST construction error: {str(e)}"]
        }


async def export_results_node(state: SCAEnhancerState) -> Dict[str, Any]:
    """
    Export all results to files
    
    Args:
        state: Current workflow state
        
    Returns:
        Updated state with output paths
    """
    logger.info(f"Starting export to {state['output_dir']}")
    
    try:
        output_path = Path(state['output_dir'])
        output_path.mkdir(parents=True, exist_ok=True)
        
        output_paths = {}
        
        # Export enhanced findings
        enhanced_path = output_path / "enhanced_findings.json"
        await _export_enhanced_findings(
            state['findings'], 
            state.get('evidence_map', {}), 
            enhanced_path,
            state.get('sast_sinks'),
            state.get('dast_inputs')
        )
        output_paths['enhanced_findings'] = str(enhanced_path)
        
        # Export SAST sinks
        if state.get('sast_sinks'):
            sast_path = output_path / "sast_config.json"
            await _export_sast_sinks(state['sast_sinks'], sast_path)
            output_paths['sast_config'] = str(sast_path)
        
        # Export DAST inputs
        if state.get('dast_inputs'):
            dast_path = output_path / "dast_inputs.json"
            await _export_dast_inputs(state['dast_inputs'], dast_path)
            output_paths['dast_inputs'] = str(dast_path)
        
        # Export processing summary
        summary_path = output_path / "processing_summary.json"
        await _export_processing_summary(state, summary_path)
        output_paths['summary'] = str(summary_path)
        
        return {
            "output_paths": output_paths,
            "current_step": "export_complete",
            "last_update": datetime.now(),
            "errors": []
        }
        
    except Exception as e:
        logger.error(f"Error in export: {e}")
        return {
            "output_paths": {},
            "current_step": "export_failed",
            "last_update": datetime.now(),
            "errors": [f"Export error: {str(e)}"]
        }


# Helper functions for export
async def _export_enhanced_findings(findings, evidence_map, output_path, sast_sinks=None, dast_inputs=None):
    """Export enhanced findings with evidence, SAST sinks, and DAST inputs"""
    import json
    
    # Create lookup maps for SAST and DAST data by finding ID
    sast_map = {}
    dast_map = {}
    
    if sast_sinks:
        for sink in sast_sinks:
            key = f"{sink.package}@{sink.version}#{sink.cve}"
            if key not in sast_map:
                sast_map[key] = []
            sast_map[key].append(sink.model_dump())
    
    if dast_inputs:
        for dast_input in dast_inputs:
            key = f"{dast_input.package}@{dast_input.version}#{dast_input.cve}"
            if key not in dast_map:
                dast_map[key] = []
            dast_map[key].append(dast_input.model_dump())
    
    enhanced_findings = []
    for finding in findings:
        # Use finding.id directly to match the key used in evidence_map
        evidence_list = evidence_map.get(finding.id, [])
        
        # Get SAST and DAST data for this finding
        finding_key = f"{finding.package}@{finding.version}#{finding.vulnerability.id}"
        sast_data = sast_map.get(finding_key, [])
        dast_data = dast_map.get(finding_key, [])
        
        enhanced_finding = {
            "finding": finding.model_dump(),
            "evidence": [evidence.model_dump() for evidence in evidence_list],
            "sast_sinks": sast_data,
            "dast_inputs": dast_data
        }
        enhanced_findings.append(enhanced_finding)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(enhanced_findings, f, indent=2, ensure_ascii=False, default=str)


async def _export_sast_sinks(sast_sinks, output_path):
    """Export SAST sinks"""
    import json
    
    sast_data = [sink.model_dump() for sink in sast_sinks]
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sast_data, f, indent=2, ensure_ascii=False, default=str)


async def _export_dast_inputs(dast_inputs, output_path):
    """Export DAST inputs"""
    import json
    
    dast_data = [input_item.model_dump() for input_item in dast_inputs]
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(dast_data, f, indent=2, ensure_ascii=False, default=str)


async def _export_processing_summary(state, output_path):
    """Export processing summary"""
    import json
    
    # Get processing stats safely
    processing_stats = state.get('processing_stats', {})
    
    summary = {
        "processing_summary": {
            "total_findings": len(state.get('findings', [])),
            "successful_sast": processing_stats.get('successful_sast', 0),
            "successful_dast": processing_stats.get('successful_dast', 0),
            "safe_components_count": processing_stats.get('safe_components_count', 0),
            "evidence_count": processing_stats.get('evidence_count', 0),
            "cache_hit_rate": processing_stats.get('cache_hit_rate', 0.0),
            "processing_time": processing_stats.get('total_processing_time', 0.0),
            "errors": state.get('errors', []),
            "output_files": state.get('output_paths', {}),
            "current_step": state.get('current_step', 'unknown')
        }
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False, default=str)