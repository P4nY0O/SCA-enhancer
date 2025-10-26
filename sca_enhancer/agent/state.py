"""
LangGraph State definitions for SCA-enhancer Agent

This module defines the state structures used in the LangGraph workflow.
"""

from typing import List, Dict, Any, Optional, TypedDict, Annotated
from datetime import datetime
import operator

from .schemas import Finding, Evidence, SASTSink, DASTInput


class SCAEnhancerState(TypedDict):
    """
    Main state for the SCA-enhancer LangGraph workflow with sequential processing
    """
    # Input data
    input_file: str
    output_dir: str
    config: Dict[str, Any]
    
    # All findings data
    findings: Annotated[List[Finding], operator.add]
    
    # Sequential processing state
    current_finding_index: int
    current_finding: Optional[Finding]
    current_finding_evidence: Optional[List[Evidence]]
    current_sast_result: Optional[SASTSink]
    current_dast_result: Optional[DASTInput]
    
    # Processed findings with their results
    processed_findings: Annotated[List[Dict[str, Any]], operator.add]
    
    # Processing metadata
    current_step: str
    errors: Annotated[List[str], operator.add]
    
    # Processing statistics (optional)
    cache_hits: Optional[int]
    cache_misses: Optional[int]
    successful_sast: Optional[int]
    successful_dast: Optional[int]


class IngestState(TypedDict):
    """State for the ingestion step"""
    input_path: str
    sca_tool: str
    findings: List[Finding]
    errors: List[str]


class RetrievalState(TypedDict):
    """State for the evidence retrieval step"""
    findings: List[Finding]
    evidence_map: Dict[str, List[Evidence]]
    cache_hits: int
    cache_misses: int
    errors: List[str]


class ExtractionState(TypedDict):
    """State for the SAST extraction step"""
    findings: List[Finding]
    evidence_map: Dict[str, List[Evidence]]
    sast_sinks: List[SASTSink]
    successful_sast: int
    errors: List[str]


class ConstructionState(TypedDict):
    """State for the DAST construction step"""
    findings: List[Finding]
    evidence_map: Dict[str, List[Evidence]]
    dast_inputs: List[DASTInput]
    successful_dast: int
    errors: List[str]


class ExportState(TypedDict):
    """State for the export step"""
    findings: List[Finding]
    evidence_map: Dict[str, List[Evidence]]
    sast_sinks: List[SASTSink]
    dast_inputs: List[DASTInput]
    output_dir: str
    output_paths: Dict[str, str]
    errors: List[str]