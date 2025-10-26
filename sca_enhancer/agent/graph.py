"""LangGraph workflow definition for SCA-enhancer Agent

This module defines the workflow graph using LangGraph, orchestrating
the SCA enhancement process through batch processing of all findings in a single workflow.
"""

import logging
from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from .state import SCAEnhancerState
from .nodes import (
    ingest_node,
    batch_retrieve_evidence_node,
    batch_extract_sast_node,
    batch_construct_dast_node,
    export_results_node
)

logger = logging.getLogger(__name__)


def create_workflow() -> StateGraph:
    """
    Create the SCA-enhancer workflow graph with batch processing
    
    Returns:
        StateGraph ready for compilation
    """
    # Create the graph
    workflow = StateGraph(SCAEnhancerState)
    
    # Add nodes for batch processing
    workflow.add_node("ingest", ingest_node)
    workflow.add_node("batch_retrieve_evidence", batch_retrieve_evidence_node)
    workflow.add_node("batch_extract_sast", batch_extract_sast_node)
    workflow.add_node("batch_construct_dast", batch_construct_dast_node)
    workflow.add_node("export_results", export_results_node)
    
    # Add edges - Linear batch processing workflow
    workflow.set_entry_point("ingest")
    workflow.add_edge("ingest", "batch_retrieve_evidence")
    workflow.add_edge("batch_retrieve_evidence", "batch_extract_sast")
    workflow.add_edge("batch_extract_sast", "batch_construct_dast")
    workflow.add_edge("batch_construct_dast", "export_results")
    workflow.add_edge("export_results", END)
    
    return workflow


def create_agent_graph(config_dict: Dict[str, Any]) -> StateGraph:
    """
    Create and compile the agent graph with configuration
    
    Args:
        config_dict: Configuration dictionary
        
    Returns:
        Compiled StateGraph instance
    """
    workflow = create_workflow()
    
    # Add memory saver for checkpointing
    memory = MemorySaver()
    
    # Compile the graph
    app = workflow.compile(checkpointer=memory)
    
    logger.info("SCA-enhancer workflow graph created successfully")
    
    return app


async def run_workflow(
    input_file: str,
    output_dir: str,
    config: Dict[str, Any],
    sca_tool: str = "auto",
    thread_id: str = "default"
) -> Dict[str, Any]:
    """
    Run the SCA-enhancer workflow with batch processing
    
    Args:
        input_file: Path to input SCA tool output
        output_dir: Directory for output files
        config: Agent configuration
        sca_tool: SCA tool type
        thread_id: Thread ID for checkpointing
        
    Returns:
        Final workflow state
    """
    logger.info(f"Starting batch workflow for {input_file}")
    
    # Create and compile workflow
    app = create_workflow()
    memory = MemorySaver()
    compiled_app = app.compile(checkpointer=memory)
    
    # Initial state
    initial_state = {
        "input_file": input_file,
        "output_dir": output_dir,
        "config": config,
        "sca_tool": sca_tool,
        "findings": [],
        "evidence_map": {},
        "sast_sinks": [],
        "dast_inputs": [],
        "output_files": {},
        "current_step": "starting",
        "errors": [],
        "processing_stats": {
            "total_findings": 0,
            "evidence_count": 0,
            "sast_sinks_count": 0,
            "dast_inputs_count": 0,
            "processing_time": 0.0
        }
    }
    
    # Run workflow
    final_state = await compiled_app.ainvoke(
        initial_state,
        config={
            "configurable": {"thread_id": thread_id},
            "recursion_limit": 50  # Reduced since we have fewer nodes
        }
    )
    
    logger.info("Batch workflow completed")
    return final_state