"""
SCA-enhancer Agent - Software Composition Analysis Enhancement Agent

This package provides an intelligent agent that enhances SCA (Software Composition Analysis)
results by bridging them with SAST (Static Application Security Testing) and DAST 
(Dynamic Application Security Testing) tools using LangGraph and RAG (Retrieval-Augmented Generation) techniques.

The agent takes SCA tool outputs (like OpenSCA JSON format) as input and generates
structured outputs for SAST and DAST tools to improve security testing coverage.
"""

__version__ = "1.0.0"
__author__ = "SCA-enhancer Team"
__email__ = "team@sca-enhancer.org"

from sca_enhancer.agent import SCAEnhancerAgent

__all__ = ["SCAEnhancerAgent"]