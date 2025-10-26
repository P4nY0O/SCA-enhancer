"""
Data schemas for SCA-enhancer Agent

This module defines the core data structures used throughout the SCA enhancement workflow,
including Finding, Evidence, SASTSink, and DASTInput models.

The agent processes SCA tool outputs (like OpenSCA JSON format) and generates
structured inputs for SAST and DAST tools.
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ConfidenceLevel(str, Enum):
    """Confidence level for extracted information"""
    HIGH = "high"  # High confidence: Diff + Advisory consistent
    MEDIUM = "medium"  # Medium confidence: Advisory clear, Diff incomplete
    LOW = "low"  # Low confidence: Mainly from PoC/blogs


class VulnerabilityType(str, Enum):
    """Common vulnerability types"""
    RCE = "RCE"
    XSS = "XSS"
    SQL_INJECTION = "SQL_INJECTION"
    DESERIALIZATION = "DESERIALIZATION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    XXE = "XXE"
    TEMPLATE_INJECTION = "TEMPLATE_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    KNOWN_VULNERABILITY = "KNOWN_VULNERABILITY"
    OTHER = "OTHER"


class Vulnerability(BaseModel):
    """漏洞详情"""
    id: str = Field(..., description="CVE ID or vulnerability identifier")
    type: VulnerabilityType = Field(..., description="Vulnerability type")
    severity: str = Field(..., description="Severity level (critical/high/medium/low)")
    range: str = Field(..., description="Affected version range")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    
    # Additional attributes needed by the system
    cve_id: Optional[str] = Field(None, description="CVE ID (alias for id)")
    
    def __post_init__(self):
        """Set cve_id as alias for id if not provided"""
        if self.cve_id is None:
            self.cve_id = self.id


class Finding(BaseModel):
    """SCA扫描发现的漏洞实体"""
    package: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    language: str = Field(..., description="Programming language")
    purl: str = Field(..., description="Package URL identifier")
    vulnerability: Vulnerability = Field(..., description="Vulnerability details")
    paths: List[str] = Field(default_factory=list, description="Dependency paths")
    direct: bool = Field(default=False, description="Is direct dependency")
    
    # Additional attributes needed by the system
    component_name: Optional[str] = Field(None, description="Component name (alias for package)")
    component_language: Optional[str] = Field(None, description="Component language (alias for language)")
    component_vendor: Optional[str] = Field(None, description="Component vendor")
    
    @property
    def id(self) -> str:
        """Generate unique ID for the finding"""
        return f"{self.package}@{self.version}:{self.vulnerability.id}"


class EvidenceSourceType(str, Enum):
    """Evidence source types"""
    NVD = "nvd"
    GHSA = "ghsa"
    VENDOR_ADVISORY = "vendor_advisory"
    GITHUB_COMMITS = "github_commits"
    POC_SOURCES = "poc_sources"


class EvidenceSource(BaseModel):
    """证据来源"""
    type: Literal["advisory", "patch", "poc", "blog"] = Field(..., description="Evidence type")
    url: str = Field(..., description="Source URL")
    title: Optional[str] = Field(None, description="Source title")
    content: str = Field(..., description="Evidence content")
    weight: float = Field(..., description="Evidence weight (0.0-1.0)")
    retrieved_at: datetime = Field(default_factory=datetime.now, description="Retrieval timestamp")
    
    # Additional attributes needed by the system
    source: Optional[str] = Field(None, description="Source identifier (alias for type)")
    
    def model_post_init(self, __context):
        """Set source as alias for type if not provided"""
        if self.source is None:
            self.source = self.type


class Evidence(BaseModel):
    """Evidence bundle for a finding"""
    finding_id: str = Field(..., description="Associated finding identifier")
    sources: List[EvidenceSource] = Field(default_factory=list, description="Evidence sources")
    cached: bool = Field(default=False, description="Whether evidence was cached")
    cache_key: str = Field(..., description="Cache key for this evidence")
    
    # Additional attributes needed by the system
    source: Optional[str] = Field(None, description="Source identifier")
    content: Optional[str] = Field(None, description="Evidence content")
    
    def model_post_init(self, __context):
        """Set source from first evidence source if not provided"""
        if self.source is None and self.sources:
            self.source = self.sources[0].type
        if self.content is None and self.sources:
            self.content = self.sources[0].content


class ConfigKey(BaseModel):
    """Configuration key recommendation for SAST tools"""
    key: str = Field(..., description="Configuration key name")
    suggest: str = Field(..., description="Suggested value")
    note: Optional[str] = Field(None, description="Additional notes")


class CallPattern(BaseModel):
    """Dangerous call pattern for SAST analysis"""
    api: str = Field(..., description="API or function name")
    arg_positions: List[int] = Field(default_factory=list, description="Dangerous argument positions")
    note: Optional[str] = Field(None, description="Pattern description")


class SASTSink(BaseModel):
    """SAST联动线索实体 - Output for SAST tools"""
    id: str = Field(..., description="Unique identifier for this sink")
    finding_id: str = Field(..., description="Associated finding identifier")
    package: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    cve: str = Field(..., description="CVE identifier")
    language: str = Field(..., description="Programming language")
    vuln_type: VulnerabilityType = Field(..., description="Vulnerability type")
    
    # SAST specific fields
    dangerous_functions: List[str] = Field(default_factory=list, description="Dangerous functions to monitor")
    config_keys: List[ConfigKey] = Field(default_factory=list, description="Configuration recommendations")
    danger_funcs: List[str] = Field(default_factory=list, description="Dangerous functions")
    call_patterns: List[CallPattern] = Field(default_factory=list, description="Call patterns to watch")
    sources: List[str] = Field(default_factory=list, description="Source points")
    sinks: List[str] = Field(default_factory=list, description="Sink points")
    
    # Evidence
    evidence: Optional[List[EvidenceSource]] = Field(default_factory=list, description="Associated evidence sources")
    
    # Metadata
    evidence_refs: List[str] = Field(default_factory=list, description="Evidence reference URLs")
    confidence: ConfidenceLevel = Field(..., description="Confidence level")
    extracted_at: datetime = Field(default_factory=datetime.now, description="Extraction timestamp")
    created_at: datetime = Field(default_factory=datetime.now, description="Creation timestamp")


class AttackVector(BaseModel):
    """Attack vector specification for DAST tools"""
    protocol: str = Field(..., description="Protocol (HTTP, RPC, etc.)")
    interface_type: str = Field(..., description="Interface type (web, api, etc.)")
    injection_points: List[str] = Field(default_factory=list, description="Injection points")


class Payload(BaseModel):
    """Attack payload specification for DAST tools"""
    name: str = Field(..., description="Payload name")
    raw: str = Field(..., description="Raw payload string")
    encoding: str = Field(default="raw", description="Encoding type")
    placement: str = Field(..., description="Where to place the payload")
    notes: Optional[str] = Field(None, description="Additional notes")


class Detector(BaseModel):
    """Detection mechanism for DAST tools"""
    type: Literal["status_code", "keyword", "exception", "oob", "timing"] = Field(..., description="Detector type")
    value: str = Field(..., description="Detection value or pattern")
    hint: Optional[str] = Field(None, description="Detection hint")


class DASTInput(BaseModel):
    """DAST联动线索实体 - Input for DAST tools"""
    package: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    cve: str = Field(..., description="CVE identifier")
    vuln_type: VulnerabilityType = Field(..., description="Vulnerability type")
    
    # DAST specific fields
    preconditions: List[str] = Field(default_factory=list, description="Prerequisites for testing")
    attack_vectors: List[AttackVector] = Field(default_factory=list, description="Attack vectors")
    payloads: List[Payload] = Field(default_factory=list, description="Test payloads")
    detectors: List[Detector] = Field(default_factory=list, description="Detection mechanisms")
    
    # Evidence
    evidence: Optional[List[EvidenceSource]] = Field(default_factory=list, description="Associated evidence sources")
    
    # Metadata
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    risk_notes: Optional[str] = Field(None, description="Risk and compliance notes")
    extracted_at: datetime = Field(default_factory=datetime.now, description="Extraction timestamp")


class AgentState(BaseModel):
    """Agent processing state."""
    model_config = {"arbitrary_types_allowed": True}
    
    current_step: str = Field(description="Current processing step")
    processed_findings: int = Field(default=0, description="Number of processed findings")
    total_findings: int = Field(default=0, description="Total number of findings")
    errors: List[str] = Field(default_factory=list, description="Processing errors")
    start_time: Optional[datetime] = Field(default=None, description="Processing start time")
    last_update: Optional[datetime] = Field(default=None, description="Last update time")


class ProcessingResult(BaseModel):
    """处理结果"""
    findings: List[Finding] = Field(default_factory=list, description="Processed findings")
    total_findings: int = Field(..., description="Total number of findings processed")
    successful_sast: int = Field(..., description="Successfully generated SAST sinks")
    successful_dast: int = Field(..., description="Successfully generated DAST inputs")
    errors: List[str] = Field(default_factory=list, description="Error messages")
    cache_hit_rate: float = Field(..., description="Cache hit rate")
    processing_time: float = Field(..., description="Total processing time in seconds")
    
    # Additional fields for CLI compatibility
    evidence_count: int = Field(default=0, description="Number of evidence sources retrieved")
    output_files: Dict[str, str] = Field(default_factory=dict, description="Output file paths")
    
    # Output file paths (legacy)
    sast_output_path: Optional[str] = Field(None, description="SAST output file path")
    dast_output_path: Optional[str] = Field(None, description="DAST output file path")
    
    @property
    def success(self) -> bool:
        """Check if processing was successful"""
        return len(self.errors) == 0 and self.total_findings > 0
    
    @property
    def findings_count(self) -> int:
        """Alias for total_findings for backward compatibility"""
        return self.total_findings
    
    @property
    def sast_sinks_count(self) -> int:
        """Alias for successful_sast for backward compatibility"""
        return self.successful_sast
    
    @property
    def dast_inputs_count(self) -> int:
        """Alias for successful_dast for backward compatibility"""
        return self.successful_dast
    
    @property
    def message(self) -> str:
        """Error message for failed processing"""
        return "; ".join(self.errors) if self.errors else "Processing completed successfully"