"""
Configuration management for SCA-enhancer Agent

This module handles configuration loading and validation for the SCA enhancement workflow.
"""

import os
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from pathlib import Path
import json


class EvidenceSourceConfig(BaseModel):
    """Configuration for evidence sources"""
    nvd_enabled: bool = Field(default=True, description="Enable NVD database")
    ghsa_enabled: bool = Field(default=True, description="Enable GitHub Security Advisories")
    vendor_advisories_enabled: bool = Field(default=True, description="Enable vendor advisories")
    github_commits_enabled: bool = Field(default=True, description="Enable GitHub commit analysis")
    poc_sources_enabled: bool = Field(default=True, description="Enable PoC sources")
    
    # API configurations
    github_token: Optional[str] = Field(None, description="GitHub API token")
    nvd_api_key: Optional[str] = Field(None, description="NVD API key")


class CacheConfig(BaseModel):
    """Cache configuration"""
    cache_dir: str = Field(default="~/.sca-enhancer-cache", description="Cache directory")
    ttl_hours: int = Field(default=48, description="Cache TTL in hours")
    max_cache_size_mb: int = Field(default=1024, description="Maximum cache size in MB")
    
    @field_validator('cache_dir')
    @classmethod
    def expand_cache_dir(cls, v):
        return str(Path(v).expanduser())


class NetworkConfig(BaseModel):
    """Network configuration"""
    proxy_url: Optional[str] = Field(None, description="Proxy URL")
    tls_verify: bool = Field(default=True, description="Verify TLS certificates")
    timeout_seconds: int = Field(default=30, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    retry_delay_seconds: float = Field(default=1.0, description="Retry delay in seconds")


class ProcessingConfig(BaseModel):
    """Processing configuration"""
    concurrency: int = Field(default=8, description="Number of concurrent workers")
    batch_size: int = Field(default=10, description="Batch size for processing")
    max_evidence_sources: int = Field(default=10, description="Maximum evidence sources per finding")
    confidence_threshold: float = Field(default=0.5, description="Minimum confidence threshold")


class LLMConfig(BaseModel):
    """LLM configuration for LangGraph"""
    provider: str = Field(default="openai", description="LLM provider (openai, anthropic, gemini)")
    model: str = Field(default="gpt-4", description="Model name")
    temperature: float = Field(default=0.1, description="Temperature for generation")
    max_tokens: int = Field(default=4000, description="Maximum tokens per request")
    
    # API keys
    openai_api_key: Optional[str] = Field(None, description="OpenAI API key")
    anthropic_api_key: Optional[str] = Field(None, description="Anthropic API key")
    gemini_api_key: Optional[str] = Field(None, description="Google Gemini API key")


class LangSmithConfig(BaseModel):
    """LangSmith configuration for tracing"""
    enabled: bool = Field(default=True, description="Enable LangSmith tracing")
    api_key: Optional[str] = Field(None, description="LangSmith API key")
    project_name: str = Field(default="sca-enhancer", description="LangSmith project name")
    endpoint: str = Field(default="https://api.smith.langchain.com", description="LangSmith endpoint")


class AgentConfig(BaseModel):
    """Main agent configuration"""
    # Core configurations
    evidence_sources: EvidenceSourceConfig = Field(default_factory=EvidenceSourceConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    processing: ProcessingConfig = Field(default_factory=ProcessingConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    langsmith: LangSmithConfig = Field(default_factory=LangSmithConfig)
    
    # Language-specific configurations
    language_mappings: Dict[str, Dict[str, Any]] = Field(
        default_factory=lambda: {
            "java": {
                "dangerous_functions": ["ObjectInputStream.readObject", "JndiLookup.lookup", "JdbcTemplate.query"],
                "sources": ["HttpServletRequest.getParameter", "HttpServletRequest.getHeader"],
                "sinks": ["Runtime.exec", "ProcessBuilder.start", "jndi_lookup"]
            },
            "javascript": {
                "dangerous_functions": ["eval", "Function", "vm.runInNewContext", "child_process.exec"],
                "sources": ["req.query", "req.body", "req.params"],
                "sinks": ["eval", "child_process.exec", "fs.readFile"]
            },
            "python": {
                "dangerous_functions": ["pickle.load", "yaml.load", "subprocess.call"],
                "sources": ["request.args", "request.form", "request.json"],
                "sinks": ["eval", "exec", "subprocess.call"]
            }
        }
    )
    
    # Output configurations
    output_format: str = Field(default="json", description="Output format (json, yaml)")
    pretty_print: bool = Field(default=True, description="Pretty print output")
    
    @classmethod
    def from_env(cls) -> 'AgentConfig':
        """Load configuration from environment variables"""
        config = cls()
        
        # LangSmith configuration
        if os.getenv("LANGCHAIN_TRACING_V2"):
            config.langsmith.enabled = os.getenv("LANGCHAIN_TRACING_V2").lower() == "true"
        if os.getenv("LANGCHAIN_API_KEY"):
            config.langsmith.api_key = os.getenv("LANGCHAIN_API_KEY")
        if os.getenv("LANGCHAIN_PROJECT"):
            config.langsmith.project_name = os.getenv("LANGCHAIN_PROJECT")
        if os.getenv("LANGCHAIN_ENDPOINT"):
            config.langsmith.endpoint = os.getenv("LANGCHAIN_ENDPOINT")
        
        # LLM configuration
        if os.getenv("OPENAI_API_KEY"):
            config.llm.openai_api_key = os.getenv("OPENAI_API_KEY")
        if os.getenv("ANTHROPIC_API_KEY"):
            config.llm.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        if os.getenv("GEMINI_API_KEY"):
            config.llm.gemini_api_key = os.getenv("GEMINI_API_KEY")
        if os.getenv("GOOGLE_API_KEY"):
            config.llm.gemini_api_key = os.getenv("GOOGLE_API_KEY")
        
        # SCA_ENHANCER specific LLM configuration
        if os.getenv("SCA_ENHANCER_LLM_PROVIDER"):
            config.llm.provider = os.getenv("SCA_ENHANCER_LLM_PROVIDER")
        if os.getenv("SCA_ENHANCER_LLM_MODEL"):
            config.llm.model = os.getenv("SCA_ENHANCER_LLM_MODEL")
        if os.getenv("SCA_ENHANCER_LLM_API_KEY"):
            api_key = os.getenv("SCA_ENHANCER_LLM_API_KEY")
            if config.llm.provider == "openai":
                config.llm.openai_api_key = api_key
            elif config.llm.provider == "anthropic":
                config.llm.anthropic_api_key = api_key
            elif config.llm.provider == "gemini":
                config.llm.gemini_api_key = api_key
        
        # Evidence sources
        if os.getenv("GITHUB_API_TOKEN"):
            config.evidence_sources.github_token = os.getenv("GITHUB_API_TOKEN")
        if os.getenv("NVD_API_KEY"):
            config.evidence_sources.nvd_api_key = os.getenv("NVD_API_KEY")
        
        # Cache configuration
        if os.getenv("SCA_ENHANCER_CACHE_DIR"):
            config.cache.cache_dir = os.getenv("SCA_ENHANCER_CACHE_DIR")
        if os.getenv("SCA_ENHANCER_DEFAULT_TTL"):
            try:
                ttl_str = os.getenv("SCA_ENHANCER_DEFAULT_TTL")
                if ttl_str.endswith('h'):
                    config.cache.ttl_hours = int(ttl_str[:-1])
            except ValueError:
                pass
        
        # Processing configuration
        if os.getenv("SCA_ENHANCER_DEFAULT_CONCURRENCY"):
            try:
                config.processing.concurrency = int(os.getenv("SCA_ENHANCER_DEFAULT_CONCURRENCY"))
            except ValueError:
                pass
        
        # Network configuration
        if os.getenv("SCA_ENHANCER_PROXY_URL"):
            config.network.proxy_url = os.getenv("SCA_ENHANCER_PROXY_URL")
        if os.getenv("SCA_ENHANCER_TLS_VERIFY"):
            config.network.tls_verify = os.getenv("SCA_ENHANCER_TLS_VERIFY").lower() == "true"
        
        return config
    
    @classmethod
    def from_file(cls, config_path: str) -> 'AgentConfig':
        """Load configuration from file"""
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        return cls(**config_data)
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'AgentConfig':
        """Create configuration from dictionary"""
        return cls(**config_dict)
    
    def to_file(self, file_path: str) -> None:
        """Save configuration to JSON file."""
        with open(file_path, 'w') as f:
            json.dump(self.model_dump(), f, indent=2, default=str)
    
    def setup_langsmith(self) -> None:
        """Setup LangSmith environment variables"""
        if self.langsmith.enabled and self.langsmith.api_key:
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_API_KEY"] = self.langsmith.api_key
            os.environ["LANGCHAIN_PROJECT"] = self.langsmith.project_name
            os.environ["LANGCHAIN_ENDPOINT"] = self.langsmith.endpoint
    
    def get_llm_config(self) -> Dict[str, Any]:
        """Get LLM configuration for LangGraph"""
        config = {
            "temperature": self.llm.temperature,
            "max_tokens": self.llm.max_tokens
        }
        
        if self.llm.provider == "openai" and self.llm.openai_api_key:
            config["openai_api_key"] = self.llm.openai_api_key
        elif self.llm.provider == "anthropic" and self.llm.anthropic_api_key:
            config["anthropic_api_key"] = self.llm.anthropic_api_key
        elif self.llm.provider == "gemini" and self.llm.gemini_api_key:
            config["google_api_key"] = self.llm.gemini_api_key
        
        return config