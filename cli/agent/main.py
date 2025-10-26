#!/usr/bin/env python3
"""
SCA-enhancer Agent CLI

Command-line interface for the SCA-enhancer Agent that enhances
SCA tool outputs with additional security intelligence.
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sca_enhancer.agent.config import AgentConfig


def setup_logging(level: str = "INFO") -> None:
    """Setup logging configuration"""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('sca_enhancer.log')
        ]
    )


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="SCA-enhancer Agent - Enhance SCA tool outputs with additional security intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process OpenSCA output with default settings
  python -m cmd.agent.main process -i output.json -t opensca

  # Process with custom output directory and configuration
  python -m cmd.agent.main process -i output.json -o enhanced_output -c config.json

  # Run health check
  python -m cmd.agent.main health-check

  # Show configuration template
  python -m cmd.agent.main config-template
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to configuration file (JSON format)'
    )
    
    parser.add_argument(
        '--log-level', '-l',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Process command
    process_parser = subparsers.add_parser(
        'process',
        help='Process SCA tool output'
    )
    process_parser.add_argument(
        '--input', '-i',
        type=str,
        required=True,
        help='Path to SCA tool output file'
    )
    process_parser.add_argument(
        '--output', '-o',
        type=str,
        default='output',
        help='Output directory for enhanced results (default: output)'
    )
    process_parser.add_argument(
        '--tool', '-t',
        choices=['opensca', 'snyk', 'owasp', 'generic', 'auto'],
        default='auto',
        help='SCA tool type (default: auto-detect)'
    )
    
    # Health check command
    health_parser = subparsers.add_parser(
        'health-check',
        help='Perform health check on agent components'
    )
    
    # Config template command
    config_parser = subparsers.add_parser(
        'config-template',
        help='Generate configuration template'
    )
    config_parser.add_argument(
        '--output', '-o',
        type=str,
        default='config_template.json',
        help='Output path for configuration template (default: config_template.json)'
    )
    
    # Version command
    version_parser = subparsers.add_parser(
        'version',
        help='Show version information'
    )
    
    return parser


async def process_command(args: argparse.Namespace, config: AgentConfig) -> int:
    """Handle process command using LangGraph workflow"""
    try:
        # Validate input file
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: Input file not found: {args.input}", file=sys.stderr)
            return 1
        
        # Create output directory
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Import workflow components
        from sca_enhancer.agent.graph import run_workflow
        
        print(f"Starting SCA enhancement workflow for: {args.input}")
        print(f"Tool type: {args.tool}")
        print(f"Output directory: {args.output}")
        print()
        
        # Initial state for the workflow
        initial_state = {
            "input_file": str(input_path.absolute()),
            "tool_type": args.tool,
            "output_dir": str(output_dir.absolute()),
            "config": config.model_dump(),
            "findings": [],
            "evidence_map": {},
            "sast_sinks": [],
            "dast_inputs": [],
            "processing_stats": {},
            "errors": []
        }
        
        # Run the workflow
        final_state = await run_workflow(
            input_file=str(input_path.absolute()),
            output_dir=str(output_dir.absolute()),
            config=config.model_dump(),
            sca_tool=args.tool
        )
        
        # Check for errors
        if final_state.get('errors'):
            print("⚠️  Workflow completed with errors:")
            for error in final_state['errors']:
                print(f"  • {error}")
        
        # Display results
        stats = final_state.get('processing_stats', {})
        findings_count = len(final_state.get('findings', []))
        evidence_count = sum(len(evidence_list) for evidence_list in final_state.get('evidence_map', {}).values())
        sast_count = len(final_state.get('sast_sinks', []))
        dast_count = len(final_state.get('dast_inputs', []))
        
        print("✅ SCA enhancement completed successfully!")
        print()
        print("📊 Processing Summary:")
        print(f"  • Findings processed: {findings_count}")
        print(f"  • Evidence retrieved: {evidence_count}")
        print(f"  • SAST sinks extracted: {sast_count}")
        print(f"  • DAST inputs constructed: {dast_count}")
        
        # Show processing times if available
        if stats:
            print()
            print("⏱️  Processing Times:")
            if 'ingest_time' in stats:
                print(f"  • Ingestion: {stats['ingest_time']:.2f}s")
            if 'evidence_retrieval_time' in stats:
                print(f"  • Evidence retrieval: {stats['evidence_retrieval_time']:.2f}s")
            if 'sast_extraction_time' in stats:
                print(f"  • SAST extraction: {stats['sast_extraction_time']:.2f}s")
            if 'dast_construction_time' in stats:
                print(f"  • DAST construction: {stats['dast_construction_time']:.2f}s")
        
        # Show output files
        output_paths = final_state.get('output_paths', {})
        if output_paths:
            print()
            print("📁 Output Files:")
            for file_type, path in output_paths.items():
                print(f"  • {file_type}: {path}")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error during processing: {e}", file=sys.stderr)
        return 1


async def health_check_command(args: argparse.Namespace, config: AgentConfig) -> int:
    """Handle health check command"""
    try:
        print("🔍 Performing health check...")
        print()
        
        # Check configuration
        print("⚙️  Configuration:")
        print(f"  • LLM Provider: {config.llm.provider}")
        print(f"  • LLM Model: {config.llm.model}")
        print(f"  • Cache Enabled: {config.cache.enabled}")
        print(f"  • LangSmith Enabled: {config.langsmith.enabled}")
        
        # Check components availability
        print()
        print("🔧 Components:")
        
        # Check if we can import workflow components
        try:
            from sca_enhancer.agent.graph import run_workflow
            print("  ✅ LangGraph workflow: healthy")
        except ImportError as e:
            print(f"  ❌ LangGraph workflow: failed - {e}")
            return 1
        
        # Check if we can create config
        try:
            config.validate()
            print("  ✅ Configuration: healthy")
        except Exception as e:
            print(f"  ❌ Configuration: failed - {e}")
            return 1
        
        print()
        print("🏥 Overall Status: healthy")
        
        return 0
        
    except Exception as e:
        print(f"❌ Health check failed: {e}", file=sys.stderr)
        return 1


def config_template_command(args: argparse.Namespace) -> int:
    """Handle config template command"""
    try:
        # Create default configuration
        config = AgentConfig()
        
        # Export to file
        config.to_file(args.output)
        
        print(f"✅ Configuration template generated: {args.output}")
        print()
        print("📝 Next steps:")
        print("1. Edit the configuration file with your settings")
        print("2. Set up environment variables (see .env.example)")
        print("3. Run the agent with: --config your_config.json")
        
        return 0
        
    except Exception as e:
        print(f"❌ Failed to generate config template: {e}", file=sys.stderr)
        return 1


def version_command(args: argparse.Namespace) -> int:
    """Handle version command"""
    try:
        # Import version from package
        from sca_enhancer import __version__, __author__
        
        print(f"SCA-enhancer Agent v{__version__}")
        print(f"Author: {__author__}")
        print()
        print("🔗 Dependencies:")
        print("  • LangGraph: Latest")
        print("  • LangChain: Latest")
        print("  • LangSmith: Latest")
        print("  • Pydantic: Latest")
        
        return 0
        
    except Exception as e:
        print(f"❌ Failed to get version info: {e}", file=sys.stderr)
        return 1


def load_config(config_path: Optional[str]) -> AgentConfig:
    """Load configuration from file or environment"""
    try:
        if config_path:
            # Load from file
            config_file = Path(config_path)
            if not config_file.exists():
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
            config = AgentConfig.from_file(str(config_file))
            print(f"📄 Loaded configuration from: {config_path}")
        else:
            # Load from environment
            config = AgentConfig.from_env()
            print("🌍 Loaded configuration from environment variables")
        
        return config
        
    except Exception as e:
        print(f"❌ Failed to load configuration: {e}", file=sys.stderr)
        sys.exit(1)


async def main() -> int:
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Show help if no command provided
    if not args.command:
        parser.print_help()
        return 1
    
    # Handle commands that don't need configuration
    if args.command == 'config-template':
        return config_template_command(args)
    elif args.command == 'version':
        return version_command(args)
    
    # Load configuration for other commands
    config = load_config(args.config)
    
    # Route to appropriate command handler
    if args.command == 'process':
        return await process_command(args, config)
    elif args.command == 'health-check':
        return await health_check_command(args, config)
    else:
        print(f"❌ Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)