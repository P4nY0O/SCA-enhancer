"""
Setup script for SCA-enhancer Agent
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# 读取依赖
with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = []
    dev_requirements = []
    in_dev_section = False
    
    for line in f:
        line = line.strip()
        if line.startswith("# ===== 开发环境依赖 ====="):
            in_dev_section = True
            continue
        elif line and not line.startswith("#"):
            if in_dev_section:
                dev_requirements.append(line)
            else:
                requirements.append(line)

setup(
    name="sca-enhancer",
    version="1.0.0",
    author="SCA-enhancer Team",
    author_email="team@sca-enhancer.com",
    description="基于LangGraph和大语言模型的智能SCA工具增强器",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/SCA-enhancer",
    packages=find_packages(include=["sca_enhancer*", "cli*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
    },
    entry_points={
        "console_scripts": [
            "sca-enhancer=cli.agent.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "sca_enhancer": ["*.json", "*.yaml", "*.yml"],
        "": ["*.md", "*.txt", "*.json"],
    },
    zip_safe=False,
)