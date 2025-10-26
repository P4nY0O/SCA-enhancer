# Makefile for SCA-enhancer Agent

.PHONY: help install install-dev test test-unit test-integration lint format clean build docs run-example

# Default target
help:
	@echo "SCA-enhancer Agent Development Commands"
	@echo "======================================"
	@echo "install          Install production dependencies"
	@echo "install-dev      Install development dependencies"
	@echo "test             Run all tests"
	@echo "test-unit        Run unit tests only"
	@echo "test-integration Run integration tests only"
	@echo "lint             Run code linting"
	@echo "format           Format code with black and isort"
	@echo "clean            Clean build artifacts"
	@echo "build            Build package"
	@echo "docs             Build documentation"
	@echo "run-example      Run example script"

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -r requirements.txt
	pip install -e .

# Testing
test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v -m "not slow"

test-integration:
	pytest tests/integration/ -v

test-coverage:
	pytest tests/ --cov=sca_enhancer --cov-report=html --cov-report=term

# Code quality
lint:
	flake8 sca_enhancer/ cmd/ tests/
	mypy sca_enhancer/ cmd/

format:
	black sca_enhancer/ cmd/ tests/ examples/
	isort sca_enhancer/ cmd/ tests/ examples/

# Build and clean
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python setup.py sdist bdist_wheel

# Documentation
docs:
	cd docs && make html

# Examples
run-example:
	cd examples && python run_example.py

# Development setup
setup-dev: install-dev
	pre-commit install
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to verify installation."