# Makefile for SecurityAI ML Service

.PHONY: help run test lint format clean

help:
	@echo "Available commands:"
	@echo "  make run        - Run the ML service locally"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linting checks"
	@echo "  make format     - Format code with black"
	@echo "  make clean      - Clean up temporary files"

run:
	python run_service.py --reload

test:
	pytest tests/

lint:
	flake8 app/ tests/

format:
	black app/ tests/ examples/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "*.egg" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".coverage" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf .eggs/