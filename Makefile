.PHONY: help setup test demo run clean lint

help:
	@echo "CHRONOS-FL — Cyber Forensic Flight Recorder Commands:"
	@echo "  make setup     Install dependencies in editable mode"
	@echo "  make test      Run automated pytest suite"
	@echo "  make demo      Run end-to-end forensic flight recorder demo"
	@echo "  make sim       Run interactive attack & anti-forensics simulation"
	@echo "  make api       Run FastAPI backend dashboard server"
	@echo "  make clean     Remove python cache and temporary test artifacts"

setup:
	pip install -e .

test:
	python3 -m pytest tests/ -v

demo:
	python3 demo_full_pipeline.py

sim:
	python3 demo_attack_simulation.py

api:
	python3 -m uvicorn chronos.backend.app:app --reload --port 8000

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
