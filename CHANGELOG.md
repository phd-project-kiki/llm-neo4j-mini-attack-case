# Changelog

All notable changes to this project are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Planned
- Scenario generator and benchmark comparing LLM only, LLM + RAG and LLM + GraphRAG for attack reconstruction.

## [0.2.0] - 2026-10-12

Phase 2: fully local pipeline.

### Added
- FastAPI back end (`app.py`) and single-page web interface (`static/index.html`).
- Neo4j connection entered, tested and switched from the web page.
- LlamaIndex knowledge-graph extraction with a MITRE ATT&CK attack schema (`src/extract_graph.py`).
- Graph question answering combining LlamaIndex retrieval and the attack timeline (`src/chat.py`).
- Interactive graph view with zoom controls, live timeline, simulation controls and LLM analysis in the page.
- Separate configuration file `.env_pipeline` (template: `.env_pipeline.example`).
- `.gitignore`, pinned `requirements.txt`, `README.md` and this changelog.

### Changed
- `build_attack_graph.py` clears only the simulation graph, keeping extracted data.
- `neo4j_connection.py` reads settings at call time and supports a named database.
- `query_attack.py` shows the event type for simulated events.
- `llm_analysis.py` reads the Ollama URL and model from configuration.
- The original Streamlit interface moved to `app_streamlit.py`.

### Fixed
- LlamaIndex extraction failing with "Event loop is closed" (runs in synchronous mode).

## [0.1.0]

### Added
- Original Streamlit interface on Neo4j Aura: hand-built attack environment, live event simulation, timeline queries and Llama 3.2 analysis.
