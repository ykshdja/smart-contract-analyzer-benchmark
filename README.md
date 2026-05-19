# Smart Contract Analyzer

A minimal prototype for analyzing Solidity smart contracts for vulnerabilities.

## Quick Start

### 1. Install backend dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Start the backend server
```bash
cd backend
uvicorn main:app --reload --port 8000
```

### 3. Open the frontend
Open `frontend/index.html` in your browser (or serve it with any static file server).

## API Endpoint

**POST /analyze**
```json
{
  "code": "pragma solidity ^0.8.0; ..."
}
```

**Response:**
```json
{
  "vulnerabilities": [
    {
      "type": "Reentrancy",
      "severity": "high",
      "line": 15,
      "description": "...",
      "match": ".transfer(",
      "context": "..."
    }
  ]
}
```

## Project Structure
```
├── backend/
│   ├── main.py        # FastAPI server
│   ├── analyzer.py    # Pattern-based analysis
│   └── requirements.txt
└── frontend/
    └── index.html     # Simple UI
```
## --------------------------------------------------------------------------------------------------

## New Potential- Project Structure
```
smart-contract-analyzer/
│
├── backend/                         # FastAPI backend (core)
│   ├── api/                         # REST endpoints
│   │   ├── __init__.py
│   │   └── routes.py                # /analyze, /health, /benchmark
│   │
│   ├── analyzers/                   # Tool plugins (each in its own subdir)
│   │   ├── __init__.py
│   │   ├── base.py                  # Analyzer ABC
│   │   ├── slither/
│   │   │   ├── __init__.py
│   │   │   └── plugin.py            # SlitherAnalyzer
│   │   ├── mythril/
│   │   │   ├── __init__.py
│   │   │   └── plugin.py            # MythrilAnalyzer
│   │   └── echidna/
│   │       ├── __init__.py
│   │       ├── plugin.py            # EchidnaAnalyzer
│   │       └── property_generator.py# Writes test harness
│   │
│   ├── normalization/               # Tool output → Finding objects
│   │   ├── __init__.py
│   │   ├── normalizer.py            # Main normalizer
│   │   ├── slither_normalizer.py    # Slither‑specific parser
│   │   ├── mythril_normalizer.py
│   │   └── echidna_normalizer.py
│   │
│   ├── scoring/                     # Severity & confidence
│   │   ├── __init__.py
│   │   ├── severity.py              # Severity weights
│   │   ├── confidence.py            # Heuristics
│   │   └── deduplicate.py           # Merge duplicate findings
│   │
│   ├── orchestration/               # Runs all analyzers
│   │   ├── __init__.py
│   │   ├── orchestrator.py          # Loads plugins, runs in parallel
│   │   └── aggregator.py            # Combines findings + CFG
│   │
│   ├── cfg/                         # Control Flow Graph module
│   │   ├── __init__.py
│   │   ├── extractor.py             # Uses Slither’s CFG API
│   │   ├── graph_builder.py         # networkx graph from CFG
│   │   └── visualizer.py            # Graphviz rendering to PNG
│   │
│   ├── models/                      # Pydantic schemas
│   │   ├── __init__.py
│   │   ├── finding.py               # Finding, Severity enum
│   │   ├── finding_set.py           # FindingSet (collection + stats)
│   │   └── analysis_request.py      # API request/response models
│   │
│   ├── dynamic/                     # Additional dynamic logic
│   │   ├── __init__.py
│   │   └── trace_parser.py          # Parse Echidna traces
│   │
│   ├── benchmarks/                  # Evaluation suite (used by CLI)
│   │   ├── __init__.py
│   │   ├── ground_truth.json        # Labeled contracts
│   │   ├── runner.py                # Run pipeline on dataset
│   │   └── metrics.py               # Precision, recall, F1
│   │
│   ├── config.py                    # Pydantic settings (env vars)
│   ├── main.py                      # FastAPI app entry point
│   └── requirements.txt             # Python dependencies
│
├── frontend/                        # Streamlit UI
│   ├── app.py                       # Main Streamlit app
│   ├── pages/                       # Multi‑page UI
│   │   ├── analyze.py               # Upload & view findings
│   │   ├── benchmark.py             # Metrics dashboard
│   │   └── cfg_viewer.py            # CFG explorer
│   ├── components/                  # Reusable Streamlit components
│   │   ├── finding_table.py
│   │   └── severity_badge.py
│   └── utils/                       # Frontend helpers
│       └── api_client.py            # Calls backend endpoints
│
├── contracts/                       # Sample vulnerable contracts
│   ├── reentrancy.sol
│   ├── unchecked_call.sol
│   └── ...
│
├── benchmarks/                      # Dataset (symlink or copy)
│   └── scrubd/                      # SCRUBD contracts (if downloaded)
│
├── docker/                          # Docker configuration
│   ├── backend.Dockerfile
│   ├── frontend.Dockerfile
│   └── docker-compose.yml
│
├── tests/                           # Unit & integration tests
│   ├── test_normalizer.py
│   ├── test_orchestrator.py
│   └── fixtures/                    # Test contracts
│
├── docs/                            # Documentation
│   ├── architecture.md
│   ├── api.md
│   └── research_notes.md
│
├── .env.example                     # Environment variables template
├── .gitignore
├── README.md                        # Project overview, demo GIF, setup
└── run.py                           # Convenience script to start both backend & frontend




```










