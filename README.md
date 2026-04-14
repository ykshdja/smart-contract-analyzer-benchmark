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
