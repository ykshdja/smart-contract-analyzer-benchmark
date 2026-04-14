import re
import json
import subprocess
import tempfile
import os
from typing import List, Dict

VULNERABILITY_PATTERNS = [
    {
        "name": "Reentrancy",
        "severity": "high",
        "pattern": r"\.call\{.*\}\(.*\)|\.transfer\(.*\)|\.send\(.*\)",
        "check": lambda code, match: "await" not in code[max(0, code.find(match)-200):code.find(match)] and "Checks-Effects-Interactions" not in code,
        "description": "Potential reentrancy vulnerability. External calls before state updates."
    },
    {
        "name": "tx.origin Usage",
        "severity": "high",
        "pattern": r"tx\.origin",
        "description": "tx.origin usage is vulnerable to phishing attacks."
    },
    {
        "name": "Dangerous Delegatecall",
        "severity": "high",
        "pattern": r"delegatecall",
        "description": "Delegatecall to untrusted contract can lead to storage collisions."
    },
    {
        "name": "Integer Overflow/Underflow",
        "severity": "high",
        "pattern": r"\+\+|--",
        "check": lambda code, match: "unchecked" not in code and "<0.8.0" not in code,
        "description": "Potential integer arithmetic vulnerability (versions < 0.8.0)."
    },
    {
        "name": "Unchecked Call Return Value",
        "severity": "medium",
        "pattern": r"\.call\(",
        "check": lambda code, match: "require" not in code[max(0, code.find(match)-100):code.find(match)+50] and "if" not in code[max(0, code.find(match)-100):code.find(match)+50],
        "description": "Return value of external call is not checked."
    },
    {
        "name": "State Variable Default Visibility",
        "severity": "medium",
        "pattern": r"^\s*(uint|int|address|bool|bytes|mapping).*[^{]",
        "check": lambda code, match: "public" not in match and "private" not in match and "internal" not in match,
        "description": "State variable may be publicly accessible."
    },
    {
        "name": "Block Timestamp Dependence",
        "severity": "low",
        "pattern": r"block\.timestamp",
        "description": "Reliance on block.timestamp for critical operations."
    },
]


def analyze_patterns(code: str) -> List[Dict]:
    results = []
    lines = code.split("\n")
    
    for vuln in VULNERABILITY_PATTERNS:
        matches = list(re.finditer(vuln["pattern"], code, re.MULTILINE))
        
        for match in matches:
            line_num = code[:match.start()].count("\n") + 1
            
            if "check" in vuln:
                if not vuln["check"](code, match.group()):
                    continue
            
            context_start = max(0, match.start() - 30)
            context_end = min(len(code), match.end() + 30)
            context = code[context_start:context_end].replace("\n", " ")
            
            results.append({
                "type": vuln["name"],
                "severity": vuln["severity"],
                "line": line_num,
                "description": vuln["description"],
                "match": match.group()[:50],
                "context": context
            })
    
    return results


def analyze_slither(file_path: str) -> List[Dict]:
    results = []
    try:
        result = subprocess.run(
            ["slither", file_path, "--json", "-"],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for finding in data.get("results", {}).get("detectors", []):
                results.append({
                    "type": finding.get("check", "Unknown"),
                    "severity": finding.get("impact", "medium").lower(),
                    "line": finding.get("first_markdown_element", ""),
                    "description": finding.get("description", ""),
                    "match": finding.get("check", ""),
                    "context": finding.get("first_markdown_element", "")
                })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        pass
    return results


def analyze_semgrep(file_path: str) -> List[Dict]:
    results = []
    try:
        result = subprocess.run(
            ["semgrep", "--config=semgrep-rules/solidity/security", file_path, "--json"],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for finding in data.get("results", []):
                results.append({
                    "type": finding.get("check_id", "Unknown"),
                    "severity": "medium",
                    "line": finding.get("start", {}).get("line", 0),
                    "description": finding.get("extra", {}).get("message", ""),
                    "match": finding.get("path", ""),
                    "context": finding.get("extra", {}).get("lines", "")
                })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        pass
    return results


def analyze_all(code: str, file_path: str = None) -> Dict:
    return {
        "patterns": analyze_patterns(code),
        "slither": analyze_slither(file_path) if file_path else [],
        "semgrep": analyze_semgrep(file_path) if file_path else []
    }
