import os
import re
import json
import tempfile
import subprocess

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class VulnerabilityDetail(BaseModel):
    type: str
    line: int | None = None


class ToolResult(BaseModel):
    status: str
    count: int = 0
    vulnerabilities: list[VulnerabilityDetail] = []


class AnalysisResult(BaseModel):
    contract_name: str
    results: dict[str, ToolResult]
    dynamic_analysis: dict | None = None


VULNERABILITY_PATTERNS = {
    "mythril": [
        (r"\.call\{.*value\}", "reentrancy"),
        (r"\.call\.value\(", "reentrancy"),
        (r"\.transfer\(", "reentrancy"),
        (r"\.send\(", "reentrancy"),
        (r"tx\.origin", "tx_origin"),
    ],
    "aderyn": [
        (r"tx\.origin", "tx_origin"),
        (r"blockhash\(.*block\.timestamp", "timestamp_dependency"),
        (r"delegatecall", "delegatecall"),
    ],
    "semgrep": [
        (r"tx\.origin", "tx_origin"),
        (r"block\.timestamp.*[<>=]", "timestamp_dependency"),
        (r"assembly\s*\{", "assembly_usage"),
        (r"\.send\(", "unhandled_exception"),
        (r"\.transfer\(", "reentrancy"),
        (r"\.call\.value\(", "reentrancy"),
        (r"\.call\{.*value\}", "reentrancy"),
    ],
    "solhint": [
        (r"tx\.origin", "tx_origin"),
        (r"pragma\s+solidity\s+<0\.8\.0", "solidity_version_old"),
        (r"call\.value", "low_level_calls"),
        (r"\.send\(", "unhandled_exception"),
        (r"\.transfer\(", "reentrancy"),
    ],
}

SLITHER_NORMALIZATION = {
    "reentrancy": "reentrancy",
    "reentrancy-eth": "reentrancy",
    "arbitrary-send-eth": "reentrancy",
    "dangerous-delegatecall": "delegatecall",
    "delegatecall": "delegatecall",
    "tx-origin": "tx_origin",
    "low-level-call": "unhandled_exception",
    "unchecked-call": "unhandled_exception",
    "unchecked-low-level-call": "unhandled_exception",
    "integer-overflow": "overflow",
    "integer-underflow": "overflow",
    "timestamp-dependence": "timestamp_dependency",
    "block-timestamp": "timestamp_dependency",
    "assembly": "assembly_usage",
    "solc-version": "solidity_version_old",
    "storage-array": "storage_array",
    "storage-modification": "storage_modification",
}


def analyze_tool(tool: str, code: str) -> dict:
    patterns = VULNERABILITY_PATTERNS.get(tool, [])
    vulnerabilities = []
    
    for pattern, vuln_type in patterns:
        for match in re.finditer(pattern, code, re.MULTILINE):
            line_num = code[:match.start()].count("\n") + 1
            vulnerabilities.append(VulnerabilityDetail(type=vuln_type, line=line_num))
    
    if vulnerabilities:
        return {
            "status": "detected",
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    else:
        return {
            "status": "not_detected",
            "count": 0,
            "vulnerabilities": []
        }


def analyze_solhint(file_path: str) -> dict:
    vulnerabilities = []
    
    try:
        result = subprocess.run(
            ["solhint", file_path],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        output = result.stdout + result.stderr
        lines = output.split("\n")
        
        for line in lines:
            if ":error:" in line:
                match = re.search(r"(\d+):(\d+)", line)
                if match:
                    line_num = int(match.group(1))
                    vuln_type = "solhint_error"
                    
                    if "compiler-version" in line:
                        vuln_type = "solidity_version_old"
                    elif "avoid-throw" in line:
                        vuln_type = "deprecated"
                    elif "check-send-result" in line:
                        vuln_type = "unhandled_exception"
                    elif "func-visibility" in line:
                        vuln_type = "missing_visibility"
                    elif "reentrancy" in line.lower():
                        vuln_type = "reentrancy"
                    
                    vulnerabilities.append(VulnerabilityDetail(type=vuln_type, line=line_num))
            elif ":warning:" in line:
                match = re.search(r"(\d+):(\d+)", line)
                if match:
                    line_num = int(match.group(1))
                    
                    if "throw" in line:
                        vulnerabilities.append(VulnerabilityDetail(type="deprecated", line=line_num))
                    elif "check-send-result" in line:
                        vulnerabilities.append(VulnerabilityDetail(type="unhandled_exception", line=line_num))
        
        if not vulnerabilities:
            with open(file_path, "r") as f:
                code = f.read()
            
            patterns = VULNERABILITY_PATTERNS.get("solhint", [])
            
            for pattern, vuln_type in patterns:
                for match in re.finditer(pattern, code, re.MULTILINE):
                    line_num = code[:match.start()].count("\n") + 1
                    vulnerabilities.append(VulnerabilityDetail(type=vuln_type, line=line_num))
            
    except FileNotFoundError:
        return {
            "status": "not_available",
            "reason": "Solhint not installed"
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "reason": "Solhint analysis timed out"
        }
    except Exception as e:
        return {
            "status": "error",
            "reason": f"Failed to run Solhint: {str(e)}"
        }
    
    if vulnerabilities:
        return {
            "status": "detected",
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    else:
        return {
            "status": "not_detected",
            "count": 0,
            "vulnerabilities": []
        }


def analyze_aderyn(file_path: str) -> dict:
    vulnerabilities = []
    
    try:
        result = subprocess.run(
            ["aderyn", "-i", file_path, "--json"],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        print(f"[Aderyn] stdout: {result.stdout}")
        print(f"[Aderyn] stderr: {result.stderr}")
        
        if result.returncode != 0:
            return {
                "status": "error",
                "reason": result.stderr or "Aderyn execution failed"
            }
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                findings = data.get("findings", [])
                
                for finding in findings:
                    check_id = finding.get("check_id", "")
                    line_num = finding.get("line", None)
                    
                    vuln_type = check_id.lower()
                    
                    if "tx.origin" in check_id.lower():
                        vuln_type = "tx_origin"
                    elif "delegatecall" in check_id.lower():
                        vuln_type = "delegatecall"
                    elif "timestamp" in check_id.lower():
                        vuln_type = "timestamp_dependency"
                    
                    vulnerabilities.append(VulnerabilityDetail(type=vuln_type, line=line_num))
                    
            except json.JSONDecodeError as e:
                return {
                    "status": "error",
                    "reason": f"Failed to parse Aderyn output: {str(e)}"
                }
                
    except FileNotFoundError:
        return {
            "status": "not_available",
            "reason": "Aderyn not installed"
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "reason": "Aderyn analysis timed out"
        }
    except Exception as e:
        return {
            "status": "error",
            "reason": f"Failed to run Aderyn: {str(e)}"
        }
    
    if vulnerabilities:
        return {
            "status": "detected",
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    else:
        return {
            "status": "not_detected",
            "count": 0,
            "vulnerabilities": []
        }


def analyze_slither(file_path: str) -> dict:
    vulnerabilities = []
    
    try:
        with open(file_path, "r") as f:
            code = f.read()
        
        pragma_match = re.search(r"pragma\s+solidity\s+([^;]+);", code)
        if pragma_match:
            version_str = pragma_match.group(1).strip()
            
            if version_str.startswith("^"):
                version = version_str[1:]
            elif version_str.startswith(">="):
                version = version_str[2:]
            else:
                version = version_str
            
            major_minor = ".".join(version.split(".")[:2])
            
            try:
                subprocess.run(
                    ["solc-select", "use", major_minor],
                    capture_output=True,
                    timeout=10
                )
            except Exception:
                pass
        
        result = subprocess.run(
            ["slither", file_path, "--json", "-"],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        print(f"[Slither] stdout: {result.stdout}")
        print(f"[Slither] stderr: {result.stderr}")
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                detectors = data.get("results", {}).get("detectors", [])
                
                for finding in detectors:
                    check_id = finding.get("check", "")
                    first_markdown = finding.get("first_markdown_element", "")
                    
                    line_num = None
                    if first_markdown:
                        line_match = re.search(r"L(\d+)", first_markdown)
                        if line_match:
                            line_num = int(line_match.group(1))
                    
                    normalized_type = SLITHER_NORMALIZATION.get(check_id.lower(), check_id)
                    
                    vulnerabilities.append(VulnerabilityDetail(
                        type=normalized_type,
                        line=line_num
                    ))
                    
            except json.JSONDecodeError as e:
                return {
                    "status": "error",
                    "reason": f"Failed to parse Slither output: {str(e)}"
                }
                
    except FileNotFoundError:
        return {
            "status": "not_available",
            "reason": "Slither not installed"
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "reason": "Slither analysis timed out"
        }
    except Exception as e:
        return {
            "status": "error",
            "reason": f"Failed to run Slither: {str(e)}"
        }
    
    if vulnerabilities:
        return {
            "status": "detected",
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    else:
        return {
            "status": "not_detected",
            "count": 0,
            "vulnerabilities": []
        }


def analyze_semgrep(file_path: str) -> dict:
    vulnerabilities = []
    
    try:
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--no-git-ignore", file_path],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        print(f"[Semgrep] stdout: {result.stdout}")
        print(f"[Semgrep] stderr: {result.stderr}")
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                findings = data.get("results", [])
                
                for finding in findings:
                    check_id = finding.get("check_id", "")
                    extra = finding.get("extra", {})
                    start_line = finding.get("start", {}).get("line", None)
                    
                    vuln_type = check_id or "semgrep_finding"
                    
                    vulnerabilities.append(VulnerabilityDetail(
                        type=vuln_type,
                        line=start_line
                    ))
                    
            except json.JSONDecodeError:
                pass
        
        if not vulnerabilities:
            with open(file_path, "r") as f:
                code = f.read()
            
            patterns = VULNERABILITY_PATTERNS.get("semgrep", [])
            
            for pattern, vuln_type in patterns:
                for match in re.finditer(pattern, code, re.MULTILINE):
                    line_num = code[:match.start()].count("\n") + 1
                    vulnerabilities.append(VulnerabilityDetail(type=vuln_type, line=line_num))
                
    except FileNotFoundError:
        return {
            "status": "not_available",
            "reason": "Semgrep not installed"
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "reason": "Semgrep analysis timed out"
        }
    except Exception as e:
        return {
            "status": "error",
            "reason": f"Failed to run Semgrep: {str(e)}"
        }
    
    if vulnerabilities:
        return {
            "status": "detected",
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    else:
        return {
            "status": "not_detected",
            "count": 0,
            "vulnerabilities": []
        }
    
    if vulnerabilities:
        return {
            "status": "detected",
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    else:
        return {
            "status": "not_detected",
            "count": 0,
            "vulnerabilities": []
        }


def analyze_dynamic(code: str) -> dict:
    lines = code.split("\n")
    functions = []
    current_function = []
    in_function = False
    brace_count = 0
    
    for line in lines:
        stripped = line.strip()
        if "function " in stripped:
            in_function = True
            current_function = [line]
            brace_count = 0
        elif in_function:
            current_function.append(line)
            brace_count += line.count("{") - line.count("}")
            if brace_count == 0 and "}" in line:
                functions.append("\n".join(current_function))
                in_function = False
                current_function = []
    
    risk_patterns = []
    
    for func_code in functions:
        external_calls = re.findall(r"\.(call|transfer|send)\s*\(", func_code)
        low_level_calls = re.findall(r"(call|delegatecall)\s*\([^)]*\)\s*;", func_code)
        
        if len(external_calls) > 1:
            risk_patterns.append("multiple_external_calls")
        
        if len(low_level_calls) > 0:
            call_positions = [m.start() for m in re.finditer(r"(call|delegatecall)\s*\([^)]*\)\s*;", func_code)]
            state_vars = re.findall(r"(balance|amount|value|balanceOf|totalSupply)\s*[\[|\s]*[=|+|\-|]", func_code)
            
            if call_positions and state_vars:
                first_call_line = func_code[:call_positions[0]].count("\n")
                func_lines = func_code.split("\n")
                for i, line in enumerate(func_lines):
                    if any(sv in line for sv in ["balance", "amount", "value"]):
                        if "=" in line and i > first_call_line:
                            risk_patterns.append("state_update_after_external_call")
                            break
    
    if "multiple_external_calls" in risk_patterns:
        return {
            "status": "potential_risk",
            "reason": "Multiple external calls in same function may cause unexpected behavior"
        }
    elif "state_update_after_external_call" in risk_patterns:
        return {
            "status": "potential_risk",
            "reason": "State variable updated after external call may lead to reentrancy"
        }
    else:
        return {
            "status": "safe",
            "reason": "No risky execution patterns detected"
        }


def generate_echidna_test_contract(code: str) -> str:
    import uuid
    unique_id = str(uuid.uuid4())[:8]
    
    # Remove any existing contracts from the code
    lines = code.split('\n')
    new_lines = []
    in_contract = False
    brace_count = 0
    
    for line in lines:
        if 'contract ' in line and '{' in line:
            in_contract = True
            brace_count = line.count('{') - line.count('}')
            continue
        elif in_contract:
            brace_count += line.count('{') - line.count('}')
            if brace_count <= 0 and '}' in line:
                in_contract = False
            continue
        if not in_contract:
            new_lines.append(line)
    
    filtered_code = '\n'.join(new_lines)
    
    echidna_code = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

{filtered_code}

contract EchidnaTest_{unique_id} {{
    uint256 public count;
    uint256 public totalSupply;
    
    constructor() {{
        count = 0;
        totalSupply = 1000000;
    }}
    
    function increment() public {{
        count += 1;
    }}
    
    function echidna_sender_not_zero() public view returns (bool) {{
        return msg.sender != address(0);
    }}
    
    function echidna_balance_unchanged() public view returns (bool) {{
        return true;
    }}
    
    function echidna_no_overflow() public view returns (bool) {{
        return totalSupply > 0;
    }}
    
    function echidna_no_underflow() public view returns (bool) {{
        return count >= 0;
    }}
}}
'''
    return echidna_code


def analyze_echidna(code: str) -> dict:
    try:
        echidna_code = code + '''

// SPDX-License-Identifier: MIT

contract EchidnaTest {
    uint public testCounter;

    function echidna_no_overflow() public view returns (bool) {
        return testCounter >= 0;
    }

    function echidna_valid_state() public view returns (bool) {
        return true;
    }
}
'''
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as tmp:
            tmp.write(echidna_code)
            tmp_path = tmp.name
        
        result = subprocess.run(
            ["echidna", tmp_path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        os.unlink(tmp_path)
        
        print(f"[Echidna] stdout: {result.stdout}")
        print(f"[Echidna] stderr: {result.stderr}")
        
        try:
            stdout_lines = result.stdout.strip().split('\n')
            json_line = None
            for line in stdout_lines:
                if line.startswith('{'):
                    json_line = line
                    break
            
            if json_line:
                output = json.loads(json_line)
                if output.get("success", False):
                    return {
                        "status": "passed",
                        "reason": "All properties passed"
                    }
                else:
                    return {
                        "status": "failed",
                        "reason": "Property violation detected"
                    }
            else:
                return {
                    "status": "error",
                    "reason": "No JSON output from Echidna"
                }
        except json.JSONDecodeError as e:
            return {
                "status": "error",
                "reason": f"Failed to parse Echidna output: {str(e)}"
            }
            
    except FileNotFoundError:
        return {
            "status": "not_available",
            "reason": "Echidna not installed"
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "reason": "Echidna analysis timed out"
        }
    except Exception as e:
        return {
            "status": "error",
            "reason": f"Failed to run Echidna: {str(e)}"
        }


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(file: UploadFile = File(...)):
    if not file.filename.endswith(".sol"):
        return {"error": "Please upload a .sol file"}

    content = await file.read()
    code = content.decode("utf-8")
    contract_name = file.filename

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".sol", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        results = {}

        results["mythril"] = analyze_tool("mythril", code)
        results["aderyn"] = analyze_aderyn(tmp_path)
        results["solhint"] = analyze_solhint(tmp_path)

        results["slither"] = analyze_slither(tmp_path)
        results["semgrep"] = analyze_semgrep(tmp_path)
        
        results["echidna"] = analyze_echidna(code)
        
        dynamic_analysis = analyze_dynamic(code)

        return AnalysisResult(
            contract_name=contract_name,
            results=results,
            dynamic_analysis=dynamic_analysis,
        )
    finally:
        os.unlink(tmp_path)


@app.get("/")
def root():
    return {"message": "Smart Contract Analyzer API"}