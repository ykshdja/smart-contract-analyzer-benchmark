import json
import os
import glob
import sys
from backend.analyzer import analyze_all

OUTPUT_FILE = "results.json"


def extract_actual_vulnerability(filename: str) -> str:
    filename_lower = filename.lower()
    if "reentrancy" in filename_lower:
        return "reentrancy"
    elif "overflow" in filename_lower:
        return "overflow"
    elif "access" in filename_lower:
        return "access_control"
    elif "txorigin" in filename_lower or "tx_origin" in filename_lower:
        return "tx_origin"
    elif "delegatecall" in filename_lower:
        return "delegatecall"
    elif "unprotected" in filename_lower:
        return "unprotected"
    return "unknown"


def analyze_file_direct(file_path: str) -> dict:
    with open(file_path, "r") as f:
        code = f.read()
    
    # Call the backend analyzer directly
    analysis_result = analyze_all(code, file_path)
    return analysis_result


def main(folder_path: str):
    sol_files = glob.glob(os.path.join(folder_path, "*.sol"))
    total = len(sol_files)
    results = []

    print(f"Found {total} .sol files")

    for i, file_path in enumerate(sol_files, 1):
        filename = os.path.basename(file_path)
        actual_vuln = extract_actual_vulnerability(filename)

        try:
            analysis = analyze_file_direct(file_path)
            result = {
                "file": filename,
                "actual_vulnerability": actual_vuln,
                "analysis": analysis,
            }
            results.append(result)
            print(f"Processed {i}/{total} files: {filename}")
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            results.append({
                "file": filename,
                "actual_vulnerability": actual_vuln,
                "error": str(e),
            })

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_folder_direct.py <folder_path>")
        sys.exit(1)
    main(sys.argv[1])