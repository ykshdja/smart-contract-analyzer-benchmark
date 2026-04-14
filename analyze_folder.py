import json
import os
import glob
import csv
import requests

API_URL = "http://127.0.0.1:8001/analyze"
OUTPUT_FILE = "results.json"
LABELS_FILE = "SCRUBD/SCRUBD-CD/data/labels.csv"


def load_labels(labels_path: str) -> dict:
    labels_map = {}
    if os.path.exists(labels_path):
        with open(labels_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                address = row.get('Smart Contract', '').strip().lower()
                re_value = row.get('RE', '').strip()
                ux_value = row.get('UX', '').strip()
                if address:
                    if address not in labels_map:
                        labels_map[address] = set()
                    if re_value == '1':
                        labels_map[address].add('reentrancy')
                    if ux_value == '1':
                        labels_map[address].add('unhandled_exception')
    return labels_map


def extract_actual_vulnerability(filename: str, labels_map: dict) -> str:
    address = filename.replace(".sol", "").strip().lower()
    if address in labels_map and labels_map[address]:
        vulnerabilities = list(labels_map[address])
        return vulnerabilities[0]
    return "unknown"


def analyze_file(file_path: str) -> dict:
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
        response = requests.post(API_URL, files=files)
        response.raise_for_status()
        return response.json()


def main(folder_path: str):
    labels_map = load_labels(LABELS_FILE)
    print(f"Loaded {len(labels_map)} labeled contracts")

    sol_files = glob.glob(os.path.join(folder_path, "*.sol"))
    total = len(sol_files)
    results = []

    print(f"Found {total} .sol files")

    for i, file_path in enumerate(sol_files, 1):
        filename = os.path.basename(file_path)
        actual_vuln = extract_actual_vulnerability(filename, labels_map)

        try:
            analysis = analyze_file(file_path)
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
    import sys
    if len(sys.argv) < 2:
        print("Usage: python analyze_folder.py <folder_path>")
        sys.exit(1)
    main(sys.argv[1])