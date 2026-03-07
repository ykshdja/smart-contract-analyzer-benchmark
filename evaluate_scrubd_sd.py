import os
import subprocess
import json
import pandas as pd
import re

# ===== CONFIG =====
SOL_DIR = "SCRUBD/SCRUBD-SD/data/solidity_codes"
LABEL_FILE = "SCRUBD/SCRUBD-SD/data/labels.csv"
TEMP_JSON = "temp_slither.json"

TP = FP = TN = FN = 0
compiled = 0
failed = 0

# ===== LOAD LABELS =====
labels = pd.read_csv(LABEL_FILE)

def detect_version(file_path):
    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            if "pragma solidity" in line:
                match = re.search(r"(\d+\.\d+\.\d+)", line)
                if match:
                    return match.group(1)

                match2 = re.search(r"(\d+\.\d+)", line)
                if match2:
                    return match2.group(1) + ".0"

    return None


for _, row in labels.iterrows():

    file_name = row["Smart Contract"]
    ground_truth = row["RE"]

    sol_file = os.path.join(SOL_DIR, file_name)

    if not os.path.exists(sol_file):
        continue

    print(f"\nProcessing {file_name}")

    version = detect_version(sol_file)

    if version is None:
        print("No pragma found.")
        failed += 1
        continue

    print("Detected pragma version:", version)

    subprocess.run(
        f"solc-select use {version}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if os.path.exists(TEMP_JSON):
        os.remove(TEMP_JSON)

    try:
        subprocess.run(
            f"slither {sol_file} --json {TEMP_JSON}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60
        )
    except subprocess.TimeoutExpired:
        failed += 1
        continue

    if not os.path.exists(TEMP_JSON):
        failed += 1
        continue

    try:
        with open(TEMP_JSON) as f:
            data = json.load(f)
    except:
        failed += 1
        continue

    compiled += 1

    slither_detected = False

    detectors = data.get("results", {}).get("detectors", [])

    for d in detectors:
        check = d.get("check", "").lower()

        if "reentrancy" in check:
            slither_detected = True
            break

    # ===== CONFUSION MATRIX =====
    if ground_truth == 1 and slither_detected:
        TP += 1
    elif ground_truth == 0 and slither_detected:
        FP += 1
    elif ground_truth == 0 and not slither_detected:
        TN += 1
    elif ground_truth == 1 and not slither_detected:
        FN += 1


# ===== RESULTS =====
print("\n===== FINAL RESULTS =====")
print("Compiled:", compiled)
print("Failed:", failed)

print("TP:", TP)
print("FP:", FP)
print("TN:", TN)
print("FN:", FN)

precision = TP / (TP + FP) if TP + FP > 0 else 0
recall = TP / (TP + FN) if TP + FN > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0

print("Precision:", precision)
print("Recall:", recall)
print("F1-score:", f1)