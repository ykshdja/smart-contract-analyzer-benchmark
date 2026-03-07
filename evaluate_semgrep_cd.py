import os
import subprocess
import pandas as pd

# ===== CONFIG =====
SOLIDITY_FOLDER = "SCRUBD/SCRUBD-CD/data/solidity_codes"
LABELS_FILE = "SCRUBD/SCRUBD-CD/data/labels.csv"
SEMGREP_RULES = "semgrep-rules/solidity/security"

# ===== LOAD LABELS =====
labels = pd.read_csv(LABELS_FILE)

TP = FP = TN = FN = 0
processed = 0
failed = 0

for index, row in labels.iterrows():

    contract = row["Smart Contract"]
    ground_truth = row["RE"]

    filename = os.path.join(SOLIDITY_FOLDER, f"{contract}.sol")

    if not os.path.exists(filename):
        continue

    print(f"\nProcessing {contract}.sol")

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config",
                SEMGREP_RULES,
                filename
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout.lower()

    except:
        print("Semgrep failed.")
        failed += 1
        continue

    processed += 1

    # ===== DETECT REENTRANCY =====
    semgrep_detected = "reentrancy" in output

    # ===== CONFUSION MATRIX =====
    if ground_truth == 1 and semgrep_detected:
        TP += 1
    elif ground_truth == 0 and semgrep_detected:
        FP += 1
    elif ground_truth == 0 and not semgrep_detected:
        TN += 1
    elif ground_truth == 1 and not semgrep_detected:
        FN += 1


# ===== RESULTS =====
print("\n===== FINAL RESULTS =====")
print("Processed:", processed)
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