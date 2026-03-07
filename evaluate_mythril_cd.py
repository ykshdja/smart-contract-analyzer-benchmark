import os
import subprocess
import pandas as pd

# ===== CONFIG =====
SOL_DIR = "SCRUBD/SCRUBD-CD/data/solidity_codes"
LABEL_FILE = "SCRUBD/SCRUBD-CD/data/labels.csv"

TP = FP = TN = FN = 0
compiled = 0
failed = 0

# ===== LOAD LABELS =====
labels = pd.read_csv(LABEL_FILE)

# group by contract
contracts = labels.groupby("Smart Contract")["RE"].max().reset_index()

for _, row in contracts.iterrows():

    contract = row["Smart Contract"]
    ground_truth = row["RE"]

    sol_file = os.path.join(SOL_DIR, f"{contract}.sol")

    if not os.path.exists(sol_file):
        continue

    print(f"\nProcessing {contract}.sol")

    try:

        result = subprocess.run(
            [
                "myth",
                "analyze",
                sol_file,
                "--execution-timeout",
                "20"
            ],
            capture_output=True,
            text=True
        )

    except Exception as e:
        print("Execution error:", e)
        failed += 1
        continue

    output = result.stdout + result.stderr

    compiled += 1

    mythril_detected = False

    if "SWC ID: 107" in output:
        mythril_detected = True

    # ===== CONFUSION MATRIX =====
    if ground_truth == 1 and mythril_detected:
        TP += 1
    elif ground_truth == 0 and mythril_detected:
        FP += 1
    elif ground_truth == 0 and not mythril_detected:
        TN += 1
    elif ground_truth == 1 and not mythril_detected:
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