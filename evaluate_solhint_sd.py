import os
import subprocess
import pandas as pd

# ===== CONFIG =====
SOL_DIR = "SCRUBD/SCRUBD-SD/data/solidity_codes"
LABEL_FILE = "SCRUBD/SCRUBD-SD/data/labels.csv"
SOLHINT_BIN = "./node_modules/.bin/solhint"

TP = FP = TN = FN = 0
processed = 0
failed = 0

# ===== LOAD LABELS =====
labels = pd.read_csv(LABEL_FILE)

# group functions → contract level
contracts = labels.groupby("Smart Contract")["RE"].max().reset_index()

for _, row in contracts.iterrows():

    contract = row["Smart Contract"]
    ground_truth = row["RE"]

    sol_file = os.path.join(SOL_DIR, contract)

    if not os.path.exists(sol_file):
        continue

    print(f"Processing {contract}")

    try:
        result = subprocess.run(
            [SOLHINT_BIN, sol_file],
            capture_output=True,
            text=True
        )
    except Exception as e:
        print("Execution error:", e)
        failed += 1
        continue

    output = result.stdout + result.stderr
    processed += 1

    solhint_detected = False

    # detect reentrancy rule
    if "reentrancy" in output.lower():
        solhint_detected = True

    # ===== CONFUSION MATRIX =====
    if ground_truth == 1 and solhint_detected:
        TP += 1
    elif ground_truth == 0 and solhint_detected:
        FP += 1
    elif ground_truth == 0 and not solhint_detected:
        TN += 1
    elif ground_truth == 1 and not solhint_detected:
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