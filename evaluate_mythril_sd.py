import os
import subprocess
import pandas as pd

# ===== CONFIG =====
SOLIDITY_FOLDER = "SCRUBD/SCRUBD-SD/data/solidity_codes"
LABELS_FILE = "SCRUBD/SCRUBD-SD/data/labels.csv"
MYTHRIL_CMD = "myth"
TIMEOUT = 20

labels = pd.read_csv(LABELS_FILE)

# first column holds contract filenames
contract_column = labels.columns[0]

contracts = labels[contract_column].unique()

TP = FP = TN = FN = 0
processed = 0
failed = 0


for contract in contracts:

    filename = os.path.join(SOLIDITY_FOLDER, contract)

    if not os.path.exists(filename):
        print("Missing:", filename)
        continue

    print("Processing:", contract)

    try:
        result = subprocess.run(
            [
                MYTHRIL_CMD,
                "analyze",
                filename,
                "--execution-timeout",
                str(TIMEOUT)
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT + 10
        )

        output = (result.stdout + result.stderr).lower()

    except Exception as e:
        print("Error:", e)
        failed += 1
        continue

    processed += 1

    # Mythril reentrancy identifier
    mythril_detected = "swc id: 107" in output or "reentrancy" in output

    # contract vulnerable if ANY function labeled RE=1
    contract_rows = labels[labels[contract_column] == contract]
    ground_truth = 1 if contract_rows["RE"].sum() > 0 else 0

    if ground_truth == 1 and mythril_detected:
        TP += 1
    elif ground_truth == 0 and mythril_detected:
        FP += 1
    elif ground_truth == 0 and not mythril_detected:
        TN += 1
    elif ground_truth == 1 and not mythril_detected:
        FN += 1


print("\n===== FINAL RESULTS =====")
print("Processed:", processed)
print("Failed:", failed)
print("TP:", TP)
print("FP:", FP)
print("TN:", TN)
print("FN:", FN)

precision = TP/(TP+FP) if TP+FP>0 else 0
recall = TP/(TP+FN) if TP+FN>0 else 0
f1 = 2*precision*recall/(precision+recall) if precision+recall>0 else 0

print("Precision:", precision)
print("Recall:", recall)
print("F1-score:", f1)