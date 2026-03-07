import os
import subprocess
import pandas as pd
import shutil
import tempfile

# ===== CONFIG =====
SOLIDITY_FOLDER = "SCRUBD/SCRUBD-CD/data/solidity_codes"
LABELS_FILE = "SCRUBD/SCRUBD-CD/data/labels.csv"
ADERYN_PATH = "/Users/yashkhanduja/.cargo/bin/aderyn"   # adjust if needed

labels = pd.read_csv(LABELS_FILE)

TP = FP = TN = FN = 0
processed = 0
failed = 0


for _, row in labels.iterrows():

    contract = row["Smart Contract"]
    ground_truth = row["RE"]

    filename = os.path.join(SOLIDITY_FOLDER, f"{contract}.sol")

    if not os.path.exists(filename):
        continue

    print("Processing:", contract)

    # create temporary project folder
    temp_dir = tempfile.mkdtemp()

    try:
        temp_file = os.path.join(temp_dir, f"{contract}.sol")
        shutil.copy(filename, temp_file)

        result = subprocess.run(
            [ADERYN_PATH, temp_dir],
            capture_output=True,
            text=True,
            timeout=60
        )

        output = (result.stdout + result.stderr).lower()

    except Exception as e:
        print("Error:", e)
        failed += 1
        shutil.rmtree(temp_dir)
        continue

    processed += 1

    aderyn_detected = "reentrancy" in output

    if ground_truth == 1 and aderyn_detected:
        TP += 1
    elif ground_truth == 0 and aderyn_detected:
        FP += 1
    elif ground_truth == 0 and not aderyn_detected:
        TN += 1
    elif ground_truth == 1 and not aderyn_detected:
        FN += 1

    shutil.rmtree(temp_dir)


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