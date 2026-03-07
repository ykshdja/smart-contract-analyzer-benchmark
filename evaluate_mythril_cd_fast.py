import os
import subprocess
import pandas as pd
from multiprocessing import Pool, cpu_count

# ===== CONFIG =====
SOL_DIR = "SCRUBD/SCRUBD-CD/data/solidity_codes"
LABEL_FILE = "SCRUBD/SCRUBD-CD/data/labels.csv"

EXEC_TIMEOUT = "10"


def analyze_contract(args):

    contract, ground_truth = args

    sol_file = os.path.join(SOL_DIR, f"{contract}.sol")

    if not os.path.exists(sol_file):
        return None

    try:
        result = subprocess.run(
            [
                "myth",
                "analyze",
                sol_file,
                "--execution-timeout",
                EXEC_TIMEOUT,
                "--no-onchain-data"
            ],
            capture_output=True,
            text=True
        )

        output = result.stdout + result.stderr

        detected = "SWC ID: 107" in output

        return ground_truth, detected

    except Exception:
        return None


if __name__ == "__main__":

    # ===== LOAD LABELS =====
    labels = pd.read_csv(LABEL_FILE)

    contracts = labels.groupby("Smart Contract")["RE"].max().reset_index()

    inputs = [(row["Smart Contract"], row["RE"]) for _, row in contracts.iterrows()]

    print("Running Mythril on", len(inputs), "contracts using", cpu_count(), "cores")

    with Pool(cpu_count()) as pool:
        results = pool.map(analyze_contract, inputs)

    TP = FP = TN = FN = 0
    processed = 0

    for r in results:
        if r is None:
            continue

        ground_truth, detected = r
        processed += 1

        if ground_truth == 1 and detected:
            TP += 1
        elif ground_truth == 0 and detected:
            FP += 1
        elif ground_truth == 0 and not detected:
            TN += 1
        elif ground_truth == 1 and not detected:
            FN += 1

    precision = TP / (TP + FP) if TP + FP else 0
    recall = TP / (TP + FN) if TP + FN else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0

    print("\n===== FINAL RESULTS =====")
    print("Processed:", processed)

    print("TP:", TP)
    print("FP:", FP)
    print("TN:", TN)
    print("FN:", FN)

    print("Precision:", precision)
    print("Recall:", recall)
    print("F1-score:", f1)