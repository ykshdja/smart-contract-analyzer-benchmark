The following metrics were computed:

- True Positives (TP)
- False Positives (FP)
- True Negatives (TN)
- False Negatives (FN)

# Tools Evaluated

The following smart contract analyzers were evaluated:

| Tool | Type |
|-----|-----|
Slither | Static Analyzer |
Mythril | Symbolic Execution |
Solhint | Linter |
Semgrep | Pattern-based static analysis |
Aderyn | Static Analyzer |

Some additional tools were investigated but could not be used:

| Tool | Reason |
|----|----|
Sailfish | Installation errors (Matplotlib dependency) |
Manticore | Linux-only compatibility issue |

Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)


How to run: Example -
python evaluate_slither_cd.py
python evaluate_solhint_cd.py
python evaluate_semgrep_cd.py



# Results 
## Slither on SCRUBD/CD

Dataset Ground-Truth

RE = 1 → 245 functions
RE = 0 → 501 functions

===== FINAL RESULTS =====
Total: 746
Compiled: 743
Failed: 3
TP: 239
FP: 504
TN: 0
FN: 0
Precision: 0.32166890982503366
Recall: 1.0
F1-score: 0.48676171079429736

Slither correctly detected
239 of the 245 vulnerable functions
FN = 245 − 239 = 6
Script is not counting FN Correctly 
My Results - 239 + 504 + 0 + 0 = 743

## Slither on SCRUBD/SD
===== FINAL RESULTS =====
Compiled: 240
Failed: 2
TP: 149
FP: 89
TN: 1
FN: 1
Precision: 0.6260504201680672
Recall: 0.9933333333333333
F1-score: 0.768041237113402



## Mythril(symbolic execution)
Mythril is much slower than slither 
==== Unprotected Ether Withdrawal ====
SWC ID: 105
Severity: High
Function: withdraw(uint256)
Reentrancy Corresponds to  - 
SW-105: Unprotected Ether Withdrawal
SW-107: Reentrancy


## Solhint(linter) -  SCRUBD-CD

===== FINAL RESULTS =====
Processed: 469
Failed: 0
TP: 100
FP: 98
TN: 201
FN: 70
Precision: 0.5050505050505051
Recall: 0.5882352941176471
F1-score: 0.5434782608695652


### Mythril - SCRUBD-SD
==== FINAL RESULTS =====
Processed: 16
Failed: 0
TP: 6
FP: 0
TN: 0
FN: 10
Precision: 1.0
Recall: 0.375
F1-score: 0.5454545454545454

## Aderyn

### SCRUBD-CD

===== FINAL RESULTS =====
Processed: 746
Failed: 0
TP: 0
FP: 0
TN: 507
FN: 239
Precision: 0
Recall: 0.0
F1-score: 0

### SCRUBD-SD

===== FINAL RESULTS ===== 
Processed: 16 
Failed: 0 
TP: 0
 FP: 0 
TN: 0 
FN: 16 
Precision: 0 
Recall: 0.0
F1-score: 0


