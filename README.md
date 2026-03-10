# Smart Contract Vulnerability Detection — Tool Evaluation Results

This document summarizes the evaluation results of static analysis and symbolic execution tools for reentrancy vulnerability detection across two datasets: **SCRUBD/CD** (compiled dataset) and **SCRUBD/SD** (single dataset).

---

## Dataset Overview

| Dataset   | RE = 1 (Vulnerable) | RE = 0 (Not Vulnerable) | Total |
|-----------|--------------------:|------------------------:|------:|
| SCRUBD/CD | 245                 | 501                     | 746   |
| SCRUBD/SD | —                   | —                       | 242   |

---

## 1. Slither (Static Analysis)

### SCRUBD/CD

> ⚠️ **Note:** The script is not counting FN correctly. Slither correctly detected 239 of 245 vulnerable functions, meaning FN = 245 − 239 = **6**, not 0.

| Metric      | Value   |
|-------------|--------:|
| Total       | 746     |
| Compiled    | 743     |
| Failed      | 3       |
| TP          | 239     |
| FP          | 504     |
| TN          | 0       |
| FN          | **6** *(script reports 0)* |
| Precision   | 0.3217  |
| Recall      | 1.0000  |
| F1-Score    | 0.4868  |

### SCRUBD/SD

| Metric      | Value   |
|-------------|--------:|
| Compiled    | 240     |
| Failed      | 2       |
| TP          | 149     |
| FP          | 89      |
| TN          | 1       |
| FN          | 1       |
| Precision   | 0.6261  |
| Recall      | 0.9933  |
| F1-Score    | 0.7680  |

---

## 2. Mythril (Symbolic Execution)

> ⚠️ Mythril is significantly slower than Slither.

**Relevant SWC Mappings:**

| SWC ID  | Name                         | Severity |
|---------|------------------------------|----------|
| SWC-105 | Unprotected Ether Withdrawal | High     |
| SWC-107 | Reentrancy                   | High     |

### SCRUBD/SD

| Metric      | Value   |
|-------------|--------:|
| Processed   | 16      |
| Failed      | 0       |
| TP          | 6       |
| FP          | 0       |
| TN          | 0       |
| FN          | 10      |
| Precision   | 1.0000  |
| Recall      | 0.3750  |
| F1-Score    | 0.5455  |

---

## 3. Solhint (Linter)

### SCRUBD/CD

| Metric      | Value   |
|-------------|--------:|
| Processed   | 469     |
| Failed      | 0       |
| TP          | 100     |
| FP          | 98      |
| TN          | 201     |
| FN          | 70      |
| Precision   | 0.5051  |
| Recall      | 0.5882  |
| F1-Score    | 0.5435  |

---

## 4. Aderyn

### SCRUBD/CD

| Metric      | Value   |
|-------------|--------:|
| Processed   | 746     |
| Failed      | 0       |
| TP          | 0       |
| FP          | 0       |
| TN          | 507     |
| FN          | 239     |
| Precision   | 0.0000  |
| Recall      | 0.0000  |
| F1-Score    | 0.0000  |

### SCRUBD/SD

| Metric      | Value   |
|-------------|--------:|
| Processed   | 16      |
| Failed      | 0       |
| TP          | 0       |
| FP          | 0       |
| TN          | 0       |
| FN          | 16      |
| Precision   | 0.0000  |
| Recall      | 0.0000  |
| F1-Score    | 0.0000  |

---

## Summary Comparison

### SCRUBD/CD

| Tool    | Precision | Recall | F1-Score | TP  | FP  | TN  | FN      |
|---------|----------:|-------:|---------:|----:|----:|----:|--------:|
| Slither | 0.3217    | 1.0000 | 0.4868   | 239 | 504 | 0   | 6 *(bug)* |
| Solhint | 0.5051    | 0.5882 | 0.5435   | 100 | 98  | 201 | 70      |
| Aderyn  | 0.0000    | 0.0000 | 0.0000   | 0   | 0   | 507 | 239     |

### SCRUBD/SD

| Tool    | Precision | Recall | F1-Score | TP  | FP | TN | FN |
|---------|----------:|-------:|---------:|----:|---:|---:|---:|
| Slither | 0.6261    | 0.9933 | 0.7680   | 149 | 89 | 1  | 1  |
| Mythril | 1.0000    | 0.3750 | 0.5455   | 6   | 0  | 0  | 10 |
| Aderyn  | 0.0000    | 0.0000 | 0.0000   | 0   | 0  | 0  | 16 |
