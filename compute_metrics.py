import json

def load_results():
    with open('results.json', 'r') as f:
        return json.load(f)

def compute_metrics_for_tool(results, tool):
    tp = 0
    fp = 0
    fn = 0
    
    for contract in results:
        actual = contract["actual_vulnerability"]
        if actual == "unknown":
            actual = "none"
        
        tool_result = contract["analysis"]["results"][tool]
        result = tool_result.get("status", "not_detected")
        
        if actual != "none" and result == "detected":
            tp += 1
        elif actual == "none" and result == "detected":
            fp += 1
        elif actual != "none" and result == "not_detected":
            fn += 1
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "fn": fn
    }

def main():
    results = load_results()
    tools = ["semgrep", "solhint", "mythril", "slither"]
    
    for tool in tools:
        metrics = compute_metrics_for_tool(results, tool)
        print(f"Tool: {tool}")
        print(f"Precision: {metrics['precision']:.2f}")
        print(f"Recall: {metrics['recall']:.2f}")
        print(f"F1: {metrics['f1']:.2f}")
        print()

if __name__ == "__main__":
    main()