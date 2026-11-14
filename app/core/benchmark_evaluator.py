from typing import Dict, Any, List
from app.data.benchmark_dataset import BENCHMARK_CASES
from app.core.forensics import analyze_offer

def run_benchmark_evaluation() -> Dict[str, Any]:
    """
    Evaluates OfferShield AI against the 50-item synthetic benchmark dataset.
    Computes confusion matrix, precision, recall, and false positive metrics.
    """
    total = len(BENCHMARK_CASES)
    tp = 0 # Malicious correctly flagged (Risk score >= 50)
    fp = 0 # Genuine incorrectly flagged as High Risk (Risk score >= 50)
    tn = 0 # Genuine correctly left alone (Risk score < 50)
    fn = 0 # Malicious missed (Risk score < 50)
    
    detailed_results: List[Dict[str, Any]] = []
    
    for case in BENCHMARK_CASES:
        result = analyze_offer(
            raw_text=case["text"],
            sender_email=case["sender_email"],
            claimed_company=case["claimed_company"]
        )
        score = result["risk_score"]
        is_predicted_threat = score >= 50 # Threshold for malicious / high risk
        expected = case["expected_label"]
        
        outcome_status = ""
        if expected == "MALICIOUS":
            if is_predicted_threat:
                tp += 1
                outcome_status = "TRUE_POSITIVE"
            else:
                fn += 1
                outcome_status = "FALSE_NEGATIVE"
        elif expected == "GENUINE":
            if is_predicted_threat:
                fp += 1
                outcome_status = "FALSE_POSITIVE"
            else:
                tn += 1
                outcome_status = "TRUE_NEGATIVE"
                
        detailed_results.append({
            "id": case["id"],
            "title": case["title"],
            "sender_email": case["sender_email"],
            "claimed_company": case["claimed_company"],
            "expected_label": expected,
            "predicted_score": score,
            "predicted_verdict": result["verdict"],
            "outcome": outcome_status,
            "top_signal": result["signals"][0]["title"] if result["signals"] else "No threat signals detected"
        })
        
    precision = round((tp / (tp + fp)) * 100, 1) if (tp + fp) > 0 else 0.0
    recall = round((tp / (tp + fn)) * 100, 1) if (tp + fn) > 0 else 0.0
    f1 = round((2 * precision * recall) / (precision + recall), 1) if (precision + recall) > 0 else 0.0
    accuracy = round(((tp + tn) / total) * 100, 1)
    false_alarm_rate = round((fp / (fp + tn)) * 100, 1) if (fp + tn) > 0 else 0.0

    return {
        "metrics": {
            "total_samples": total,
            "malicious_samples": 25,
            "genuine_samples": 25,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "precision_percent": precision,
            "recall_percent": recall,
            "f1_score": f1,
            "accuracy_percent": accuracy,
            "false_alarm_rate_percent": false_alarm_rate
        },
        "summary": f"Evaluated {total} samples: Detected {tp}/25 threats ({recall}% recall) with only {fp} false alarm(s) ({precision}% precision).",
        "detailed_results": detailed_results
    }
