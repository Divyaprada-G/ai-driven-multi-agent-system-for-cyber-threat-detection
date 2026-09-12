"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Real Model Evaluation Engine
Strict Academic Rigor: All metrics calculated strictly on held-out test predictions.
"""

import numpy as np

def evaluate_classifier(model, X_test, y_test, preprocessor, feature_names):
    """
    Compute authentic test-set performance metrics. Never fabricates values.
    """
    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        confusion_matrix,
        classification_report,
        roc_auc_score
    )

    y_pred = model.predict(X_test)
    label_encoder = preprocessor["label_encoder"]
    class_labels = list(label_encoder.classes_)

    acc = float(accuracy_score(y_test, y_pred))
    macro_p = float(precision_score(y_test, y_pred, average='macro', zero_division=0))
    macro_r = float(recall_score(y_test, y_pred, average='macro', zero_division=0))
    macro_f1 = float(f1_score(y_test, y_pred, average='macro', zero_division=0))

    weighted_p = float(precision_score(y_test, y_pred, average='weighted', zero_division=0))
    weighted_r = float(recall_score(y_test, y_pred, average='weighted', zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average='weighted', zero_division=0))

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=range(len(class_labels)))
    cm_matrix = cm.tolist()

    # Per-class classification report
    report_dict = classification_report(
        y_test,
        y_pred,
        labels=range(len(class_labels)),
        target_names=class_labels,
        output_dict=True,
        zero_division=0
    )

    class_metrics = []
    for cls in class_labels:
        if cls in report_dict:
            entry = report_dict[cls]
            class_metrics.append({
                "className": cls,
                "precision": float(entry["precision"]),
                "recall": float(entry["recall"]),
                "f1Score": float(entry["f1-score"]),
                "support": int(entry["support"])
            })

    # Feature importances
    feature_importances = []
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        numeric_cols = preprocessor["numeric_cols"]
        for idx, imp in enumerate(importances):
            name = numeric_cols[idx] if idx < len(numeric_cols) else f"feature_{idx}"
            feature_importances.append({
                "feature": name,
                "importance": float(imp),
                "rank": 0
            })
        feature_importances.sort(key=lambda x: x["importance"], reverse=True)
        for i, item in enumerate(feature_importances):
            item["rank"] = i + 1

    # Multi-class ROC-AUC if predict_proba is supported
    roc_auc = None
    roc_note = None
    try:
        if hasattr(model, 'predict_proba') and len(class_labels) > 1:
            y_proba = model.predict_proba(X_test)
            if len(class_labels) == 2:
                roc_auc = float(roc_auc_score(y_test, y_proba[:, 1]))
            else:
                roc_auc = float(roc_auc_score(y_test, y_proba, multi_class='ovr', average='weighted'))
    except Exception as e:
        roc_note = "ROC-AUC not applicable for this evaluation configuration."

    return {
        "accuracy": acc,
        "macroPrecision": macro_p,
        "macroRecall": macro_r,
        "macroF1": macro_f1,
        "weightedPrecision": weighted_p,
        "weightedRecall": weighted_r,
        "weightedF1": weighted_f1,
        "rocAuc": roc_auc,
        "rocAucNote": roc_note,
        "confusionMatrix": {
            "labels": class_labels,
            "matrix": cm_matrix,
            "totalSamples": len(y_test)
        },
        "classificationReport": class_metrics,
        "featureImportances": feature_importances,
        "evaluatedOnTestRows": len(y_test),
        "evaluatedAt": ""
    }
