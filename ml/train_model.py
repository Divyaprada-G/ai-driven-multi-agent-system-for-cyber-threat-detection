#!/usr/bin/env python3
"""
CLI Training Script for AI-Driven Multi-Agent Cyber Threat Detection
Executes genuine machine learning training on cybersecurity datasets:
- Random Forest for Supervised Classification (Accuracy, Precision, Recall, F1, Confusion Matrix)
- Isolation Forest for Unsupervised Anomaly Detection

Usage:
  python3 ml/train_model.py [DATASET_CSV] [LABEL_COLUMN] [--model-type random_forest|isolation_forest] [--trees N] [--seed S]
"""
import sys
import os
import argparse
import json

# Ensure project root is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from cyber_agents.ml_pipeline import MLPipeline


def main():
    parser = argparse.ArgumentParser(description="Train Cybersecurity Threat Detection Models")
    parser.add_argument("dataset", nargs="?", default="data/test_dataset_cicids2017.csv", help="Path to dataset CSV")
    parser.add_argument("label_col", nargs="?", default="Label", help="Target label column (for Random Forest)")
    parser.add_argument("--model-type", choices=["random_forest", "isolation_forest"], default="random_forest", help="Model algorithm")
    parser.add_argument("--trees", type=int, default=30, help="Number of trees (estimators)")
    parser.add_argument("--depth", type=int, default=8, help="Max tree depth")
    parser.add_argument("--split", type=float, default=0.8, help="Train/test split ratio (0.1 to 0.9)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--contamination", type=float, default=0.05, help="Contamination rate for Isolation Forest")

    args = parser.parse_args()

    dataset_path = args.dataset
    if not os.path.isabs(dataset_path):
        dataset_path = os.path.join(root_dir, dataset_path)

    if not os.path.exists(dataset_path):
        print(f"Error: Dataset file not found at: {dataset_path}")
        sys.exit(1)

    print("=================================================================")
    print("AI-Driven Multi-Agent System — Machine Learning Engine")
    print("=================================================================")
    print(f"Dataset: {dataset_path}")
    print(f"Algorithm: {args.model_type.upper()}")
    print(f"Random Seed: {args.seed}")
    print("Validating dataset and enforcing data leakage prevention...")

    pipeline = MLPipeline()

    try:
        if args.model_type == "random_forest":
            print(f"Target Label Column: {args.label_col}")
            print(f"Train/Test Partition: {int(args.split * 100)}% Train / {int((1 - args.split) * 100)}% Held-out Test")
            print("Fitting preprocessor strictly on training split...")
            print(f"Training {args.trees} decision trees with bagging and feature subspace sampling...")

            artifact = pipeline.train_random_forest(
                dataset_input=dataset_path,
                label_column=args.label_col,
                train_ratio=args.split,
                random_seed=args.seed,
                n_estimators=args.trees,
                max_depth=args.depth
            )

            metrics = artifact["evaluationMetrics"]
            print("\n-----------------------------------------------------------------")
            print("TRAINING & EVALUATION SUCCESSFUL (HELD-OUT TEST SET):")
            print("-----------------------------------------------------------------")
            print(f"Model ID:            {artifact['modelId']}")
            print(f"Model Version:       {artifact['modelVersion']}")
            print(f"Training Samples:    {artifact['trainRows']}")
            print(f"Test Samples:        {artifact['testRows']}")
            print(f"Accuracy:            {metrics['accuracy'] * 100:.2f}%")
            print(f"Macro Precision:     {metrics['macroPrecision'] * 100:.2f}%")
            print(f"Macro Recall:        {metrics['macroRecall'] * 100:.2f}%")
            print(f"Macro F1-Score:      {metrics['macroF1'] * 100:.2f}%")
            print(f"Weighted F1-Score:   {metrics['weightedF1'] * 100:.2f}%")

            print("\nConfusion Matrix:")
            labels = metrics["confusionMatrix"]["labels"]
            print("  " + "  ".join(f"{lbl[:10]:>10}" for lbl in labels))
            for i, row in enumerate(metrics["confusionMatrix"]["matrix"]):
                row_str = "  ".join(f"{val:>10}" for val in row)
                print(f"{labels[i][:10]:>10}: {row_str}")

            print("\nTop Contributing Features:")
            for f in metrics["featureImportances"][:5]:
                print(f"  {f['rank']}. {f['feature']:<30} (importance: {f['importance']:.4f})")

        else:
            print(f"Training Isolation Forest with contamination: {args.contamination}...")
            artifact = pipeline.train_isolation_forest(
                dataset_input=dataset_path,
                contamination=args.contamination,
                n_estimators=args.trees,
                random_seed=args.seed
            )

            print("\n-----------------------------------------------------------------")
            print("ISOLATION FOREST TRAINING SUCCESSFUL:")
            print("-----------------------------------------------------------------")
            print(f"Model ID:            {artifact['modelId']}")
            print(f"Total Samples:       {artifact['trainRows']}")
            print(f"Features Analyzed:   {artifact['featureCount']}")
            print(f"Anomaly Threshold:   {artifact.get('anomalyThreshold', 0.5):.4f}")
            print(f"Notes:               {artifact['notes']}")

        print(f"\nArtifact saved to: ml/artifacts/{artifact['modelId']}/")
        print("=================================================================")

    except Exception as e:
        print(f"\nTraining failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
