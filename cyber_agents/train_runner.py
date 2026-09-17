#!/usr/bin/env python3
"""
Python Training Subprocess Runner
Receives JSON payload from stdin, runs the ML training pipeline,
and emits the resulting TrainedModelArtifact JSON to stdout.
"""
import sys
import os
import json

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from cyber_agents.ml_pipeline import MLPipeline


def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            print(json.dumps({"error": "No input provided to training runner."}), file=sys.stderr)
            sys.exit(1)

        payload = json.loads(raw_input)
        algorithm = payload.get("algorithm", "RANDOM_FOREST").upper()
        dataset_path = payload.get("datasetPath")
        raw_csv = payload.get("rawCsv")

        if not dataset_path and not raw_csv:
            dataset_path = os.path.join(root_dir, "data", "test_dataset_cicids2017.csv")

        if dataset_path and not os.path.isabs(dataset_path):
            dataset_path = os.path.join(root_dir, dataset_path)

        pipeline = MLPipeline()
        hyperparameters = payload.get("hyperparameters", {})

        if algorithm == "ISOLATION_FOREST":
            contamination = float(hyperparameters.get("contamination", payload.get("contamination", 0.05)))
            n_estimators = int(hyperparameters.get("n_estimators", 30))
            random_seed = int(payload.get("randomSeed", 42))

            artifact = pipeline.train_isolation_forest(
                dataset_input=raw_csv if raw_csv else dataset_path,
                is_raw_csv=bool(raw_csv),
                selected_features=payload.get("selectedFeatures"),
                excluded_identifiers=payload.get("excludedIdentifiers"),
                contamination=contamination,
                n_estimators=n_estimators,
                random_seed=random_seed
            )
        else:
            label_col = payload.get("labelColumn", "Label")
            train_ratio = float(payload.get("splitRatio", payload.get("trainRatio", 0.8)))
            random_seed = int(payload.get("randomSeed", 42))
            n_estimators = int(hyperparameters.get("n_estimators", 30))
            max_depth = int(hyperparameters.get("max_depth", 8)) if hyperparameters.get("max_depth") else 8

            artifact = pipeline.train_random_forest(
                dataset_input=raw_csv if raw_csv else dataset_path,
                is_raw_csv=bool(raw_csv),
                label_column=label_col,
                selected_features=payload.get("selectedFeatures"),
                excluded_identifiers=payload.get("excludedIdentifiers"),
                train_ratio=train_ratio,
                random_seed=random_seed,
                n_estimators=n_estimators,
                max_depth=max_depth
            )

        # Output serialized artifact
        print(json.dumps(artifact))
        sys.exit(0)

    except Exception as e:
        import traceback
        err_msg = str(e)
        print(json.dumps({"error": err_msg, "trace": traceback.format_exc()}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
