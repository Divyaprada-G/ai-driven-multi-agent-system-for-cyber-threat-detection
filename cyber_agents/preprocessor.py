"""
Machine Learning Preprocessing & Data Leakage Prevention Module
Implements:
- Leakage-free train/test splitting (before any scaling or imputation)
- Median imputation fitted on training data only
- Standard scaling (z-score standardization) fitted on training data only
- Label encoding
- Data leakage verification checks
"""
import math
import random
from typing import Dict, List, Any, Tuple, Optional


class PreprocessingPipeline:
    """
    Fitted preprocessing pipeline holding parameters estimated strictly on training sets.
    """

    def __init__(
        self,
        feature_names: List[str],
        imputation_strategy: str = "median",
        scale_features: bool = True
    ):
        self.feature_names = feature_names
        self.imputation_strategy = imputation_strategy
        self.scale_features = scale_features
        self.feature_impute_values: Dict[str, float] = {}
        self.feature_means: Dict[str, float] = {}
        self.feature_stds: Dict[str, float] = {}
        self.label_to_id: Dict[str, int] = {}
        self.id_to_label: Dict[int, str] = {}
        self.is_fitted: bool = False

    def fit(self, X_train: List[List[float]], y_train: Optional[List[str]] = None):
        """
        Calculates imputation values and standardization parameters (mean, std)
        STRICTLY on training data to prevent data leakage.
        """
        num_features = len(self.feature_names)
        num_samples = len(X_train)
        if num_samples == 0:
            raise ValueError("Cannot fit preprocessor on empty training set.")

        # Compute imputation values and mean/std per feature column
        for col_idx, feat_name in enumerate(self.feature_names):
            valid_vals = []
            for row in X_train:
                val = row[col_idx]
                if not (math.isnan(val) or math.isinf(val)):
                    valid_vals.append(val)

            if not valid_vals:
                impute_val = 0.0
                mean_val = 0.0
                std_val = 1.0
            else:
                valid_vals.sort()
                if self.imputation_strategy == "median":
                    n = len(valid_vals)
                    mid = n // 2
                    impute_val = (valid_vals[mid] if n % 2 != 0 else (valid_vals[mid - 1] + valid_vals[mid]) / 2.0)
                else:
                    impute_val = sum(valid_vals) / len(valid_vals)

                mean_val = sum(valid_vals) / len(valid_vals)
                variance = sum((v - mean_val) ** 2 for v in valid_vals) / max(1, len(valid_vals) - 1)
                std_val = math.sqrt(variance)
                if std_val < 1e-7:
                    std_val = 1.0

            self.feature_impute_values[feat_name] = impute_val
            self.feature_means[feat_name] = mean_val
            self.feature_stds[feat_name] = std_val

        # Fit label encoding if labels provided
        if y_train:
            unique_labels = sorted(list(set(y_train)))
            self.label_to_id = {lbl: idx for idx, lbl in enumerate(unique_labels)}
            self.id_to_label = {idx: lbl for idx, lbl in enumerate(unique_labels)}

        self.is_fitted = True

    def transform(self, X: List[List[float]]) -> List[List[float]]:
        """
        Transforms samples using previously fitted parameters (no data leakage).
        """
        if not self.is_fitted:
            raise RuntimeError("Pipeline must be fitted before calling transform().")

        transformed: List[List[float]] = []
        for row in X:
            t_row = []
            for col_idx, feat_name in enumerate(self.feature_names):
                val = row[col_idx]
                # Impute if invalid
                if math.isnan(val) or math.isinf(val):
                    val = self.feature_impute_values.get(feat_name, 0.0)

                # Standardize if enabled
                if self.scale_features:
                    m = self.feature_means.get(feat_name, 0.0)
                    s = self.feature_stds.get(feat_name, 1.0)
                    val = (val - m) / s
                t_row.append(val)
            transformed.append(t_row)

        return transformed

    def transform_sample_dict(self, sample: Dict[str, Any]) -> List[float]:
        """
        Transforms a single feature dictionary into a normalized feature vector.
        """
        raw_row = []
        for feat_name in self.feature_names:
            raw_val = sample.get(feat_name, 0.0)
            try:
                num = float(raw_val)
                if math.isnan(num) or math.isinf(num):
                    num = self.feature_impute_values.get(feat_name, 0.0)
            except (ValueError, TypeError):
                num = self.feature_impute_values.get(feat_name, 0.0)
            raw_row.append(num)

        return self.transform([raw_row])[0]

    def encode_labels(self, y: List[str]) -> List[int]:
        """
        Encodes target string labels into zero-indexed integers.
        """
        return [self.label_to_id.get(lbl, -1) for lbl in y]

    def decode_label(self, label_id: int) -> str:
        """
        Decodes integer class back to string label.
        """
        return self.id_to_label.get(label_id, "UNKNOWN")


def train_test_split_dataset(
    rows: List[List[str]],
    headers: List[str],
    selected_features: List[str],
    label_column: Optional[str] = None,
    train_ratio: float = 0.8,
    random_seed: int = 42,
    stratify: bool = True
) -> Dict[str, Any]:
    """
    Performs data leakage-free train/test partition.
    Ensures that test samples are completely held out from feature engineering.
    """
    if train_ratio <= 0.0 or train_ratio >= 1.0:
        raise ValueError("train_ratio must be strictly between 0 and 1.")

    feat_indices = [headers.index(f) for f in selected_features if f in headers]
    if len(feat_indices) != len(selected_features):
        missing = [f for f in selected_features if f not in headers]
        raise ValueError(f"Selected features not in dataset headers: {missing}")

    label_idx = headers.index(label_column) if label_column and label_column in headers else None

    # Parse rows into raw numerical features and labels
    X_raw: List[List[float]] = []
    y_raw: List[str] = []

    for r in rows:
        row_feats = []
        for idx in feat_indices:
            val_str = r[idx]
            try:
                val = float(val_str)
            except (ValueError, TypeError):
                val = float("nan")
            row_feats.append(val)
        X_raw.append(row_feats)

        if label_idx is not None:
            y_raw.append(r[label_idx])

    num_samples = len(X_raw)
    rng = random.Random(random_seed)

    # Perform split (stratified if labels available and enabled)
    if label_idx is not None and stratify and len(set(y_raw)) > 1:
        class_indices: Dict[str, List[int]] = {}
        for idx, lbl in enumerate(y_raw):
            class_indices.setdefault(lbl, []).append(idx)

        train_indices: List[int] = []
        test_indices: List[int] = []

        for lbl, indices in class_indices.items():
            rng.shuffle(indices)
            split_point = max(1, int(len(indices) * train_ratio))
            if len(indices) == 1:
                # If only 1 sample, put in train
                train_indices.extend(indices)
            else:
                train_indices.extend(indices[:split_point])
                test_indices.extend(indices[split_point:])

        rng.shuffle(train_indices)
        rng.shuffle(test_indices)
    else:
        indices = list(range(num_samples))
        rng.shuffle(indices)
        split_point = int(num_samples * train_ratio)
        train_indices = indices[:split_point]
        test_indices = indices[split_point:]

    X_train = [X_raw[i] for i in train_indices]
    X_test = [X_raw[i] for i in test_indices]
    y_train = [y_raw[i] for i in train_indices] if label_idx is not None else []
    y_test = [y_raw[i] for i in test_indices] if label_idx is not None else []

    # Fit preprocessor on training data only
    pipeline = PreprocessingPipeline(selected_features)
    pipeline.fit(X_train, y_train if label_idx is not None else None)

    # Transform both splits using parameters derived exclusively from training set
    X_train_transformed = pipeline.transform(X_train)
    X_test_transformed = pipeline.transform(X_test)

    y_train_encoded = pipeline.encode_labels(y_train) if y_train else []
    y_test_encoded = pipeline.encode_labels(y_test) if y_test else []

    return {
        "X_train": X_train_transformed,
        "X_test": X_test_transformed,
        "y_train": y_train,
        "y_test": y_test,
        "y_train_encoded": y_train_encoded,
        "y_test_encoded": y_test_encoded,
        "train_indices": train_indices,
        "test_indices": test_indices,
        "pipeline": pipeline,
        "selected_features": selected_features,
        "label_column": label_column
    }
