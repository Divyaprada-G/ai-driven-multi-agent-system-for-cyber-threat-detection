"""
Machine Learning Core Models:
- Random Forest Classifier (Supervised) with Bagging, Subspace Sampling, Gini Impurity,
  and comprehensive Held-Out Test Evaluation (Accuracy, Precision, Recall, F1, Confusion Matrix).
- Isolation Forest (Unsupervised) with Isolation Trees, Average Path Length,
  Anomaly Scoring, and Explainability.
"""
import math
import random
import json
import os
from typing import Dict, List, Any, Tuple, Optional


class TreeNode:
    """Node in a CART Decision Tree."""
    def __init__(
        self,
        feature_idx: Optional[int] = None,
        threshold: Optional[float] = None,
        left: Optional['TreeNode'] = None,
        right: Optional['TreeNode'] = None,
        value: Optional[int] = None,
        class_probs: Optional[Dict[int, float]] = None,
        impurity: float = 0.0,
        samples: int = 0
    ):
        self.feature_idx = feature_idx
        self.threshold = threshold
        self.left = left
        self.right = right
        self.value = value
        self.class_probs = class_probs or {}
        self.impurity = impurity
        self.samples = samples

    @property
    def is_leaf(self) -> bool:
        return self.value is not None


class DecisionTree:
    """Single Decision Tree for Classification using Gini Impurity."""
    def __init__(
        self,
        max_depth: int = 10,
        min_samples_split: int = 2,
        min_samples_leaf: int = 1,
        max_features: Optional[int] = None,
        random_state: int = 42
    ):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.rng = random.Random(random_state)
        self.root: Optional[TreeNode] = None
        self.feature_importances: List[float] = []

    def _gini(self, y: List[int]) -> float:
        if not y:
            return 0.0
        n = len(y)
        counts: Dict[int, int] = {}
        for label in y:
            counts[label] = counts.get(label, 0) + 1
        return 1.0 - sum((c / n) ** 2 for c in counts.values())

    def _best_split(
        self,
        X: List[List[float]],
        y: List[int],
        feature_indices: List[int]
    ) -> Tuple[Optional[int], Optional[float], float]:
        best_feat = None
        best_thresh = None
        best_gain = 0.0
        current_gini = self._gini(y)
        n = len(y)

        for feat_idx in feature_indices:
            values = sorted(list(set(row[feat_idx] for row in X)))
            if len(values) <= 1:
                continue

            # Candidate split thresholds (midpoints)
            thresholds = [(values[i] + values[i + 1]) / 2.0 for i in range(len(values) - 1)]
            for thresh in thresholds:
                left_y, right_y = [], []
                for row, label in zip(X, y):
                    if row[feat_idx] <= thresh:
                        left_y.append(label)
                    else:
                        right_y.append(label)

                if len(left_y) < self.min_samples_leaf or len(right_y) < self.min_samples_leaf:
                    continue

                gain = current_gini - (
                    (len(left_y) / n) * self._gini(left_y) + (len(right_y) / n) * self._gini(right_y)
                )

                if gain > best_gain:
                    best_gain = gain
                    best_feat = feat_idx
                    best_thresh = thresh

        return best_feat, best_thresh, best_gain

    def _build_tree(self, X: List[List[float]], y: List[int], depth: int = 0) -> TreeNode:
        n_samples = len(y)
        counts: Dict[int, int] = {}
        for lbl in y:
            counts[lbl] = counts.get(lbl, 0) + 1

        majority_class = max(counts.items(), key=lambda item: item[1])[0]
        class_probs = {c: count / n_samples for c, count in counts.items()}
        current_impurity = self._gini(y)

        # Base cases: pure node, max depth reached, or too few samples
        if (
            depth >= self.max_depth
            or len(counts) == 1
            or n_samples < self.min_samples_split
        ):
            return TreeNode(
                value=majority_class,
                class_probs=class_probs,
                impurity=current_impurity,
                samples=n_samples
            )

        n_features = len(X[0])
        max_f = self.max_features or max(1, int(math.sqrt(n_features)))
        all_features = list(range(n_features))
        candidate_features = self.rng.sample(all_features, min(max_f, n_features))

        best_feat, best_thresh, best_gain = self._best_split(X, y, candidate_features)

        if best_feat is None or best_gain <= 0.0:
            return TreeNode(
                value=majority_class,
                class_probs=class_probs,
                impurity=current_impurity,
                samples=n_samples
            )

        # Record feature importance gain
        self.feature_importances[best_feat] += best_gain * (n_samples / self.total_train_samples)

        left_X, left_y = [], []
        right_X, right_y = [], []
        for row, label in zip(X, y):
            if row[best_feat] <= best_thresh:
                left_X.append(row)
                left_y.append(label)
            else:
                right_X.append(row)
                right_y.append(label)

        left_child = self._build_tree(left_X, left_y, depth + 1)
        right_child = self._build_tree(right_X, right_y, depth + 1)

        return TreeNode(
            feature_idx=best_feat,
            threshold=best_thresh,
            left=left_child,
            right=right_child,
            impurity=current_impurity,
            samples=n_samples
        )

    def fit(self, X: List[List[float]], y: List[int]):
        n_features = len(X[0])
        self.total_train_samples = len(y)
        self.feature_importances = [0.0] * n_features
        self.root = self._build_tree(X, y, depth=0)

    def predict_row_probs(self, row: List[float], node: Optional[TreeNode] = None) -> Dict[int, float]:
        if node is None:
            node = self.root
        if node.is_leaf:
            return node.class_probs
        if row[node.feature_idx] <= node.threshold:
            return self.predict_row_probs(row, node.left)
        else:
            return self.predict_row_probs(row, node.right)


class RandomForest:
    """
    Random Forest Classifier for Supervised Cybersecurity Attack Classification.
    Ensemble of decision trees trained with bootstrap bagging and feature subspace sampling.
    """
    def __init__(
        self,
        n_estimators: int = 30,
        max_depth: int = 8,
        min_samples_split: int = 2,
        min_samples_leaf: int = 1,
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.random_state = random_state
        self.trees: List[DecisionTree] = []
        self.classes: List[int] = []
        self.feature_importances_: List[float] = []

    def fit(self, X: List[List[float]], y: List[int]):
        n_samples = len(X)
        n_features = len(X[0])
        self.classes = sorted(list(set(y)))
        self.trees = []
        raw_importances = [0.0] * n_features
        rng = random.Random(self.random_state)

        for i in range(self.n_estimators):
            # Bootstrap sample with replacement
            boot_indices = [rng.randint(0, n_samples - 1) for _ in range(n_samples)]
            boot_X = [X[idx] for idx in boot_indices]
            boot_y = [y[idx] for idx in boot_indices]

            tree = DecisionTree(
                max_depth=self.max_depth,
                min_samples_split=self.min_samples_split,
                min_samples_leaf=self.min_samples_leaf,
                random_state=self.random_state + i * 13
            )
            tree.fit(boot_X, boot_y)
            self.trees.append(tree)

            for feat_idx in range(n_features):
                raw_importances[feat_idx] += tree.feature_importances[feat_idx]

        # Normalize feature importances
        total_imp = sum(raw_importances)
        if total_imp > 0:
            self.feature_importances_ = [imp / total_imp for imp in raw_importances]
        else:
            self.feature_importances_ = [1.0 / n_features] * n_features

    def predict_proba(self, X: List[List[float]]) -> List[Dict[int, float]]:
        results: List[Dict[int, float]] = []
        for row in X:
            aggregated_probs: Dict[int, float] = {c: 0.0 for c in self.classes}
            for tree in self.trees:
                t_probs = tree.predict_row_probs(row)
                for c, p in t_probs.items():
                    aggregated_probs[c] = aggregated_probs.get(c, 0.0) + p / len(self.trees)
            results.append(aggregated_probs)
        return results

    def predict(self, X: List[List[float]]) -> List[int]:
        probs = self.predict_proba(X)
        predictions = []
        for p_dict in probs:
            pred_class = max(p_dict.items(), key=lambda item: item[1])[0]
            predictions.append(pred_class)
        return predictions

    def evaluate(
        self,
        X_test: List[List[float]],
        y_test: List[int],
        id_to_label: Dict[int, str]
    ) -> Dict[str, Any]:
        """
        Calculates exact classification metrics on held-out test data.
        """
        if not X_test or not y_test:
            raise ValueError("Test data cannot be empty for evaluation.")

        y_pred = self.predict(X_test)
        total_samples = len(y_test)

        # Accuracy
        correct = sum(1 for yt, yp in zip(y_test, y_pred) if yt == yp)
        accuracy = correct / total_samples

        all_class_ids = sorted(list(set(y_test + y_pred)))
        class_names = [id_to_label.get(c, str(c)) for c in all_class_ids]

        # Confusion Matrix: rows = true labels, cols = predicted labels
        label_to_matrix_idx = {c: i for i, c in enumerate(all_class_ids)}
        matrix_dim = len(all_class_ids)
        matrix = [[0] * matrix_dim for _ in range(matrix_dim)]

        for yt, yp in zip(y_test, y_pred):
            r = label_to_matrix_idx[yt]
            c = label_to_matrix_idx[yp]
            matrix[r][c] += 1

        # Per-class metrics
        class_reports = []
        precisions, recalls, f1s = [], [], []
        supports = []

        for c_id in all_class_ids:
            idx = label_to_matrix_idx[c_id]
            tp = matrix[idx][idx]
            fp = sum(matrix[r][idx] for r in range(matrix_dim) if r != idx)
            fn = sum(matrix[idx][c] for c in range(matrix_dim) if c != idx)
            support = sum(matrix[idx])

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

            precisions.append(prec)
            recalls.append(rec)
            f1s.append(f1)
            supports.append(support)

            class_reports.append({
                "className": id_to_label.get(c_id, str(c_id)),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1Score": round(f1, 4),
                "support": support
            })

        # Macro and weighted averages
        macro_prec = sum(precisions) / len(precisions) if precisions else 0.0
        macro_rec = sum(recalls) / len(recalls) if recalls else 0.0
        macro_f1 = sum(f1s) / len(f1s) if f1s else 0.0

        total_supp = sum(supports)
        weighted_prec = sum(p * s for p, s in zip(precisions, supports)) / total_supp if total_supp > 0 else 0.0
        weighted_rec = sum(r * s for r, s in zip(recalls, supports)) / total_supp if total_supp > 0 else 0.0
        weighted_f1 = sum(f * s for f, s in zip(f1s, supports)) / total_supp if total_supp > 0 else 0.0

        return {
            "accuracy": round(accuracy, 4),
            "macroPrecision": round(macro_prec, 4),
            "macroRecall": round(macro_rec, 4),
            "macroF1": round(macro_f1, 4),
            "weightedPrecision": round(weighted_prec, 4),
            "weightedRecall": round(weighted_rec, 4),
            "weightedF1": round(weighted_f1, 4),
            "confusionMatrix": {
                "labels": class_names,
                "matrix": matrix,
                "totalSamples": total_samples
            },
            "classificationReport": class_reports
        }


class IsolationTreeNode:
    """Node in an Isolation Tree."""
    def __init__(
        self,
        feature_idx: Optional[int] = None,
        split_value: Optional[float] = None,
        left: Optional['IsolationTreeNode'] = None,
        right: Optional['IsolationTreeNode'] = None,
        size: int = 0
    ):
        self.feature_idx = feature_idx
        self.split_value = split_value
        self.left = left
        self.right = right
        self.size = size

    @property
    def is_leaf(self) -> bool:
        return self.split_value is None


class IsolationTree:
    """Single Isolation Tree."""
    def __init__(self, max_depth: int = 8, random_state: int = 42):
        self.max_depth = max_depth
        self.rng = random.Random(random_state)
        self.root: Optional[IsolationTreeNode] = None

    def _build_tree(self, X: List[List[float]], current_depth: int = 0) -> IsolationTreeNode:
        n_samples = len(X)
        if current_depth >= self.max_depth or n_samples <= 1:
            return IsolationTreeNode(size=n_samples)

        n_features = len(X[0])
        # Pick random feature
        feat_idx = self.rng.randint(0, n_features - 1)
        feat_vals = [row[feat_idx] for row in X]
        min_v = min(feat_vals)
        max_v = max(feat_vals)

        if min_v == max_v:
            return IsolationTreeNode(size=n_samples)

        split_v = self.rng.uniform(min_v, max_v)
        left_X = [row for row in X if row[feat_idx] < split_v]
        right_X = [row for row in X if row[feat_idx] >= split_v]

        left_child = self._build_tree(left_X, current_depth + 1)
        right_child = self._build_tree(right_X, current_depth + 1)

        return IsolationTreeNode(
            feature_idx=feat_idx,
            split_value=split_v,
            left=left_child,
            right=right_child,
            size=n_samples
        )

    def fit(self, X: List[List[float]]):
        self.root = self._build_tree(X, 0)

    def path_length(self, x: List[float], node: Optional[IsolationTreeNode] = None, current_depth: int = 0) -> float:
        if node is None:
            node = self.root
        if node.is_leaf:
            return current_depth + _c(node.size)
        if x[node.feature_idx] < node.split_value:
            return self.path_length(x, node.left, current_depth + 1)
        else:
            return self.path_length(x, node.right, current_depth + 1)


def _c(n: int) -> float:
    """Average path length of unsuccessful search in BST."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    # Euler-Mascheroni constant = 0.5772156649
    return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class IsolationForest:
    """
    Isolation Forest for Unsupervised Anomaly Detection.
    Isolates anomalous instances by recursive random partitioning.
    Anomalies require fewer partitions and exhibit shorter path lengths.
    """
    def __init__(
        self,
        n_estimators: int = 50,
        max_samples: int = 256,
        contamination: float = 0.05,
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.trees: List[IsolationTree] = []
        self.threshold: float = 0.5
        self.subsample_size: int = 256

    def fit(self, X: List[List[float]]):
        n_samples = len(X)
        self.subsample_size = min(self.max_samples, n_samples)
        max_depth = math.ceil(math.log2(max(2, self.subsample_size)))
        rng = random.Random(self.random_state)
        self.trees = []

        for i in range(self.n_estimators):
            sub_indices = rng.sample(range(n_samples), self.subsample_size)
            sub_X = [X[idx] for idx in sub_indices]
            tree = IsolationTree(max_depth=max_depth, random_state=self.random_state + i * 17)
            tree.fit(sub_X)
            self.trees.append(tree)

        # Compute anomaly scores on training set to set threshold via contamination percentile
        scores = self.score_samples(X)
        sorted_scores = sorted(scores, reverse=True)
        thresh_idx = int(len(sorted_scores) * self.contamination)
        self.threshold = sorted_scores[min(thresh_idx, len(sorted_scores) - 1)]

    def score_samples(self, X: List[List[float]]) -> List[float]:
        """
        Anomaly score s(x, n) = 2^(-E(h(x)) / c(n)).
        Values close to 1 indicate anomalies; values < 0.5 indicate normal instances.
        """
        c_n = _c(self.subsample_size)
        scores = []
        for row in X:
            avg_h = sum(t.path_length(row) for t in self.trees) / len(self.trees)
            score = 2.0 ** (-avg_h / c_n) if c_n > 0 else 0.5
            scores.append(round(score, 4))
        return scores

    def predict(self, X: List[List[float]]) -> List[int]:
        """Returns 1 for anomaly, 0 for benign."""
        scores = self.score_samples(X)
        return [1 if s >= self.threshold else 0 for s in scores]

    def explain_anomaly(
        self,
        sample: List[float],
        feature_names: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Explains anomaly by identifying features that caused the shortest path lengths.
        """
        feature_depths: Dict[int, List[int]] = {}
        for tree in self.trees:
            curr = tree.root
            d = 0
            while curr and not curr.is_leaf:
                feature_depths.setdefault(curr.feature_idx, []).append(d)
                if sample[curr.feature_idx] < curr.split_value:
                    curr = curr.left
                else:
                    curr = curr.right
                d += 1

        avg_depths = [
            (feat_idx, sum(depths) / len(depths))
            for feat_idx, depths in feature_depths.items()
        ]
        # Sort ascending: lowest average depth = most anomalous feature contributing to isolation
        avg_depths.sort(key=lambda item: item[1])

        explanations = []
        for rank, (feat_idx, depth) in enumerate(avg_depths[:5], start=1):
            feat_name = feature_names[feat_idx] if feat_idx < len(feature_names) else f"feature_{feat_idx}"
            explanations.append({
                "feature": feat_name,
                "averageIsolationDepth": round(depth, 2),
                "rank": rank,
                "importance": round(1.0 / (depth + 1.0), 4)
            })
        return explanations
