"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Data Leakage-Free Preprocessing Pipeline
"""

import numpy as np
import pandas as pd

def clean_and_split_data(df, feature_cols, target_col, test_size=0.2, random_state=42):
    """
    Split dataset BEFORE applying any learned data transformations.
    Strictly prevents target or distributional leakage into test evaluation.
    """
    from sklearn.model_selection import train_test_split
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler, LabelEncoder

    # Extract raw features and target
    X = df[feature_cols].copy()
    y = df[target_col].copy()

    # Clean infinite values in X by replacing with NaN first
    X = X.replace([np.inf, -np.inf], np.nan)

    # Convert object columns that are numeric
    for col in X.columns:
        if X[col].dtype == 'object':
            try:
                X[col] = pd.to_numeric(X[col])
            except Exception:
                pass

    # Check stratification feasibility
    class_counts = y.value_counts()
    can_stratify = (class_counts >= 2).all()
    stratify_target = y if can_stratify else None

    # Strict train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify_target
    )

    # Fit Imputer and Scaler ONLY on X_train
    numeric_cols = X_train.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = X_train.select_dtypes(exclude=[np.number]).columns.tolist()

    imputer = SimpleImputer(strategy='median')
    scaler = StandardScaler()

    if numeric_cols:
        X_train_num = imputer.fit_transform(X_train[numeric_cols])
        X_test_num = imputer.transform(X_test[numeric_cols])

        X_train_scaled = scaler.fit_transform(X_train_num)
        X_test_scaled = scaler.transform(X_test_num)
    else:
        X_train_scaled = np.empty((len(X_train), 0))
        X_test_scaled = np.empty((len(X_test), 0))

    # Fit LabelEncoder on y_train
    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)
    
    # Handle possible unseen classes in test set safely
    y_test_encoded = []
    for val in y_test:
        if val in label_encoder.classes_:
            y_test_encoded.append(label_encoder.transform([val])[0])
        else:
            # Assign first class as fallback
            y_test_encoded.append(0)
    y_test_encoded = np.array(y_test_encoded)

    preprocessor = {
        "imputer": imputer,
        "scaler": scaler,
        "numeric_cols": numeric_cols,
        "categorical_cols": categorical_cols,
        "label_encoder": label_encoder,
        "feature_names": feature_cols,
        "stratified": can_stratify
    }

    return X_train_scaled, X_test_scaled, y_train_encoded, y_test_encoded, preprocessor
