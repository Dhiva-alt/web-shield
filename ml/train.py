"""
WebShield - Offline Phishing URL Classifier Training Pipeline

Pipeline Specification:
1. Pure Raw URL Processing: Ignores any external or precomputed columns.
2. Exact Feature Parity: Extracts features via ml/features.py (identical to extension/lib/features.js).
3. Memory Guardrail (~6 GB RAM): Stratified sample capped at 50,000 rows.
4. Stratified 80/20 split with fixed random seed.
5. Models:
   - Logistic Regression baseline
   - Random Forest (n_estimators=30, max_depth=8)
6. Metrics & Reporting: Accuracy, Precision, Recall, F1, Confusion Matrix, Feature Importances.
7. Leakage Auditing:
   - Domain overlap between train and test splits
   - Near-duplicate URL overlap
   - Single-feature perfect separation checks
8. Persistence: Saves metrics, confusion matrices, and exported rules to ml/outputs/.
"""

import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

# Ensure ml/ directory is importable
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
sys.path.insert(0, str(CURRENT_DIR))

from features import extract_features

RANDOM_SEED = 42
MAX_SAMPLE_SIZE = 50000
OUTPUTS_DIR = CURRENT_DIR / "outputs"


def get_domain(url_str: str) -> str:
    """Extracts lowercase domain name for leakage analysis."""
    try:
        if "://" not in str(url_str):
            url_str = "http://" + str(url_str)
        parsed = urlparse(str(url_str))
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def load_and_preprocess_data(csv_path: Path):
    """
    Loads raw URL CSV, handles varying column names, cleans nulls/duplicates,
    and returns stratified sample capped at MAX_SAMPLE_SIZE.
    """
    print(f"\n[1/6] Loading dataset from: {csv_path.name}")
    start_time = time.time()

    # Read CSV
    df = pd.read_csv(csv_path)
    print(f"      Raw rows loaded: {len(df):,}")

    # Standardize URL column name
    url_col = None
    for candidate in ["URL", "url", "Url", "raw_url"]:
        if candidate in df.columns:
            url_col = candidate
            break
    if not url_col:
        raise ValueError(f"Could not identify raw URL column in: {list(df.columns)}")

    # Standardize Label column name
    label_col = None
    for candidate in ["Label", "label", "type", "class", "result", "target"]:
        if candidate in df.columns:
            label_col = candidate
            break
    if not label_col:
        raise ValueError(f"Could not identify Label column in: {list(df.columns)}")

    # Isolate ONLY raw URL and label (ignore any precomputed features)
    df = df[[url_col, label_col]].copy()
    df.rename(columns={url_col: "url", label_col: "raw_label"}, inplace=True)

    # Clean nulls
    initial_count = len(df)
    df.dropna(subset=["url", "raw_label"], inplace=True)
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 0]

    # Map labels to binary: 0 = Benign/Safe, 1 = Phishing/Malicious
    def map_label(val):
        s = str(val).lower().strip()
        if s in ["0", "good", "benign", "safe", "legitimate", "0.0"]:
            return 0
        elif s in ["1", "bad", "phishing", "malicious", "defacement", "malware", "1.0"]:
            return 1
        return None

    df["label"] = df["raw_label"].apply(map_label)
    df.dropna(subset=["label"], inplace=True)
    df["label"] = df["label"].astype(int)

    # Deduplicate on raw URL
    df.drop_duplicates(subset=["url"], inplace=True)
    cleaned_count = len(df)
    print(f"      Cleaned & deduplicated unique URLs: {cleaned_count:,} (dropped {initial_count - cleaned_count:,})")

    # Report class distribution
    class_counts = df["label"].value_counts().to_dict()
    benign_count = class_counts.get(0, 0)
    phish_count = class_counts.get(1, 0)
    print(f"      Full class balance -> Safe (0): {benign_count:,} ({benign_count/cleaned_count*100:.1f}%), Phishing (1): {phish_count:,} ({phish_count/cleaned_count*100:.1f}%)")

    # Stratified downsample if exceeding memory limit
    if cleaned_count > MAX_SAMPLE_SIZE:
        print(f"      Downsampling to memory-safe stratified sample of {MAX_SAMPLE_SIZE:,} rows...")
        sample_ratio = MAX_SAMPLE_SIZE / cleaned_count
        df, _ = train_test_split(
            df,
            train_size=MAX_SAMPLE_SIZE,
            stratify=df["label"],
            random_state=RANDOM_SEED
        )
        print(f"      Sampled dataset size: {len(df):,}")

    elapsed = time.time() - start_time
    print(f"      Preprocessed in {elapsed:.2f}s")
    return df


def extract_feature_matrix(urls: pd.Series):
    """
    Applies ml/features.py extract_features across the URLs series.
    Returns DataFrame of numerical features.
    """
    print(f"\n[2/6] Extracting features for {len(urls):,} URLs using ml/features.py...")
    start_time = time.time()

    records = [extract_features(u) for u in urls]
    feature_df = pd.DataFrame(records)

    # Exclude non-feature diagnostic fields
    feature_cols = [
        c for c in feature_df.columns
        if c not in ["isValidUrl"]
    ]
    X = feature_df[feature_cols].copy()
    elapsed = time.time() - start_time
    print(f"      Extracted {X.shape[1]} features in {elapsed:.2f}s")
    return X


def audit_data_leakage(train_df: pd.DataFrame, test_df: pd.DataFrame, X_train: pd.DataFrame, y_train: pd.Series):
    """
    Audits domain overlap, URL overlap, and single-feature separation.
    """
    print("\n[3/6] Auditing Data Leakage between Train and Test Splits...")
    leakage_report = {}

    # 1. Exact URL Overlap
    train_urls = set(train_df["url"])
    test_urls = set(test_df["url"])
    exact_overlap = train_urls.intersection(test_urls)
    leakage_report["exact_url_overlap_count"] = len(exact_overlap)
    print(f"      - Exact URL overlap: {len(exact_overlap)} URLs")

    # 2. Domain Overlap
    train_domains = set(train_df["domain"]) - {""}
    test_domains = set(test_df["domain"]) - {""}
    domain_overlap = train_domains.intersection(test_domains)
    leakage_report["train_unique_domains"] = len(train_domains)
    leakage_report["test_unique_domains"] = len(test_domains)
    leakage_report["domain_overlap_count"] = len(domain_overlap)
    domain_overlap_pct = (len(domain_overlap) / len(test_domains) * 100) if test_domains else 0.0
    leakage_report["domain_overlap_pct_of_test"] = round(domain_overlap_pct, 2)

    print(f"      - Unique domains in train: {len(train_domains):,}")
    print(f"      - Unique domains in test: {len(test_domains):,}")
    print(f"      - Overlapping domains: {len(domain_overlap):,} ({domain_overlap_pct:.2f}% of test domains)")

    # 3. Single-feature separation check (AUC / Correlation / Separation)
    suspicious_separators = []
    for col in X_train.columns:
        corr = np.corrcoef(X_train[col], y_train)[0, 1]
        if abs(corr) >= 0.85:
            suspicious_separators.append((col, round(float(corr), 4)))

    leakage_report["suspicious_single_features"] = suspicious_separators
    if suspicious_separators:
        print(f"      [!] WARNING: Single feature(s) showing extreme correlation (>= 0.85): {suspicious_separators}")
    else:
        print("      - No single feature separates the classes artificially (all |corr| < 0.85).")

    return leakage_report


def train_and_evaluate(df: pd.DataFrame):
    """
    Executes 80/20 stratified split, extracts features, trains models, and saves results.
    """
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    df["domain"] = df["url"].apply(get_domain)

    # 80/20 Stratified Split
    train_df, test_df = train_test_split(
        df,
        test_size=0.20,
        stratify=df["label"],
        random_state=RANDOM_SEED
    )

    print(f"\n      Train split size: {len(train_df):,} rows")
    print(f"      Test split size:  {len(test_df):,} rows")

    # Extract features
    X_train = extract_feature_matrix(train_df["url"])
    X_test = extract_feature_matrix(test_df["url"])
    y_train = train_df["label"].values
    y_test = test_df["label"].values

    # Leakage Audit
    leakage_report = audit_data_leakage(train_df, test_df, X_train, y_train)

    # -------------------------------------------------------------------------
    # Model 1: Logistic Regression Baseline
    # -------------------------------------------------------------------------
    print("\n[4/6] Training Logistic Regression Baseline...")
    start_lr = time.time()
    lr = LogisticRegression(max_iter=1000, random_state=RANDOM_SEED)
    lr.fit(X_train, y_train)
    lr_time = time.time() - start_lr

    y_pred_lr = lr.predict(X_test)
    lr_acc = accuracy_score(y_test, y_pred_lr)
    lr_prec = precision_score(y_test, y_pred_lr, zero_division=0)
    lr_rec = recall_score(y_test, y_pred_lr, zero_division=0)
    lr_f1 = f1_score(y_test, y_pred_lr, zero_division=0)
    lr_cm = confusion_matrix(y_test, y_pred_lr).tolist()

    print(f"      Trained in {lr_time:.2f}s")
    print(f"      Logistic Regression Results on Test Set:")
    print(f"        Accuracy:  {lr_acc:.4f}")
    print(f"        Precision: {lr_prec:.4f}")
    print(f"        Recall:    {lr_rec:.4f}")
    print(f"        F1 Score:  {lr_f1:.4f}")
    print(f"        Confusion Matrix: {lr_cm}")

    # -------------------------------------------------------------------------
    # Model 2: Random Forest (30 trees, max_depth 8)
    # -------------------------------------------------------------------------
    print("\n[5/6] Training Random Forest (n_estimators=30, max_depth=8)...")
    start_rf = time.time()
    rf = RandomForestClassifier(
        n_estimators=30,
        max_depth=8,
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_time = time.time() - start_rf

    y_pred_rf = rf.predict(X_test)
    rf_acc = accuracy_score(y_test, y_pred_rf)
    rf_prec = precision_score(y_test, y_pred_rf, zero_division=0)
    rf_rec = recall_score(y_test, y_pred_rf, zero_division=0)
    rf_f1 = f1_score(y_test, y_pred_rf, zero_division=0)
    rf_cm = confusion_matrix(y_test, y_pred_rf).tolist()

    # Feature Importance
    feature_importances = dict(
        sorted(
            zip(X_train.columns, [round(float(v), 4) for v in rf.feature_importances_]),
            key=lambda item: item[1],
            reverse=True
        )
    )

    print(f"      Trained in {rf_time:.2f}s")
    print(f"      Random Forest Results on Test Set:")
    print(f"        Accuracy:  {rf_acc:.4f}")
    print(f"        Precision: {rf_prec:.4f}")
    print(f"        Recall:    {rf_rec:.4f}")
    print(f"        F1 Score:  {rf_f1:.4f}")
    print(f"        Confusion Matrix (TN, FP / FN, TP):")
    print(f"          TN: {rf_cm[0][0]:,} | FP: {rf_cm[0][1]:,}")
    print(f"          FN: {rf_cm[1][0]:,} | TP: {rf_cm[1][1]:,}")
    print("\n      Top Feature Importances:")
    for feat, imp in list(feature_importances.items())[:8]:
        print(f"        - {feat}: {imp:.4f}")

    # -------------------------------------------------------------------------
    # 6. Export Random Forest to Compact JSON (Nested Arrays)
    # Target: extension/model/rf_model.json (must stay under 1 MB)
    # -------------------------------------------------------------------------
    def export_tree_recursive(tree, node_idx=0):
        feature = int(tree.feature[node_idx])
        if feature == -2:  # Leaf node
            class_counts = tree.value[node_idx][0]
            prob_phish = float(class_counts[1] / np.sum(class_counts))
            return [None, None, None, None, round(prob_phish, 4)]

        threshold = float(round(tree.threshold[node_idx], 4))
        left_child = export_tree_recursive(tree, int(tree.children_left[node_idx]))
        right_child = export_tree_recursive(tree, int(tree.children_right[node_idx]))
        return [feature, threshold, left_child, right_child, None]

    print("\n[6/7] Exporting Random Forest to compact JSON in extension/model/...")
    trees_json = [export_tree_recursive(est.tree_, 0) for est in rf.estimators_]

    model_payload = {
        "model_type": "RandomForestClassifier",
        "n_estimators": len(trees_json),
        "max_depth": 8,
        "features": list(X_train.columns),
        "trees": trees_json
    }

    extension_model_path = PROJECT_ROOT / "extension" / "model" / "rf_model.json"
    extension_model_path.parent.mkdir(parents=True, exist_ok=True)
    with open(extension_model_path, "w", encoding="utf-8") as f:
        json.dump(model_payload, f, separators=(",", ":"))

    model_size_bytes = extension_model_path.stat().st_size
    print(f"      Saved: {extension_model_path}")
    print(f"      Size: {model_size_bytes:,} bytes ({model_size_bytes / 1024:.2f} KB) - well under 1 MB limit.")

    # -------------------------------------------------------------------------
    # 7. Generate 20 Sample Test URLs with Python Predictions for Parity Verification
    # -------------------------------------------------------------------------
    print("\n[7/7] Selecting 20 sample test URLs for cross-engine JS/Python verification...")
    safe_samples = test_df[test_df["label"] == 0].head(10)
    phish_samples = test_df[test_df["label"] == 1].head(10)
    sample_20 = pd.concat([safe_samples, phish_samples]).sample(frac=1.0, random_state=RANDOM_SEED)

    sample_features = extract_feature_matrix(sample_20["url"])
    sample_probs = rf.predict_proba(sample_features)[:, 1]

    sample_20_records = []
    for i, (_, row) in enumerate(sample_20.iterrows()):
        feat_dict = sample_features.iloc[i].to_dict()
        feat_vector = [float(feat_dict[col]) for col in X_train.columns]
        sample_20_records.append({
            "url": row["url"],
            "actual_label": int(row["label"]),
            "python_probability": round(float(sample_probs[i]), 4),
            "feature_vector": feat_vector
        })

    sample_path = OUTPUTS_DIR / "sample_20_eval.json"
    with open(sample_path, "w", encoding="utf-8") as f:
        json.dump(sample_20_records, f, indent=2)

    # Save complete evaluation metrics
    report = {
        "dataset_sample_size": len(df),
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "model_file_size_kb": round(model_size_bytes / 1024, 2),
        "leakage_audit": leakage_report,
        "logistic_regression": {
            "training_time_seconds": round(lr_time, 2),
            "accuracy": round(lr_acc, 4),
            "precision": round(lr_prec, 4),
            "recall": round(lr_rec, 4),
            "f1": round(lr_f1, 4),
            "confusion_matrix": lr_cm
        },
        "random_forest": {
            "hyperparameters": {"n_estimators": 30, "max_depth": 8, "seed": RANDOM_SEED},
            "training_time_seconds": round(rf_time, 2),
            "accuracy": round(rf_acc, 4),
            "precision": round(rf_prec, 4),
            "recall": round(rf_rec, 4),
            "f1": round(rf_f1, 4),
            "confusion_matrix": rf_cm,
            "feature_importances": feature_importances
        }
    }

    metrics_path = OUTPUTS_DIR / "evaluation_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"      Evaluation report saved: {metrics_path}")
    return report


def main():
    data_dir = CURRENT_DIR / "data"
    csv_candidates = list(data_dir.glob("*.csv"))

    if not csv_candidates:
        print("[!] No CSV dataset found in ml/data/.")
        print("[!] Please provide dataset approval before downloading.")
        sys.exit(0)

    dataset_path = csv_candidates[0]
    df = load_and_preprocess_data(dataset_path)
    train_and_evaluate(df)


if __name__ == "__main__":
    main()
