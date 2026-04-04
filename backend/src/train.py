"""
train.py — CyberSafe Malicious URL Detector · Training Pipeline
Trains a GradientBoosting classifier with full evaluation, feature importance,
cross-validation, and artefact saving.
"""

import os
import json
import time
import warnings
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_auc_score,
    accuracy_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from features import extract_features, feature_names

warnings.filterwarnings("ignore")


# ---------------------------------------------------------------------------
# Config — edit these paths to match your project layout
# ---------------------------------------------------------------------------

DATA_PATH   = Path("../../data/malicious_phish.csv")
MODEL_DIR   = Path("../model")
MODEL_PATH  = MODEL_DIR / "cybersafe_model.pkl"
META_PATH   = MODEL_DIR / "cybersafe_meta.json"
PLOT_DIR    = MODEL_DIR / "plots"

RANDOM_STATE  = 42
TEST_SIZE     = 0.2
CV_FOLDS      = 5   # number of times training repeats
URL_COL       = "url" # column name in your dataset
LABEL_COL     = "type" #column name in your dataset


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_data(path: Path) -> pd.DataFrame:
    print(f"[1/6] Loading dataset from {path} …")
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    df = pd.read_csv(path)  # loads CSV into memory
    assert URL_COL in df.columns and LABEL_COL in df.columns, (
        f"CSV must have '{URL_COL}' and '{LABEL_COL}' columns."
    )
    # Drop nulls / empty URLs
    before = len(df)
    df = df.dropna(subset=[URL_COL, LABEL_COL]) #removes missing values
    df = df[df[URL_COL].str.strip().astype(bool)] #removes empty URLs like " "
    print(f"    {len(df):,} rows loaded ({before - len(df)} dropped).")
    print(f"    Class distribution:\n{df[LABEL_COL].value_counts().to_string()}\n") # shows how many: phishing,bening,etc
    return df


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    print(f"[2/6] Extracting features for {len(df):,} URLs …")
    t0 = time.time()
    rows = []
    errors = 0
    for url in df[URL_COL]: #loop over every URL (650 rows)
        try:
            rows.append(extract_features(str(url))) # URL -> number
        except Exception:
            rows.append({k: 0 for k in feature_names()}) # if extraction fails, don't crash just fill zeros
            errors += 1
    X = pd.DataFrame(rows) #convert list -> table
    print(f"    Done in {time.time() - t0:.1f}s — {X.shape[1]} features, {errors} extraction errors.\n")
    return X


def build_model() -> Pipeline:
    """
    Wraps a GradientBoostingClassifier in a pipeline.
    Swap out the classifier here if you want to try XGBoost / LightGBM later.
    """
    clf = GradientBoostingClassifier(
        n_estimators=300,
        learning_rate=0.08,
        max_depth=5,
        min_samples_split=10,
        subsample=0.85,
        random_state=RANDOM_STATE,
        verbose=0,
    )
    return Pipeline([  # scale data, apply model
        ("scaler", StandardScaler()),
        ("clf", clf),
    ])


def evaluate(model, X_test, y_test, le: LabelEncoder, plot_dir: Path):
    print("[5/6] Evaluating on held-out test set …")
    y_pred  = model.predict(X_test) # model prediction
    y_proba = model.predict_proba(X_test) 

    acc = accuracy_score(y_test, y_pred)
    print(f"\n    Accuracy : {acc:.4f}")

    # AUC — works for binary and multiclass
    try:
        if len(le.classes_) == 2:
            auc = roc_auc_score(y_test, y_proba[:, 1]) # how well model separates classes
        else:
            auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="weighted")
        print(f"    ROC-AUC  : {auc:.4f}")
    except Exception as e:
        auc = None
        print(f"    ROC-AUC  : N/A ({e})")

    print("\n    Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_)) # shows: precision, recall, f1-score

    # Confusion matrix plot
    plot_dir.mkdir(parents=True, exist_ok=True)
    cm = confusion_matrix(y_test, y_pred) # shows mistakes, Actual vs Predicted
    fig, ax = plt.subplots(figsize=(7, 6))
    ConfusionMatrixDisplay(cm, display_labels=le.classes_).plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title("Confusion Matrix — CyberSafe Model", fontsize=13, pad=12)
    plt.tight_layout()
    cm_path = plot_dir / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=150) #saves graph as image
    plt.close()
    print(f"    Confusion matrix saved → {cm_path}")

    return acc, auc


# Tells which features matter most 
# Eg. url_length -> important, entropy -> important
def plot_feature_importance(model, feat_names: list[str], plot_dir: Path, top_n: int = 20):
    clf = model.named_steps["clf"]
    if not hasattr(clf, "feature_importances_"):
        return
    importances = clf.feature_importances_
    idx = np.argsort(importances)[-top_n:][::-1]

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(
        [feat_names[i] for i in idx][::-1],
        importances[idx][::-1],
        color="#3A86FF",
        edgecolor="white",
    )
    ax.set_xlabel("Feature Importance (mean decrease in impurity)")
    ax.set_title(f"Top {top_n} Features — CyberSafe Model", fontsize=13, pad=12)
    plt.tight_layout()
    fi_path = plot_dir / "feature_importance.png"
    plt.savefig(fi_path, dpi=150)
    plt.close()
    print(f"    Feature importance plot saved → {fi_path}")


#LabelEncoder converts test labels -> numbers
# benign      → 0
# defacement  → 1
# malware     → 2
# phishing    → 3
# Model trains on these numbers
def save_artefacts(model, le: LabelEncoder, acc: float, auc, feat_names: list[str]):
    print("[6/6] Saving model artefacts …")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump({"model": model, "label_encoder": le}, MODEL_PATH) # saves: model, label encoder
    print(f"    Model saved → {MODEL_PATH}")

    meta = {  #saves feature names, accuracy, time
        "feature_names": feat_names,
        "classes":       list(le.classes_),
        "test_accuracy": round(acc, 4),
        "test_roc_auc":  round(auc, 4) if auc is not None else None,
        "trained_at":    time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    META_PATH.write_text(json.dumps(meta, indent=2))
    print(f"    Metadata saved → {META_PATH}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("\n" + "=" * 60)
    print("  CyberSafe · Malicious URL Detector · Training Pipeline")
    print("=" * 60 + "\n")

    # 1. Load dataset
    df = load_data(DATA_PATH)

    # 2. Convert URLs -> Features
    X = build_features(df)
    feat_names = list(X.columns)

    # 3. Encode labels
    #  eg. phishing → 2
    #      benign → 0
    le = LabelEncoder()
    y  = le.fit_transform(df[LABEL_COL])
    print(f"[3/6] Label classes: {list(le.classes_)}\n")

    # 4. Split data: train= 80% test= 20% + cross-validate= train model multiple times (5x)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )
    print(f"[4/6] Train: {len(X_train):,} | Test: {len(X_test):,}")

    model = build_model()

    print(f"    Running {CV_FOLDS}-fold stratified cross-validation …")
    cv_scores = cross_val_score(
        model, X_train, y_train,
        cv=StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE),
        scoring="accuracy",
        n_jobs=-1,
    )
    print(f"    CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}\n")

    print("    Fitting final model on full training set …")
    t0 = time.time()
    model.fit(X_train, y_train) #final training
    print(f"    Trained in {time.time() - t0:.1f}s\n")

    # 5. Evaluate
    PLOT_DIR.mkdir(parents=True, exist_ok=True)
    acc, auc = evaluate(model, X_test, y_test, le, PLOT_DIR) #test model
    plot_feature_importance(model, feat_names, PLOT_DIR)

    # 6. Save model + metadata
    save_artefacts(model, le, acc, auc, feat_names)

    print("=" * 60)
    print("  Training complete. ✓")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
