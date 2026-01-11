import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import joblib
import warnings

# ======================
# Ignore overflow warnings
# ======================
warnings.simplefilter(action='ignore', category=RuntimeWarning)

# ======================
# Helper function: prepare features and labels
# ======================
def prepare_features(csv_path):
    df = pd.read_csv(csv_path)
    drop_cols = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Dataset", "Attack"]
    X = df.drop(columns=drop_cols + ["Label"])
    y = df["Label"]

    # Clean data
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    X = X.astype(np.float32)
    X = X.clip(upper=1e8)

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Class imbalance
    neg, pos = np.bincount(y_train)
    scale_pos_weight = neg / pos

    return X_train, X_test, y_train, y_test, scale_pos_weight

# ======================
# List of CSV chunks
# ======================
datasets = [
    "/mnt/8tb_hdd/harish/ds2/splited/dataset0.csv",
    "/mnt/8tb_hdd/harish/ds2/splited/dataset1.csv",
    "/mnt/8tb_hdd/harish/ds2/splited/dataset2.csv",
    # ... add all other datasets
]

# ======================
# Initialize model variable
# ======================
model = None

# ======================
# Loop through CSVs for incremental training
# ======================
for idx, csv_path in enumerate(datasets):

    print(f"\n===== Training on dataset {idx} =====")
    X_train, X_test, y_train, y_test, scale_pos_weight = prepare_features(csv_path)

    if model is None:
        # First dataset → create a new model
        model = xgb.XGBClassifier(
            objective="binary:logistic",
            n_estimators=500,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos_weight,
            reg_alpha=0.1,
            reg_lambda=1,
            use_label_encoder=False,
            eval_metric="auc",
            random_state=42
        )
        # Train first model
        model.fit(X_train, y_train, eval_set=[(X_train, y_train), (X_test, y_test)], verbose=50)
    else:
        # Subsequent datasets → continue training
        model.fit(
            X_train, y_train,
            eval_set=[(X_train, y_train), (X_test, y_test)],
            xgb_model=model,  # continue from previous model
            verbose=50
        )

    # ======================
    # Evaluation
    # ======================
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print("===== Model Metrics =====")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1-score : {f1:.4f}")
    print(f"ROC-AUC  : {roc:.4f}")
    print("Confusion Matrix:")
    print(cm)

# ======================
# Export final model
# ======================
joblib.dump(model, "xgb_attack_model.pkl")
print("\nFinal model exported successfully!")

