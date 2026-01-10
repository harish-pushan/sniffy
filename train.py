import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import xgboost as xgb
import numpy as np
import joblib  # for pickle export

# ======================
# 1. Load dataset
# ======================
df = pd.read_csv("/mnt/8tb_hdd/harish/ds2/splited/dataset0.csv")

# Drop non-feature columns
drop_cols = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Dataset"]  # we drop IPs and dataset label
X = df.drop(columns=drop_cols + ["Label"])
y = df["Label"]

# ======================
# 2. Train-test split
# ======================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ======================
# 3. Calculate class imbalance
# ======================
neg, pos = np.bincount(y_train)
scale_pos_weight = neg / pos

# ======================
# 4. Define XGBoost model
# ======================
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

# ======================
# 5. Train model with early stopping
# ======================
eval_set = [(X_train, y_train), (X_test, y_test)]
model.fit(
    X_train, y_train,
    eval_set=eval_set,
    verbose=50
)

# ======================
# 6. Make predictions
# ======================
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

# ======================
# 7. Evaluation metrics
# ======================
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
# 8. Export the model
# ======================


# Option 2: Pickle export (Python-only, convenient for pipelines)
joblib.dump(model, "xgb_attack_model.pkl")
print("Model exported successfully!")

