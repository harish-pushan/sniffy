import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import joblib  # for saving the model

# ======================
# 1. Load dataset
# ======================
df = pd.read_csv("d/mnt/8tb_hdd/harish/ds2/splited/dataset0.csv")

# Drop non-feature columns
drop_cols = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Dataset"]
X = df.drop(columns=drop_cols + ["Label"])
y = df["Label"]

# ======================
# 2. Train-test split
# ======================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ======================
# 3. Create DMatrix objects
# ======================
dtrain = xgb.DMatrix(X_train, label=y_train)
dtest = xgb.DMatrix(X_test, label=y_test)

# ======================
# 4. Calculate class imbalance
# ======================
neg, pos = np.bincount(y_train)
scale_pos_weight = neg / pos

# ======================
# 5. Set XGBoost parameters
# ======================
params = {
    "objective": "binary:logistic",
    "max_depth": 6,
    "eta": 0.05,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "scale_pos_weight": scale_pos_weight,
    "reg_alpha": 0.1,
    "reg_lambda": 1,
    "eval_metric": "auc",
    "seed": 42
}

# ======================
# 6. Train model with early stopping
# ======================
evals = [(dtrain, "train"), (dtest, "eval")]
num_boost_round = 500
early_stopping_rounds = 30

model = xgb.train(
    params=params,
    dtrain=dtrain,
    num_boost_round=num_boost_round,
    evals=evals,
    early_stopping_rounds=early_stopping_rounds,
    verbose_eval=50
)

# ======================
# 7. Make predictions
# ======================
y_proba = model.predict(dtest)
y_pred = (y_proba > 0.5).astype(int)

# ======================
# 8. Evaluation metrics
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
# 9. Export the model
# ======================
joblib.dump(model, "xgb_attack_model.pkl")
print("Model exported successfully!")

