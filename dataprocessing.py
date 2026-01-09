import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix

# ------------------------
# 1️⃣ Load dataset
# ------------------------
df = pd.read_parquet("nids.parquet")
df.info()
# ------------------------
# 2️⃣ Define target
# ------------------------
y = df["Label"]  # or df["Attack"] if you want multi-class
X = df.drop(columns=["Label"])  # Keep everything else

# ------------------------
# 3️⃣ Encode categorical features
# ------------------------
cat_cols = X.select_dtypes(include="object").columns.tolist()

for col in cat_cols:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col].astype(str))

# ------------------------
# 4️⃣ Scale numeric features (optional but recommended)
# ------------------------
num_cols = X.select_dtypes(include=np.number).columns.tolist()
scaler = StandardScaler()
X[num_cols] = scaler.fit_transform(X[num_cols])

# ------------------------
# 5️⃣ Train/test split
# ------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# ------------------------
# 6️⃣ XGBoost model
# ------------------------
model = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",  # change to multi:softprob for multi-class
    eval_metric="logloss",
    n_jobs=-1,
    random_state=42
)

model.fit(X_train, y_train)

# ------------------------
# 7️⃣ Evaluation
# ------------------------
y_pred = model.predict(X_test)
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))

# ------------------------
# 8️⃣ Feature importance (optional)
# ------------------------
import matplotlib.pyplot as plt

fi = pd.Series(model.feature_importances_, index=X.columns).sort_values(ascending=False)
fi.head(15).plot(kind="barh", figsize=(10,6))
plt.title("Top 15 Feature Importances")
plt.show()

