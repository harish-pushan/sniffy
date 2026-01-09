import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib

df = pd.read_csv("~/dataset/sniffy/9810e03bba4983da_MOHANAD_A4706/data/dataset.csv")
df.info()


TARGET = "Label"   # or "Attack"

drop_cols = [
    "Attack",
    "Dataset"
]

X = df.drop(columns=drop_cols + [TARGET])
y = df[TARGET]


for col in X.columns:
    if X[col].dtype == "object":
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))


X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    n_jobs=-1,
    random_state=42
)

rf.fit(X_train, y_train)



y_pred = rf.predict(X_test)

print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))


joblib.dump(rf, "rf_nids_model.pkl")
joblib.dump(scaler, "scaler.pkl")
