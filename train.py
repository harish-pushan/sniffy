import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import ipaddress


def train_with_chunks(file_list):
    le = LabelEncoder() 
    scaler = StandardScaler()

    model = None
    first_chunk = True

    for idx, file in enumerate(file_list):
        print(f"\n Training on chunk {idx+1}/{len(file_list)}= {file}")

        # load data
        df = pd.read_csv(file)

        y = df["Label"]                 # target
        X = df.drop(columns=["Label"])  # ALL features kept

        ip_cols = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR"]
        
        def ip_to_int(ip):
            try:
                return int(ipaddress.IPv4Address(ip))
            except:
                return 0
        
        for col in ip_cols:
            df[col] = df[col].astype(str).apply(ip_to_int)
        
        # encode y ONLY
        y_enc = le.fit_transform(y)

        # scale X ONLY
        if first_chunk:
            X_scaled = scaler.fit_transform(X)
            first_chunk = False
        else:
            X_scaled = scaler.transform(X)

        # train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled,
            y_enc,
            test_size=0.2,
            stratify=y_enc,
            random_state=42
        )

        # model
        model = XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            objective="binary:logistic",
            eval_metric="logloss",
            n_jobs=-1,
            random_state=42
        )

        # chunk training
        model.fit(
            X_train,
            y_train,
            xgb_model=None if idx == 0 else model
        )

        # eval
        y_pred = model.predict(X_test)
        print(confusion_matrix(y_test, y_pred))
        print(classification_report(y_test, y_pred))

    # save everything
    joblib.dump(model, "xgb_chunk_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(le, "label_encoder.pkl")

    print("\n✅ model + scaler + encoder saved")


# file list 
file_list = [
    '/mnt/8tb_hdd/harish/ds2/splited/dataset0.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset12.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset15.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset3.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset6.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset9.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset10.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset13.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset1.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset4.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset7.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset11.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset14.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset2.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset5.csv',
    '/mnt/8tb_hdd/harish/ds2/splited/dataset8.csv'
]

train_with_chunks(file_list)

