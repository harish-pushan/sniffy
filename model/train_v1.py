import numpy as np
import pandas as pd
import warnings
from os import walk
from sys import argv
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix


warnings.simplefilter(action='ignore', category=RuntimeWarning)
# Define the number of rows per chunk
CHUNKSIZE = 100000
COLS = [
    "IPV4_SRC_ADDR",
    "L4_SRC_PORT",
    "IPV4_DST_ADDR",
    "L4_DST_PORT",
    "PROTOCOL",
    "L7_PROTO",
    "IN_BYTES",
    "IN_PKTS",
    "OUT_BYTES",
    "OUT_PKTS",
    "TCP_FLAGS",
    "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN",
    "DURATION_OUT",
    "MIN_TTL",
    "MAX_TTL",
    "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES",
    "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES",
    "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES",
    "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT",
    "ICMP_TYPE",
    "ICMP_IPV4_TYPE",
    "DNS_QUERY_ID",
    "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER",
    "FTP_COMMAND_RET_CODE",
    "Label",
    "Attack",
    "Dataset",
]


def split_csv(csv_location:str) -> int:
    storage_location = "/home/h4r15h/dataset/sniffy/splitted/"
    counter = 0
    chunks = pd.read_csv(csv_location, chunksize=CHUNKSIZE)
    # Using the default header as the column 
    for chunk in chunks:
        if counter == 0:
            df = pd.DataFrame(chunk)
            df.to_csv(f'{storage_location}dataset{counter}.csv')
            print(f"Write succussful for :{storage_location}dataset{counter}.csv")
            counter +=1
    # Hardcoding the header and using that as the column (I can't come up with a better solution)
        else:
            df = pd.DataFrame(chunk)
            df.columns = COLS
            df.to_csv(f'{storage_location}dataset{counter}.csv')
            print(f"Write succussful for :{storage_location}dataset{counter}.csv")
            counter +=1
    return 1



def import_data(csv_location:str):
    raw_dataset = pd.read_csv(csv_location)
    np_array = raw_dataset.to_numpy()
    return np_array

def prepare_features(dataframe):
    df = dataframe
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
        X, y, test_size=0.35, random_state=42, stratify=y
    )

    # Class imbalance
    neg, pos = np.bincount(y_train)
    scale_pos_weight = neg / pos

    return X_train, X_test, y_train, y_test, scale_pos_weight

'''
#All the documentation says that is should be:
#scale_pos_weight = count(negative examples)/count(Positive examples)
'''

def prepare_dataframe_from_directory(directory_location:str):
    #directory path treversal
    file_names_list = []
    for (dirpath,dirname,filename) in walk(directory_location):
        print(dirpath)
        file_names_list.extend(filename)
    
    for i in file_names_list:
        print(i)
        if i[-3:] == "csv":
                #now think about how to get this data into the training routine 
                # Create the numpy array with the file name 
                new_location = f"/home/h4r15h/dataset/sniffy/splitted/{i}"
                data_chunk = pd.read_csv(new_location)    
                df = pd.DataFrame(data_chunk)
                xtrain , xtest, ytrain, ytest ,scal_pos_weight = prepare_features(df)
                return xtrain,xtest,ytrain,ytest,scal_pos_weight
        else:
            pass 
            
def train_model(xtrain,xtest,ytrain,ytest,scal_pos_weight):
    model = None

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
    
    joblib.dump(model, "xgb_attack_model.pkl")
    print("\nFinal model exported successfully!")       




    
