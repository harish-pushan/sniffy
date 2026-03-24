import joblib
import numpy as np
import xgboost 
print(joblib.__version__)

model = joblib.load("xgb_attack_model.pkl")
features = [[
    11937,80,6,7.0,280,2,0,0,2,2,0,
    4293202,1765,0,64,64,140,140,0,140,140140.0,0.0,0,0,0,0,
    1120000,0,0,2,0,0,0,512,0,0,0,0,0,0,0.0
]]

print(model.predict(features))
print(model.predict_proba(features))