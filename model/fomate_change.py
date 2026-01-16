import pandas as pd

# only needs to be done once
df = pd.read_csv("nids.csv")  # original CSV stays
df.to_parquet("nids.parquet", engine="pyarrow", compression="snappy")
