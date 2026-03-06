import pandas as pd

p_ml = r"src/models/CIC-IDS2017/datasets/day/MachineLearningCVE/binary/train/Monday-WorkingHours.pcap_ISCX.parquet"
p_tl = r"src/models/CIC-IDS2017/datasets/day/TrafficLabelling/binary/train/Monday-WorkingHours.pcap_ISCX.parquet"

df_ml = pd.read_parquet(p_ml)
df_tl = pd.read_parquet(p_tl)

print("ML columns sample:", df_ml.columns[:10], " ...", len(df_ml.columns))
print("TL columns sample:", df_tl.columns[:10], " ...", len(df_tl.columns))
print("TL has Timestamp?", "Timestamp" in df_tl.columns)
print("TL has Source IP?", "Source IP" in df_tl.columns)