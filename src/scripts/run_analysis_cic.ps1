$ErrorActionPreference = "Stop"

python src\helpers\analyze_cic_folder.py `
  --ml_dir "C:\Users\xfeli\Desktop\TFM\modelos\src\datasets\CIC-IDS2017\MachineLearningCVE" `
  --flows_dir "C:\Users\xfeli\Desktop\TFM\modelos\src\datasets\CIC-IDS2017\TrafficLabelling" `
  --out out/CIC --deep