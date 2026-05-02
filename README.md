# TFM_SIEM_IDS-IPS_IA

python -m pip install torch==2.9.1 torchvision==0.24.1 torchaudio==2.9.1 --index-url https://download.pytorch.org/whl/cu128

-------------

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1

-------------

src\scripts\run_analysis.ps1
src\scripts\cic_run_all_models.ps1
src\scripts\nusw_run_all_models.ps1
src\scripts\nusw_train_models.ps1

-------------

python print_tree.py "C:\\Users\\xfeli\\Desktop\TFM\\modelos"

-------------

python .\src\models\CIC-IDS2017\prepare_dataset.py --split_mode day --datasets both

python .\src\models\CIC-IDS2017\prepare_dataset.py --split_mode groupkfold --datasets both

python .\src\models\CIC-IDS2017\prepare_dataset.py --split_mode random --datasets both --seed 42

-------------

python .\src\models\CIC-IDS2017\prepare_sequence_dataset.py --mode day --task binary --window 20 --group_key source_ip

python .\src\models\CIC-IDS2017\prepare_sequence_dataset.py --mode groupkfold --task binary --window 20 --group_key source_ip

python .\src\models\CIC-IDS2017\prepare_sequence_dataset.py --mode random --task binary --window 20 --seed 42

-------------

python .\src\helpers\analyze_nusw_folder.py --deep

python .\src\models\NUSW-NB15\prepare_dataset.py --split_mode random --source_set raw4 --seed 42

python .\src\models\NUSW-NB15\prepare_dataset.py --split_mode groupkfold --source_set raw4 --all_folds --n_folds 8

python .\src\models\NUSW-NB15\prepare_dataset.py --split_mode official --source_set official_pair

python .\src\models\NUSW-NB15\validate_datasets.py --modes random groupkfold official

python .\src\models\NUSW-NB15\train_ml_binary_hgb.py --split_mode random --epochs 200

python .\src\models\NUSW-NB15\train_ml_multiclass_hgb.py --split_mode random --epochs 250

python .\src\models\NUSW-NB15\train_anomaly_isoforest.py --split_mode random --epochs 300

python .\src\models\NUSW-NB15\train_ml_binary_mlp.py --split_mode random --epochs 25

python .\src\models\NUSW-NB15\compare_models.py --artifacts_dir src\models\NUSW-NB15\artifacts

python .\src\models\NUSW-NB15\evaluate_train_test_network.py

.\src\scripts\nusw_run_all_models.ps1 -Modes random,groupkfold,official -AllGroupFolds -RunAnalysis -DeepAnalysis

# Optional: skip the MLP baseline if you only want tree + anomaly models
.\src\scripts\nusw_run_all_models.ps1 -Modes random,groupkfold,official -AllGroupFolds -SkipBinaryMlp

-------------

UGR16

python .\src\models\UGR16\prepare_dataset.py --split_mode date --binary_balance stratified_downsample

python .\src\models\UGR16\prepare_dataset.py --split_mode random --binary_balance stratified_downsample --seed 42

python .\src\models\UGR16\prepare_dataset.py --split_mode groupkfold --binary_balance stratified_downsample --all_folds --n_folds 8

python .\src\models\UGR16\validate_datasets.py --modes date random groupkfold

python .\src\models\UGR16\train_ml_binary_hgb.py --split_mode date --epochs 200

python .\src\models\UGR16\train_ml_multiclass_hgb.py --split_mode date --epochs 250

python .\src\models\UGR16\train_anomaly_isoforest.py --split_mode date --epochs 300

python .\src\models\UGR16\train_ml_binary_mlp.py --split_mode date --epochs 25

python .\src\models\UGR16\compare_models.py --artifacts_dir src\models\UGR16\artifacts

.\src\scripts\ugr_run_all_models.ps1 -Modes date

# Optional: full sweep across split families and all grouped folds
.\src\scripts\ugr_run_all_models.ps1 -Modes date,random,groupkfold -AllGroupFolds

# Optional: skip weak-label multiclass and MLP when you only want the core baselines
.\src\scripts\ugr_run_all_models.ps1 -Modes date,random,groupkfold -AllGroupFolds -SkipMulticlass -SkipBinaryMlp

-------------