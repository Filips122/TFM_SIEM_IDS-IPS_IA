# TFM_SIEM_IDS-IPS_IA

python -m pip install torch==2.9.1 torchvision==0.24.1 torchaudio==2.9.1 --index-url https://download.pytorch.org/whl/cu128

-------------

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1

-------------

src\scripts\run_analysis.ps1
src\scripts\cic_run_all_models.ps1

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