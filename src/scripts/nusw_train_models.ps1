$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Script location (usually <repo>\src\scripts)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Repo root assumed: src\scripts -> ..\..
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")

# Prefer workspace venv Python when available
$py = "python"
$venvPy = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPy) {
    $py = $venvPy
}

# Default runtime knobs
$hgbEpochs = "100"
$multiclassEpochs = "100"
$mlpEpochs = "25"
$anomalyEstimators = "100"
$fold = "7"
$nFolds = "8"

function RunPy([string]$relPath, [string[]]$pyArgs) {
    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }
    & $py -u $fullPath @pyArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $relPath (exit code $LASTEXITCODE)"
    }
}

Write-Host "=== NUSW train-all models ===" -ForegroundColor Green
Write-Host "Repo root: $repoRoot"
Write-Host "Python   : $py"

# 1) Preprocess datasets
RunPy "src\models\NUSW-NB15\prepare_dataset.py" @("--split_mode", "random", "--source_set", "raw4", "--seed", "42")
RunPy "src\models\NUSW-NB15\prepare_dataset.py" @(
    "--split_mode", "groupkfold",
    "--source_set", "raw4",
    "--fold", $fold,
    "--n_folds", $nFolds,
    "--anomaly_group_train_policy", "fallback_official_benign"
)
RunPy "src\models\NUSW-NB15\prepare_dataset.py" @("--split_mode", "official", "--source_set", "official_pair", "--seed", "42")

# 2) Validate generated datasets
RunPy "src\models\NUSW-NB15\validate_datasets.py" @("--modes", "random", "groupkfold", "official", "--label_map_scope", "latest")

# 3) Random mode - all NUSW models
RunPy "src\models\NUSW-NB15\train_ml_binary_hgb.py" @("--split_mode", "random", "--epochs", $hgbEpochs)
RunPy "src\models\NUSW-NB15\train_ml_multiclass_hgb.py" @("--split_mode", "random", "--epochs", $multiclassEpochs)
RunPy "src\models\NUSW-NB15\train_ml_binary_mlp.py" @("--split_mode", "random", "--epochs", $mlpEpochs)
RunPy "src\models\NUSW-NB15\train_anomaly_isoforest.py" @("--split_mode", "random", "--epochs", $anomalyEstimators)

# 4) Groupkfold mode (single fold by default)
RunPy "src\models\NUSW-NB15\train_ml_binary_hgb.py" @("--split_mode", "groupkfold", "--fold", $fold, "--n_folds", $nFolds, "--epochs", $hgbEpochs)
RunPy "src\models\NUSW-NB15\train_ml_multiclass_hgb.py" @("--split_mode", "groupkfold", "--fold", $fold, "--n_folds", $nFolds, "--epochs", $multiclassEpochs)
RunPy "src\models\NUSW-NB15\train_ml_binary_mlp.py" @("--split_mode", "groupkfold", "--fold", $fold, "--n_folds", $nFolds, "--epochs", $mlpEpochs)
RunPy "src\models\NUSW-NB15\train_anomaly_isoforest.py" @("--split_mode", "groupkfold", "--fold", $fold, "--n_folds", $nFolds, "--epochs", $anomalyEstimators)

# 5) Official mode
RunPy "src\models\NUSW-NB15\train_ml_binary_hgb.py" @("--split_mode", "official", "--epochs", $hgbEpochs)
RunPy "src\models\NUSW-NB15\train_ml_multiclass_hgb.py" @("--split_mode", "official", "--epochs", $multiclassEpochs)
RunPy "src\models\NUSW-NB15\train_ml_binary_mlp.py" @("--split_mode", "official", "--epochs", $mlpEpochs)
RunPy "src\models\NUSW-NB15\train_anomaly_isoforest.py" @("--split_mode", "official", "--epochs", $anomalyEstimators)

# 6) Comparison and dataset decision report
RunPy "src\models\NUSW-NB15\compare_models.py" @("--artifacts_dir", (Join-Path $repoRoot "src\models\NUSW-NB15\artifacts"))
RunPy "src\models\NUSW-NB15\evaluate_train_test_network.py" @()

Write-Host "NUSW train-all finished." -ForegroundColor Green