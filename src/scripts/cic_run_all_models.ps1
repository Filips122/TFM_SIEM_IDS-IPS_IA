param(
    [string]$PythonExe = "python",
    [int]$Epochs = 20,
    [switch]$SkipCompare,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Script location (usually <repo>\src\scripts)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Repo root assumed: src\scripts -> ..\..
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")

$py = $PythonExe
$epochs = "$Epochs"

function RunPy([string]$relPath, [string[]]$pyArgs) {
    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }
    Write-Host "`n>>> python -u $relPath $($pyArgs -join ' ')" -ForegroundColor Cyan
    if ($DryRun) {
        return
    }
    & $py -u $fullPath @pyArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $relPath (exit code $LASTEXITCODE)"
    }
}

Write-Host "=== CIC-IDS2017 orchestration ===" -ForegroundColor Green
Write-Host "Repo root : $repoRoot"
Write-Host "Python    : $py"
Write-Host "Epochs    : $epochs"
Write-Host "Dry run   : $DryRun"

# --- Online TL ---
RunPy "src\models\CIC-IDS2017\train_tl_binary_logreg_torch.py" @("--split_mode","day","--epochs",$epochs)
RunPy "src\models\CIC-IDS2017\train_tl_binary_logreg_torch.py" @("--split_mode","groupkfold","--fold","4","--epochs",$epochs)

RunPy "src\models\CIC-IDS2017\train_tl_binary_hgb.py" @("--split_mode","day","--epochs",$epochs)
RunPy "src\models\CIC-IDS2017\train_tl_binary_hgb.py" @("--split_mode","groupkfold","--fold","4","--epochs",$epochs)

# --- Offline ML binario ---
RunPy "src\models\CIC-IDS2017\train_ml_binary_hgb.py" @("--split_mode","day","--epochs",$epochs)
RunPy "src\models\CIC-IDS2017\train_ml_binary_hgb.py" @("--split_mode","groupkfold","--fold","4","--epochs",$epochs)

# --- Offline ML (PyTorch) entrenado en random + report day/kfold4 ---
RunPy "src\models\CIC-IDS2017\train_ml_binary_mlp.py" @("--epochs",$epochs)
RunPy "src\models\CIC-IDS2017\train_ml_binary_fttransformer.py" @("--epochs",$epochs)

# --- Offline ML multiclass ---
RunPy "src\models\CIC-IDS2017\train_ml_multiclass_hgb.py" @("--split_mode","random","--epochs",$epochs)

# --- Anomaly (IsolationForest) ---
RunPy "src\models\CIC-IDS2017\train_anomaly_isoforest.py" @("--dataset","TrafficLabelling","--split_mode","day","--epochs",$epochs)
RunPy "src\models\CIC-IDS2017\train_anomaly_isoforest.py" @("--dataset","TrafficLabelling","--split_mode","groupkfold","--fold","4","--epochs",$epochs)

# --- Secuencial GRU ---
RunPy "src\models\CIC-IDS2017\train_seq_tl_gru.py" @("--mode","day","--task","binary","--epochs",$epochs)
RunPy "src\models\CIC-IDS2017\train_seq_tl_gru.py" @("--mode","groupkfold","--task","binary","--fold","4","--epochs",$epochs)

# --- Comparativa final ---
if (-not $SkipCompare) {
    RunPy "src\models\CIC-IDS2017\compare_models.py" @("--artifacts_dir", (Join-Path $repoRoot "src\models\CIC-IDS2017\artifacts"), "--split_modes", "day", "groupkfold", "random")
}

Write-Host "`nCIC-IDS2017 orchestration finished." -ForegroundColor Green