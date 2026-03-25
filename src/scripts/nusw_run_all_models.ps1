param(
    [string[]]$Modes = @("random", "groupkfold", "official"),

    [ValidateSet("raw4", "official_pair", "all")]
    [string]$SourceSet = "raw4",

    [ValidateSet("strict", "fallback_official_benign")]
    [string]$AnomalyGroupTrainPolicy = "strict",

    [string]$PythonExe = "python",
    [int]$Chunksize = 250000,
    [int]$Seed = 42,
    [int]$BinaryEpochs = 200,
    [int]$MulticlassEpochs = 250,
    [int]$AnomalyEstimators = 300,
    [int]$MlpEpochs = 25,
    [int]$NFolds = 8,
    [int[]]$GroupFolds = @(0),
    [double]$SampleFrac,
    [switch]$AllGroupFolds,
    [switch]$RunAnalysis,
    [switch]$SkipBinaryMlp,
    [switch]$DeepAnalysis,
    [switch]$SkipPreprocess,
    [switch]$SkipValidation,
    [switch]$SkipCompare
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$allowedModes = @("random", "groupkfold", "official")
$normalizedModes = @()
foreach ($modeArg in $Modes) {
    $parts = @($modeArg -split ",")
    foreach ($part in $parts) {
        $candidate = $part.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        if ($allowedModes -notcontains $candidate) {
            throw "Invalid mode '$candidate'. Allowed values: $($allowedModes -join ', ')"
        }
        $normalizedModes += $candidate
    }
}
$Modes = $normalizedModes | Select-Object -Unique

if (-not $Modes -or $Modes.Count -eq 0) {
    throw "At least one mode is required. Allowed values: $($allowedModes -join ', ')"
}

# Script location (usually <repo>\src\scripts)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Repo root assumed: src\scripts -> ..\..
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if ($PythonExe -eq "python" -and (Test-Path $venvPython)) {
    $PythonExe = $venvPython
}
$hasSampleFrac = $PSBoundParameters.ContainsKey("SampleFrac")

function RunPy([string]$relPath, [string[]]$pyArgs) {
    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }

    Write-Host "`n>>> python -u $relPath $($pyArgs -join ' ')" -ForegroundColor Cyan
    & $PythonExe -u $fullPath @pyArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $relPath (exit code $LASTEXITCODE)"
    }
}

function Invoke-Prepare([string]$mode) {
    $prepareSourceSet = if ($mode -eq "official") { "official_pair" } else { $SourceSet }
    $args = @(
        "--split_mode", $mode,
        "--source_set", $prepareSourceSet,
        "--anomaly_group_train_policy", $AnomalyGroupTrainPolicy,
        "--chunksize", "$Chunksize",
        "--seed", "$Seed"
    )

    if ($mode -eq "groupkfold") {
        if ($AllGroupFolds) {
            $args += @("--all_folds", "--n_folds", "$NFolds")
        }
        else {
            foreach ($fold in $GroupFolds) {
                RunPy "src\models\NUSW-NB15\prepare_dataset.py" ($args + @("--fold", "$fold", "--n_folds", "$NFolds"))
            }
            return
        }
    }

    RunPy "src\models\NUSW-NB15\prepare_dataset.py" $args
}

function Invoke-GroupedTrainer([string]$relPath, [string]$epochsArg, [int]$epochsValue) {
    if ($AllGroupFolds) {
        $args = @("--split_mode", "groupkfold", "--all_folds", "--n_folds", "$NFolds", $epochsArg, "$epochsValue")
        if ($hasSampleFrac) {
            $args += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $args
        return
    }

    foreach ($fold in $GroupFolds) {
        $args = @("--split_mode", "groupkfold", "--fold", "$fold", "--n_folds", "$NFolds", $epochsArg, "$epochsValue")
        if ($hasSampleFrac) {
            $args += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $args
    }
}

function Invoke-GroupedAnomalyTrainer() {
    if ($AllGroupFolds) {
        RunPy "src\models\NUSW-NB15\train_anomaly_isoforest.py" @(
            "--split_mode", "groupkfold",
            "--all_folds",
            "--n_folds", "$NFolds",
            "--epochs", "$AnomalyEstimators"
        )
        return
    }

    foreach ($fold in $GroupFolds) {
        RunPy "src\models\NUSW-NB15\train_anomaly_isoforest.py" @(
            "--split_mode", "groupkfold",
            "--fold", "$fold",
            "--n_folds", "$NFolds",
            "--epochs", "$AnomalyEstimators"
        )
    }
}

Write-Host "=== NUSW-NB15 orchestration ===" -ForegroundColor Green
Write-Host "Repo root : $repoRoot"
Write-Host "Python    : $PythonExe"
Write-Host "Modes     : $($Modes -join ', ')"
Write-Host "Source set: $SourceSet"
Write-Host "Anomaly policy: $AnomalyGroupTrainPolicy"
Write-Host "Run binary MLP: $(-not $SkipBinaryMlp)"

if ($RunAnalysis) {
    $analysisArgs = @()
    if ($DeepAnalysis) {
        $analysisArgs += "--deep"
    }
    RunPy "src\helpers\analyze_nusw_folder.py" $analysisArgs
}

if (-not $SkipPreprocess) {
    foreach ($mode in $Modes) {
        Invoke-Prepare $mode
    }
}

if (-not $SkipValidation) {
    RunPy "src\models\NUSW-NB15\validate_datasets.py" (@("--modes") + $Modes)
}

foreach ($mode in $Modes) {
    if ($mode -eq "groupkfold") {
        Invoke-GroupedTrainer "src\models\NUSW-NB15\train_ml_binary_hgb.py" "--epochs" $BinaryEpochs
        Invoke-GroupedTrainer "src\models\NUSW-NB15\train_ml_multiclass_hgb.py" "--epochs" $MulticlassEpochs
        if (-not $SkipBinaryMlp) {
            Invoke-GroupedTrainer "src\models\NUSW-NB15\train_ml_binary_mlp.py" "--epochs" $MlpEpochs
        }
        Invoke-GroupedAnomalyTrainer
        continue
    }

    $binaryArgs = @("--split_mode", $mode, "--epochs", "$BinaryEpochs")
    $multiclassArgs = @("--split_mode", $mode, "--epochs", "$MulticlassEpochs")
    if ($hasSampleFrac) {
        $binaryArgs += @("--sample_frac", "$SampleFrac")
        $multiclassArgs += @("--sample_frac", "$SampleFrac")
    }

    RunPy "src\models\NUSW-NB15\train_ml_binary_hgb.py" $binaryArgs
    RunPy "src\models\NUSW-NB15\train_ml_multiclass_hgb.py" $multiclassArgs
    if (-not $SkipBinaryMlp) {
        $mlpArgs = @("--split_mode", $mode, "--epochs", "$MlpEpochs")
        if ($hasSampleFrac) {
            $mlpArgs += @("--sample_frac", "$SampleFrac")
        }
        RunPy "src\models\NUSW-NB15\train_ml_binary_mlp.py" $mlpArgs
    }
    RunPy "src\models\NUSW-NB15\train_anomaly_isoforest.py" @("--split_mode", $mode, "--epochs", "$AnomalyEstimators")
}

if (-not $SkipCompare) {
    RunPy "src\models\NUSW-NB15\compare_models.py" @(
        "--artifacts_dir", (Join-Path $repoRoot "src\models\NUSW-NB15\artifacts")
    )
}

Write-Host "`nNUSW-NB15 orchestration finished." -ForegroundColor Green