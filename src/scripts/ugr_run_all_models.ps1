param(
    [string[]]$Modes = @("date"),

    [ValidateSet("thesis_v1", "all_main")]
    [string]$Subset = "thesis_v1",

    [ValidateSet("stratified_downsample", "none")]
    [string]$BinaryBalance = "stratified_downsample",

    [string]$PythonExe = "python",
    [int]$Chunksize = 250000,
    [int]$Seed = 42,
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 265,
    [int]$AnomalyEstimators = 315,
    [int]$AnomalyMaxTrainRows = 500000,
    [int]$AnomalyMaxEvalRows = 200000,
    [int]$AnomalyNJobs = 1,
    [int]$MlpEpochs = 40,
    [int]$NFolds = 8,
    [int[]]$GroupFolds = @(0),
    [double]$SampleFrac,
    [switch]$AllGroupFolds,
    [switch]$SkipBinaryMlp,
    [switch]$SkipMulticlass,
    [switch]$SkipPreprocess,
    [switch]$SkipValidation,
    [switch]$SkipCompare
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$allowedModes = @("date", "random", "groupkfold")
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

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
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
    $args = @(
        "--split_mode", $mode,
        "--subset", $Subset,
        "--binary_balance", $BinaryBalance,
        "--chunksize", "$Chunksize",
        "--seed", "$Seed"
    )

    if ($mode -eq "groupkfold") {
        if ($AllGroupFolds) {
            $args += @("--all_folds", "--n_folds", "$NFolds")
        }
        else {
            foreach ($fold in $GroupFolds) {
                RunPy "src\models\UGR16\prepare_dataset.py" ($args + @("--fold", "$fold", "--n_folds", "$NFolds"))
            }
            return
        }
    }

    RunPy "src\models\UGR16\prepare_dataset.py" $args
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
        $args = @(
            "--split_mode", "groupkfold",
            "--all_folds",
            "--n_folds", "$NFolds",
            "--epochs", "$AnomalyEstimators",
            "--max_train_rows", "$AnomalyMaxTrainRows",
            "--max_eval_rows", "$AnomalyMaxEvalRows",
            "--n_jobs", "$AnomalyNJobs",
            "--seed", "$Seed"
        )
        if ($hasSampleFrac) {
            $args += @("--sample_frac", "$SampleFrac")
        }
        RunPy "src\models\UGR16\train_anomaly_isoforest.py" $args
        return
    }

    foreach ($fold in $GroupFolds) {
        $args = @(
            "--split_mode", "groupkfold",
            "--fold", "$fold",
            "--n_folds", "$NFolds",
            "--epochs", "$AnomalyEstimators",
            "--max_train_rows", "$AnomalyMaxTrainRows",
            "--max_eval_rows", "$AnomalyMaxEvalRows",
            "--n_jobs", "$AnomalyNJobs",
            "--seed", "$Seed"
        )
        if ($hasSampleFrac) {
            $args += @("--sample_frac", "$SampleFrac")
        }
        RunPy "src\models\UGR16\train_anomaly_isoforest.py" $args
    }
}

Write-Host "=== UGR16 orchestration ===" -ForegroundColor Green
Write-Host "Repo root      : $repoRoot"
Write-Host "Python         : $PythonExe"
Write-Host "Modes          : $($Modes -join ', ')"
Write-Host "Subset         : $Subset"
Write-Host "Binary balance : $BinaryBalance"
Write-Host "Run multiclass : $(-not $SkipMulticlass)"
Write-Host "Run binary MLP : $(-not $SkipBinaryMlp)"
Write-Host "Anomaly rows   : train<=${AnomalyMaxTrainRows}, eval<=${AnomalyMaxEvalRows}, n_jobs=${AnomalyNJobs}"

if (-not $SkipPreprocess) {
    foreach ($mode in $Modes) {
        Invoke-Prepare $mode
    }
}

if (-not $SkipValidation) {
    RunPy "src\models\UGR16\validate_datasets.py" (@("--modes") + $Modes)
}

foreach ($mode in $Modes) {
    if ($mode -eq "groupkfold") {
        Invoke-GroupedTrainer "src\models\UGR16\train_ml_binary_hgb.py" "--epochs" $BinaryEpochs
        if (-not $SkipMulticlass) {
            Invoke-GroupedTrainer "src\models\UGR16\train_ml_multiclass_hgb.py" "--epochs" $MulticlassEpochs
        }
        if (-not $SkipBinaryMlp) {
            Invoke-GroupedTrainer "src\models\UGR16\train_ml_binary_mlp.py" "--epochs" $MlpEpochs
        }
        Invoke-GroupedAnomalyTrainer
        continue
    }

    $binaryArgs = @("--split_mode", $mode, "--epochs", "$BinaryEpochs")
    if ($hasSampleFrac) {
        $binaryArgs += @("--sample_frac", "$SampleFrac")
    }
    RunPy "src\models\UGR16\train_ml_binary_hgb.py" $binaryArgs

    if (-not $SkipMulticlass) {
        $multiclassArgs = @("--split_mode", $mode, "--epochs", "$MulticlassEpochs")
        if ($hasSampleFrac) {
            $multiclassArgs += @("--sample_frac", "$SampleFrac")
        }
        RunPy "src\models\UGR16\train_ml_multiclass_hgb.py" $multiclassArgs
    }

    if (-not $SkipBinaryMlp) {
        $mlpArgs = @("--split_mode", $mode, "--epochs", "$MlpEpochs")
        if ($hasSampleFrac) {
            $mlpArgs += @("--sample_frac", "$SampleFrac")
        }
        RunPy "src\models\UGR16\train_ml_binary_mlp.py" $mlpArgs
    }

    $anomalyArgs = @(
        "--split_mode", $mode,
        "--epochs", "$AnomalyEstimators",
        "--max_train_rows", "$AnomalyMaxTrainRows",
        "--max_eval_rows", "$AnomalyMaxEvalRows",
        "--n_jobs", "$AnomalyNJobs",
        "--seed", "$Seed"
    )
    if ($hasSampleFrac) {
        $anomalyArgs += @("--sample_frac", "$SampleFrac")
    }
    RunPy "src\models\UGR16\train_anomaly_isoforest.py" $anomalyArgs
}

if (-not $SkipCompare) {
    $compareArgs = @("--artifacts_dir", (Join-Path $repoRoot "src\models\UGR16\artifacts"), "--split_modes") + $Modes
    RunPy "src\models\UGR16\compare_models.py" $compareArgs
}

Write-Host "`nUGR16 orchestration finished." -ForegroundColor Green