param(
    [string[]]$Modes = @("date"),
    [string]$Dataset = "UGR16_MARAPR_HYBRID",
    [string]$PythonExe = "python",
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 265,
    [int]$AnomalyEstimators = 315,
    [int]$AnomalyMaxTrainRows = 500000,
    [int]$AnomalyMaxEvalRows = 200000,
    [int]$AnomalyNJobs = 1,
    [int]$MlpEpochs = 40,
    [int]$NFolds = 8,
    [int[]]$GroupFolds = @(0),
    [int]$Seed = 42,
    [double]$SampleFrac,
    [switch]$AllGroupFolds,
    [switch]$SkipBinaryHgb,
    [switch]$SkipBinaryMlp,
    [switch]$SkipMulticlass,
    [switch]$ForceMulticlass,
    [switch]$SkipAnomaly,
    [switch]$SkipCompare,
    [switch]$SkipDatasetCheck,
    [switch]$DryRun
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
$datasetsBase = Join-Path $repoRoot "src\models\UGR16\datasets"
$artifactsDir = Join-Path $repoRoot "src\models\UGR16\artifacts"
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if ($PythonExe -eq "python" -and (Test-Path $venvPython)) {
    $PythonExe = $venvPython
}
$hasSampleFrac = $PSBoundParameters.ContainsKey("SampleFrac")

function RunPy([string]$relPath, [string[]]$pythonParams) {
    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }

    Write-Host "`n>>> python -u $relPath $($pythonParams -join ' ')" -ForegroundColor Cyan
    if ($DryRun) {
        return
    }

    & $PythonExe -u $fullPath @pythonParams
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $relPath (exit code $LASTEXITCODE)"
    }
}

function Get-DatasetRoot([string]$mode) {
    return Join-Path $datasetsBase (Join-Path $mode $Dataset)
}

function Get-FoldRoot([string]$mode, [int]$fold) {
    return Join-Path (Get-DatasetRoot $mode) "fold_$fold"
}

function Test-ParquetFolder([string]$folder) {
    if (!(Test-Path $folder)) {
        return $false
    }

    $first = Get-ChildItem -Path $folder -Filter "*.parquet" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    return $null -ne $first
}

function Test-PipelineReady([string]$baseDir, [string]$pipeline) {
    if ($pipeline -eq "anomaly") {
        $folders = @(
            (Join-Path $baseDir "anomaly\train_benign")
            (Join-Path $baseDir "anomaly\val_mixed")
            (Join-Path $baseDir "anomaly\test_mixed")
        )
    }
    else {
        $folders = @(
            (Join-Path $baseDir "$pipeline\train")
            (Join-Path $baseDir "$pipeline\val")
            (Join-Path $baseDir "$pipeline\test")
        )
    }

    $missing = @()
    foreach ($folder in $folders) {
        if (!(Test-ParquetFolder $folder)) {
            $missing += $folder
        }
    }

    return @{
        Ready = ($missing.Count -eq 0)
        Missing = $missing
    }
}

function Get-RequestedFolds() {
    if ($AllGroupFolds) {
        return 0..($NFolds - 1)
    }
    return $GroupFolds
}

function Assert-RequiredPipeline([string]$mode, [string]$pipeline) {
    if ($SkipDatasetCheck) {
        return
    }

    if ($mode -eq "groupkfold") {
        foreach ($fold in Get-RequestedFolds) {
            $foldRoot = Get-FoldRoot $mode $fold
            $status = Test-PipelineReady $foldRoot $pipeline
            if (-not $status.Ready) {
                throw "Dataset '$Dataset' is not ready for pipeline '$pipeline' in mode '$mode' fold_$fold. Missing parquet files in: $($status.Missing -join ', ')"
            }
        }
        return
    }

    $modeRoot = Get-DatasetRoot $mode
    $status = Test-PipelineReady $modeRoot $pipeline
    if (-not $status.Ready) {
        throw "Dataset '$Dataset' is not ready for pipeline '$pipeline' in mode '$mode'. Missing parquet files in: $($status.Missing -join ', ')"
    }
}

function Test-OptionalPipeline([string]$mode, [string]$pipeline) {
    if ($SkipDatasetCheck) {
        return $true
    }

    if ($mode -eq "groupkfold") {
        foreach ($fold in Get-RequestedFolds) {
            $status = Test-PipelineReady (Get-FoldRoot $mode $fold) $pipeline
            if (-not $status.Ready) {
                return $false
            }
        }
        return $true
    }

    $status = Test-PipelineReady (Get-DatasetRoot $mode) $pipeline
    return [bool]$status.Ready
}

function New-BaseTrainerArgs([string]$mode, [int]$epochs) {
    $trainerParams = @("--split_mode", $mode, "--dataset", $Dataset, "--epochs", "$epochs")
    if ($hasSampleFrac) {
        $trainerParams += @("--sample_frac", "$SampleFrac")
    }
    return $trainerParams
}

function New-AnomalyTrainerArgs([string]$mode, [int]$epochs) {
    $trainerParams = @(
        "--split_mode", $mode,
        "--dataset", $Dataset,
        "--epochs", "$epochs",
        "--max_train_rows", "$AnomalyMaxTrainRows",
        "--max_eval_rows", "$AnomalyMaxEvalRows",
        "--n_jobs", "$AnomalyNJobs",
        "--seed", "$Seed"
    )
    if ($hasSampleFrac) {
        $trainerParams += @("--sample_frac", "$SampleFrac")
    }
    return $trainerParams
}

function Invoke-GroupedTrainer([string]$relPath, [int]$epochs, [switch]$NoSampleFrac) {
    if ($AllGroupFolds) {
        $trainerParams = @("--split_mode", "groupkfold", "--dataset", $Dataset, "--all_folds", "--n_folds", "$NFolds", "--epochs", "$epochs")
        if ($hasSampleFrac -and -not $NoSampleFrac) {
            $trainerParams += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $trainerParams
        return
    }

    foreach ($fold in $GroupFolds) {
        $trainerParams = @("--split_mode", "groupkfold", "--dataset", $Dataset, "--fold", "$fold", "--n_folds", "$NFolds", "--epochs", "$epochs")
        if ($hasSampleFrac -and -not $NoSampleFrac) {
            $trainerParams += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $trainerParams
    }
}

function Invoke-GroupedAnomalyTrainer([int]$epochs) {
    if ($AllGroupFolds) {
        $trainerParams = @(
            "--split_mode", "groupkfold",
            "--dataset", $Dataset,
            "--all_folds",
            "--n_folds", "$NFolds",
            "--epochs", "$epochs",
            "--max_train_rows", "$AnomalyMaxTrainRows",
            "--max_eval_rows", "$AnomalyMaxEvalRows",
            "--n_jobs", "$AnomalyNJobs",
            "--seed", "$Seed"
        )
        if ($hasSampleFrac) {
            $trainerParams += @("--sample_frac", "$SampleFrac")
        }
        RunPy "src\models\UGR16\train_anomaly_isoforest.py" $trainerParams
        return
    }

    foreach ($fold in $GroupFolds) {
        $trainerParams = @(
            "--split_mode", "groupkfold",
            "--dataset", $Dataset,
            "--fold", "$fold",
            "--n_folds", "$NFolds",
            "--epochs", "$epochs",
            "--max_train_rows", "$AnomalyMaxTrainRows",
            "--max_eval_rows", "$AnomalyMaxEvalRows",
            "--n_jobs", "$AnomalyNJobs",
            "--seed", "$Seed"
        )
        if ($hasSampleFrac) {
            $trainerParams += @("--sample_frac", "$SampleFrac")
        }
        RunPy "src\models\UGR16\train_anomaly_isoforest.py" $trainerParams
    }
}

Write-Host "=== UGR16 existing-dataset model run ===" -ForegroundColor Green
Write-Host "Repo root   : $repoRoot"
Write-Host "Python      : $PythonExe"
Write-Host "Dataset     : $Dataset"
Write-Host "Modes       : $($Modes -join ', ')"
Write-Host "Anomaly rows: train<=${AnomalyMaxTrainRows}, eval<=${AnomalyMaxEvalRows}, n_jobs=${AnomalyNJobs}"
Write-Host "Dry run     : $DryRun"
Write-Host "No prepare_dataset script will be executed." -ForegroundColor Yellow

foreach ($mode in $Modes) {
    if (-not $SkipBinaryHgb -or -not $SkipBinaryMlp) {
        Assert-RequiredPipeline $mode "binary"
    }
    if (-not $SkipAnomaly) {
        Assert-RequiredPipeline $mode "anomaly"
    }
}

$canRunMulticlass = -not $SkipMulticlass
if ($canRunMulticlass) {
    foreach ($mode in $Modes) {
        if (-not (Test-OptionalPipeline $mode "multiclass")) {
            if ($ForceMulticlass) {
                Assert-RequiredPipeline $mode "multiclass"
            }
            Write-Warning "Multiclass pipeline is missing for dataset '$Dataset' mode '$mode'; train_ml_multiclass_hgb.py will be skipped. Use -ForceMulticlass to fail instead."
            $canRunMulticlass = $false
            break
        }
    }
}

foreach ($mode in $Modes) {
    if ($mode -eq "groupkfold") {
        if (-not $SkipBinaryHgb) {
            Invoke-GroupedTrainer "src\models\UGR16\train_ml_binary_hgb.py" $BinaryEpochs
        }
        if ($canRunMulticlass) {
            Invoke-GroupedTrainer "src\models\UGR16\train_ml_multiclass_hgb.py" $MulticlassEpochs
        }
        if (-not $SkipBinaryMlp) {
            Invoke-GroupedTrainer "src\models\UGR16\train_ml_binary_mlp.py" $MlpEpochs
        }
        if (-not $SkipAnomaly) {
            Invoke-GroupedAnomalyTrainer $AnomalyEstimators
        }
        continue
    }

    if (-not $SkipBinaryHgb) {
        RunPy "src\models\UGR16\train_ml_binary_hgb.py" (New-BaseTrainerArgs $mode $BinaryEpochs)
    }
    if ($canRunMulticlass) {
        RunPy "src\models\UGR16\train_ml_multiclass_hgb.py" (New-BaseTrainerArgs $mode $MulticlassEpochs)
    }
    if (-not $SkipBinaryMlp) {
        RunPy "src\models\UGR16\train_ml_binary_mlp.py" (New-BaseTrainerArgs $mode $MlpEpochs)
    }
    if (-not $SkipAnomaly) {
        RunPy "src\models\UGR16\train_anomaly_isoforest.py" (New-AnomalyTrainerArgs $mode $AnomalyEstimators)
    }
}

if (-not $SkipCompare) {
    $compareArgs = @("--artifacts_dir", $artifactsDir, "--datasets", $Dataset, "--split_modes") + $Modes
    RunPy "src\models\UGR16\compare_models.py" $compareArgs
}

Write-Host "`nUGR16 existing-dataset model run finished." -ForegroundColor Green
