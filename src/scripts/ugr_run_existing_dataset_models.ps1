param(
    [string[]]$Modes = @("date"),
    [string]$Dataset = "UGR16_V3_80GB",
    [string]$PythonExe = "python",
    [int]$BinaryEpochs = 200,
    [int]$MulticlassEpochs = 250,
    [int]$AnomalyEstimators = 300,
    [int]$MlpEpochs = 25,
    [int]$NFolds = 8,
    [int[]]$GroupFolds = @(0),
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

function RunPy([string]$relPath, [string[]]$pyArgs) {
    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }

    Write-Host "`n>>> python -u $relPath $($pyArgs -join ' ')" -ForegroundColor Cyan
    if ($DryRun) {
        return
    }

    & $PythonExe -u $fullPath @pyArgs
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
    $args = @("--split_mode", $mode, "--dataset", $Dataset, "--epochs", "$epochs")
    if ($hasSampleFrac) {
        $args += @("--sample_frac", "$SampleFrac")
    }
    return $args
}

function Invoke-GroupedTrainer([string]$relPath, [int]$epochs, [switch]$NoSampleFrac) {
    if ($AllGroupFolds) {
        $args = @("--split_mode", "groupkfold", "--dataset", $Dataset, "--all_folds", "--n_folds", "$NFolds", "--epochs", "$epochs")
        if ($hasSampleFrac -and -not $NoSampleFrac) {
            $args += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $args
        return
    }

    foreach ($fold in $GroupFolds) {
        $args = @("--split_mode", "groupkfold", "--dataset", $Dataset, "--fold", "$fold", "--n_folds", "$NFolds", "--epochs", "$epochs")
        if ($hasSampleFrac -and -not $NoSampleFrac) {
            $args += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $args
    }
}

Write-Host "=== UGR16 existing-dataset model run ===" -ForegroundColor Green
Write-Host "Repo root   : $repoRoot"
Write-Host "Python      : $PythonExe"
Write-Host "Dataset     : $Dataset"
Write-Host "Modes       : $($Modes -join ', ')"
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
            Invoke-GroupedTrainer "src\models\UGR16\train_anomaly_isoforest.py" $AnomalyEstimators -NoSampleFrac
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
        RunPy "src\models\UGR16\train_anomaly_isoforest.py" @("--split_mode", $mode, "--dataset", $Dataset, "--epochs", "$AnomalyEstimators")
    }
}

if (-not $SkipCompare) {
    RunPy "src\models\UGR16\compare_models.py" @("--artifacts_dir", $artifactsDir)
}

Write-Host "`nUGR16 existing-dataset model run finished." -ForegroundColor Green
